"""Operator authentication flows."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.config import get_settings
from fraudmesh.core.crypto import decrypt_str, encrypt_str, hmac_hex, sha256_hex
from fraudmesh.core.ids import new_id
from fraudmesh.core.ratelimit import progressive_delay_s
from fraudmesh.core.redis import redis
from fraudmesh.db.models import AuthSession, OtpChallenge, User, UserDevice
from fraudmesh.services.audit import service as audit
from fraudmesh.services.auth import security as sec

logger = logging.getLogger(__name__)


class AuthError(Exception):
    def __init__(self, message: str, code: str = "invalid_credentials", status: int = 401):
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    session_id: str
    expires_in: int


@dataclass
class LoginResult:
    tokens: TokenPair | None = None
    mfa_token: str | None = None
    mfa_enrollment_required: bool = False
    new_device: bool = False


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _register_device(db: AsyncSession, user: User, fingerprint: str | None, label: str, ip: str | None) -> tuple[str | None, bool]:
    if not fingerprint:
        return None, False
    fp_hash = hmac_hex(f"device:{fingerprint}")
    dev = (
        await db.execute(select(UserDevice).where(UserDevice.user_id == user.id, UserDevice.fingerprint_hash == fp_hash))
    ).scalar_one_or_none()
    if dev is None:
        dev = UserDevice(id=new_id("udev"), user_id=user.id, fingerprint_hash=fp_hash, label=label[:160], last_ip=ip)
        db.add(dev)
        await db.flush()
        return dev.id, True
    dev.last_seen = _now()
    dev.last_ip = ip
    return dev.id, False


async def _issue_session(db: AsyncSession, user: User, device_id: str | None, ip: str | None, ua: str | None,
                         family_id: str | None = None, mfa_verified: bool = False) -> TokenPair:
    s = get_settings()
    refresh, refresh_hash = sec.new_refresh_token()
    sess = AuthSession(
        id=new_id("ses"),
        user_id=user.id,
        family_id=family_id or new_id("fam"),
        refresh_hash=refresh_hash,
        device_id=device_id,
        ip=ip,
        user_agent=(ua or "")[:300],
        expires_at=_now() + timedelta(seconds=s.refresh_token_ttl_s),
        mfa_verified=mfa_verified,
    )
    db.add(sess)
    access = sec.issue_token(
        user.id, "access", s.access_token_ttl_s, role=user.role, sid=sess.id, fam=sess.family_id, mfa=mfa_verified
    )
    return TokenPair(access_token=access, refresh_token=refresh, session_id=sess.id, expires_in=s.access_token_ttl_s)


async def login(db: AsyncSession, email: str, password: str, ip: str | None, ua: str | None,
                device_fingerprint: str | None, device_label: str) -> LoginResult:
    s = get_settings()
    email = email.strip().lower()
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    actor = audit.Actor(id=user.id if user else None, name=email, ip=ip, user_agent=ua)

    if user is not None and user.locked_until and user.locked_until > _now():
        await audit.record(db, actor, "auth.login.locked", "user", user.id)
        raise AuthError("account temporarily locked", "locked", 423)

    # Progressive delay keyed on the account name (works for unknown accounts too).
    fail_key = f"authfail:{hmac_hex(email)}"
    prior_failures = int(await redis().get(fail_key) or 0)
    delay = progressive_delay_s(prior_failures)
    if delay:
        await asyncio.sleep(delay)

    ok = sec.verify_secret(user.password_hash if user else None, password)
    if not ok or user is None or not user.is_active:
        await redis().incr(fail_key)
        await redis().expire(fail_key, s.lockout_seconds)
        if user is not None:
            user.failed_logins += 1
            if user.failed_logins >= s.login_max_failures:
                user.locked_until = _now() + timedelta(seconds=s.lockout_seconds)
                user.failed_logins = 0
                await audit.record(db, actor, "auth.lockout", "user", user.id, new_state={"locked_until": user.locked_until.isoformat()}, commit=False)
        await audit.record(db, actor, "auth.login.failed", "user", user.id if user else None)
        raise AuthError("invalid email or password")

    await redis().delete(fail_key)
    user.failed_logins = 0
    if sec.needs_rehash(user.password_hash):
        user.password_hash = sec.hash_secret(password)

    device_id, is_new_device = await _register_device(db, user, device_fingerprint, device_label, ip)
    actor.device_id = device_id

    if user.mfa_enabled:
        mfa_token = sec.issue_token(user.id, "mfa", s.mfa_token_ttl_s, did=device_id, nd=is_new_device)
        await audit.record(db, actor, "auth.login.password_ok", "user", user.id, new_state={"mfa": "required", "new_device": is_new_device})
        return LoginResult(mfa_token=mfa_token, new_device=is_new_device)

    user.last_login_at = _now()
    tokens = await _issue_session(db, user, device_id, ip, ua)
    await audit.record(db, actor, "auth.login.success", "user", user.id, new_state={"mfa": False, "new_device": is_new_device})
    return LoginResult(tokens=tokens, mfa_enrollment_required=True, new_device=is_new_device)


async def verify_mfa(db: AsyncSession, mfa_token: str, code: str, ip: str | None, ua: str | None) -> TokenPair:
    try:
        claims = sec.decode_token(mfa_token, "mfa")
    except Exception as exc:
        raise AuthError("MFA session expired — sign in again", "mfa_expired") from exc
    user = await db.get(User, claims["sub"])
    if user is None or not user.mfa_enabled or user.totp_secret_enc is None:
        raise AuthError("MFA not available")
    # Per-token attempt cap stops brute force of the 6-digit space within one MFA session.
    attempts_key = f"mfa_attempts:{claims['jti']}"
    attempts = await redis().incr(attempts_key)
    await redis().expire(attempts_key, get_settings().mfa_token_ttl_s)
    actor = audit.Actor(id=user.id, name=user.email, ip=ip, user_agent=ua, device_id=claims.get("did"))
    if attempts > 5:
        await audit.record(db, actor, "auth.mfa.too_many_attempts", "user", user.id)
        raise AuthError("too many MFA attempts — sign in again", "mfa_locked", 429)
    step = sec.verify_totp(decrypt_str(user.totp_secret_enc), code, user.totp_last_step)
    if step is None:
        await audit.record(db, actor, "auth.mfa.failed", "user", user.id)
        raise AuthError("invalid verification code", "invalid_mfa")
    user.totp_last_step = step
    user.last_login_at = _now()
    tokens = await _issue_session(db, user, claims.get("did"), ip, ua, mfa_verified=True)
    await audit.record(db, actor, "auth.mfa.success", "user", user.id)
    return tokens


async def refresh(db: AsyncSession, refresh_token: str, ip: str | None, ua: str | None) -> TokenPair:
    token_hash = sha256_hex(refresh_token)
    sess = (await db.execute(select(AuthSession).where(AuthSession.refresh_hash == token_hash))).scalar_one_or_none()
    if sess is None:
        raise AuthError("invalid refresh token", "invalid_refresh")
    user = await db.get(User, sess.user_id)
    actor = audit.Actor(id=sess.user_id, name=user.email if user else sess.user_id, ip=ip, user_agent=ua)
    if sess.rotated_at is not None or sess.revoked_at is not None:
        # Reuse of a rotated token ⇒ assume theft: revoke the entire family.
        await revoke_family(db, sess.family_id, "refresh_reuse_detected")
        await audit.record(db, actor, "auth.refresh.reuse_detected", "session", sess.family_id)
        raise AuthError("refresh token reuse detected — all sessions in this family revoked", "refresh_reuse")
    if sess.expires_at < _now() or user is None or not user.is_active:
        raise AuthError("refresh token expired", "refresh_expired")
    sess.rotated_at = _now()
    tokens = await _issue_session(db, user, sess.device_id, ip, ua, family_id=sess.family_id, mfa_verified=sess.mfa_verified)
    await db.commit()
    return tokens


async def revoke_family(db: AsyncSession, family_id: str, reason: str) -> None:
    rows = (await db.execute(select(AuthSession.id).where(AuthSession.family_id == family_id))).scalars().all()
    await db.execute(
        update(AuthSession)
        .where(AuthSession.family_id == family_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=_now(), revoked_reason=reason)
    )
    ttl = get_settings().access_token_ttl_s + 60
    for sid in rows:
        await redis().set(f"revoked_sid:{sid}", "1", ex=ttl)
    await redis().set(f"revoked_fam:{family_id}", "1", ex=ttl)
    await db.commit()


async def is_revoked(sid: str | None, family_id: str | None) -> bool:
    keys = [k for k in (f"revoked_sid:{sid}" if sid else None, f"revoked_fam:{family_id}" if family_id else None) if k]
    if not keys:
        return False
    return bool(await redis().exists(*keys))


# ------------------------------------------------------------------ TOTP enrollment
async def begin_totp_enrollment(db: AsyncSession, user: User) -> str:
    secret = sec.new_totp_secret()
    user.totp_pending_enc = encrypt_str(secret)
    await db.commit()
    return sec.totp_uri(secret, user.email)


async def confirm_totp_enrollment(db: AsyncSession, user: User, code: str, actor: audit.Actor) -> None:
    if user.totp_pending_enc is None:
        raise AuthError("no enrollment in progress", "no_enrollment", 400)
    secret = decrypt_str(user.totp_pending_enc)
    step = sec.verify_totp(secret, code, None)
    if step is None:
        raise AuthError("invalid verification code", "invalid_mfa", 400)
    user.totp_secret_enc = user.totp_pending_enc
    user.totp_pending_enc = None
    user.totp_last_step = step
    user.mfa_enabled = True
    await audit.record(db, actor, "auth.mfa.enrolled", "user", user.id, old_state={"mfa_enabled": False}, new_state={"mfa_enabled": True})


# ------------------------------------------------------------------ one-time passcodes
async def create_otp(db: AsyncSession, subject_id: str, purpose: str, channel: str, destination_masked: str | None) -> tuple[str, str]:
    """Returns (challenge_id, code). Only the Argon2id hash of the code is stored. The
    caller is responsible for delivery (SMS/email gateway; dev outbox in demo mode)."""
    code = sec.new_otp()
    ch = OtpChallenge(
        id=new_id("otp"),
        subject_id=subject_id,
        purpose=purpose,
        channel=channel,
        destination_masked=destination_masked,
        code_hash=sec.hash_secret(code),
        expires_at=_now() + timedelta(minutes=5),
    )
    db.add(ch)
    await db.commit()
    return ch.id, code


async def verify_otp(db: AsyncSession, challenge_id: str, subject_id: str, code: str) -> bool:
    ch = await db.get(OtpChallenge, challenge_id)
    if ch is None or ch.subject_id != subject_id or ch.consumed_at is not None or ch.expires_at < _now():
        return False
    if ch.attempts >= 5:
        return False
    ch.attempts += 1
    ok = sec.verify_secret(ch.code_hash, code)
    if ok:
        ch.consumed_at = _now()
    await db.commit()
    return ok


async def deliver_dev_outbox(subject_id: str, channel: str, destination_masked: str | None, code: str) -> None:
    """DEMO MODE ONLY: there is no SMS gateway, so the code is placed in a short-lived
    Redis outbox the demo UI can display (clearly labelled). Never enabled in production."""
    if not get_settings().demo_mode:
        return
    await redis().set(
        f"outbox:{subject_id}",
        f'{{"channel":"{channel}","to":"{destination_masked or ""}","code":"{code}"}}',
        ex=300,
    )
