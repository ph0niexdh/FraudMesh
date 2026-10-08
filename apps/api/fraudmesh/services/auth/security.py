"""Authentication primitives: Argon2id, JWT, TOTP, opaque refresh tokens, RBAC."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from fraudmesh.config import get_settings
from fraudmesh.core.crypto import sha256_hex
from fraudmesh.domain import Role

# Argon2id (argon2-cffi default type) — OWASP-recommended parameters (m=64 MiB, t=3, p=2).
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

# Precomputed so failed lookups for unknown users spend the same time as real ones.
_DUMMY_HASH = _hasher.hash("fraudmesh-timing-equaliser")


def hash_secret(value: str) -> str:
    return _hasher.hash(value)


def verify_secret(stored_hash: str | None, value: str) -> bool:
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, value) and stored_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    return _hasher.check_needs_rehash(stored_hash)


PASSWORD_MIN_LEN = 12


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < PASSWORD_MIN_LEN:
        problems.append(f"at least {PASSWORD_MIN_LEN} characters")
    if password.lower() == password or password.upper() == password:
        problems.append("mixed case")
    if not any(c.isdigit() for c in password):
        problems.append("a digit")
    return problems


# ------------------------------------------------------------------ JWT
def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue_token(sub: str, kind: str, ttl_s: int, **claims) -> str:
    s = get_settings()
    now = _now()
    payload = {
        "sub": sub,
        "typ": kind,
        "iss": s.jwt_issuer,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_s)).timestamp()),
        "jti": secrets.token_hex(8),
        **claims,
    }
    return jwt.encode(payload, s.jwt_secret, algorithm="HS256")


def decode_token(token: str, kind: str) -> dict:
    s = get_settings()
    payload = jwt.decode(
        token,
        s.jwt_secret,
        algorithms=["HS256"],  # pinned: never accept "none" or asymmetric confusion
        issuer=s.jwt_issuer,
        options={"require": ["exp", "iat", "sub", "typ", "iss"]},
    )
    if payload.get("typ") != kind:
        raise jwt.InvalidTokenError("wrong token type")
    return payload


# ------------------------------------------------------------------ refresh tokens
def new_refresh_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(48)
    return token, sha256_hex(token)


# ------------------------------------------------------------------ TOTP / OTP
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name="FraudMesh")


def verify_totp(secret: str, code: str, last_step: int | None) -> int | None:
    """Return the matched time-step (for replay protection) or None. Accepts ±1 step drift
    and rejects any step at or before the last one used."""
    if not code or not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // 30
    for step in (now_step - 1, now_step, now_step + 1):
        if last_step is not None and step <= last_step:
            continue
        if secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def new_otp() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


# ------------------------------------------------------------------ RBAC
PERMISSIONS: dict[str, set[Role]] = {
    "dashboard:read": set(Role),
    "cases:read": set(Role),
    "cases:act": {Role.ADMIN, Role.INVESTIGATOR, Role.ANALYST},
    "cases:assign": {Role.ADMIN, Role.INVESTIGATOR},
    "cases:feedback": {Role.ADMIN, Role.INVESTIGATOR, Role.ANALYST},
    "events:ingest": {Role.ADMIN, Role.SECURITY_OPERATOR, Role.INVESTIGATOR, Role.ANALYST},
    "network:ingest": {Role.ADMIN, Role.SECURITY_OPERATOR},
    "media:analyze": {Role.ADMIN, Role.INVESTIGATOR, Role.ANALYST},
    "identity:verify": {Role.ADMIN, Role.INVESTIGATOR, Role.ANALYST, Role.SECURITY_OPERATOR},
    "simulator:run": {Role.ADMIN, Role.INVESTIGATOR, Role.ANALYST, Role.SECURITY_OPERATOR},
    "policies:read": set(Role),
    "policies:write": {Role.ADMIN},
    "models:read": set(Role),
    "security:read": {Role.ADMIN, Role.SECURITY_OPERATOR, Role.AUDITOR},
    "users:manage": {Role.ADMIN},
    "audit:read": {Role.ADMIN, Role.AUDITOR},
    "demo:reset": {Role.ADMIN},
}


def has_permission(role: str, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission)
    if allowed is None:
        return False
    try:
        return Role(role) in allowed
    except ValueError:
        return False


def permissions_for(role: str) -> list[str]:
    return sorted(p for p in PERMISSIONS if has_permission(role, p))
