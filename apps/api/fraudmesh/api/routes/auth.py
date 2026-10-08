"""Operator authentication endpoints.

Token transport:
* access token  – returned in the JSON body, kept in memory by the SPA, sent as Bearer.
* refresh token – httpOnly, SameSite=Strict cookie scoped to /api/auth.
* CSRF          – double-submit: the non-httpOnly ``fm_csrf`` cookie must be echoed in
  ``X-CSRF-Token`` for cookie-authenticated endpoints (refresh / logout).
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, current_user
from fraudmesh.config import get_settings
from fraudmesh.core import ratelimit
from fraudmesh.core.ratelimit import client_ip
from fraudmesh.db.models import AuthSession, User, UserDevice
from fraudmesh.db.session import get_db
from fraudmesh.services.audit import service as audit
from fraudmesh.services.auth import security as sec
from fraudmesh.services.auth import service as auth
from fraudmesh.services.auth.service import AuthError, TokenPair

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "fm_refresh"
CSRF_COOKIE = "fm_csrf"


class DeviceInfo(BaseModel):
    fingerprint: str | None = Field(default=None, max_length=256)
    label: str = Field(default="Unknown device", max_length=160)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=1, max_length=256)
    device: DeviceInfo = Field(default_factory=DeviceInfo)


class MfaRequest(BaseModel):
    mfa_token: str = Field(max_length=2048)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


def user_dict(u: User) -> dict:
    return {
        "id": u.id,
        "email": u.email,
        "display_name": u.display_name,
        "role": u.role,
        "mfa_enabled": u.mfa_enabled,
        "permissions": sec.permissions_for(u.role),
        "last_login_at": u.last_login_at,
    }


def _set_cookies(response: Response, tokens: TokenPair) -> None:
    s = get_settings()
    response.set_cookie(
        REFRESH_COOKIE, tokens.refresh_token, max_age=s.refresh_token_ttl_s, httponly=True,
        secure=s.cookie_secure, samesite="strict", path="/api/auth",
    )
    response.set_cookie(
        CSRF_COOKIE, secrets.token_urlsafe(24), max_age=s.refresh_token_ttl_s, httponly=False,
        secure=s.cookie_secure, samesite="strict", path="/",
    )


def _clear_cookies(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path="/api/auth")
    response.delete_cookie(CSRF_COOKIE, path="/")


def _check_csrf(request: Request) -> None:
    cookie = request.cookies.get(CSRF_COOKIE)
    header = request.headers.get("x-csrf-token")
    if not cookie or not header or not secrets.compare_digest(cookie, header):
        raise HTTPException(403, "CSRF token missing or invalid")


def _err(e: AuthError) -> HTTPException:
    return HTTPException(e.status, {"code": e.code, "message": str(e)})


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "auth", get_settings().auth_rate_limit_per_minute)
    try:
        res = await auth.login(
            db, body.email, body.password, client_ip(request), request.headers.get("user-agent"),
            body.device.fingerprint, body.device.label,
        )
    except AuthError as e:
        raise _err(e)
    if res.mfa_token:
        return {"status": "MFA_REQUIRED", "mfa_token": res.mfa_token, "new_device": res.new_device}
    assert res.tokens
    _set_cookies(response, res.tokens)
    user = (await db.execute(select(User).where(User.email == body.email.lower()))).scalar_one()
    await db.commit()
    return {
        "status": "OK",
        "access_token": res.tokens.access_token,
        "expires_in": res.tokens.expires_in,
        "user": user_dict(user),
        "mfa_verified": False,
        "mfa_enrollment_required": res.mfa_enrollment_required,
        "new_device": res.new_device,
    }


@router.post("/mfa")
async def mfa(body: MfaRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "auth", get_settings().auth_rate_limit_per_minute)
    try:
        tokens = await auth.verify_mfa(db, body.mfa_token, body.code, client_ip(request), request.headers.get("user-agent"))
    except AuthError as e:
        raise _err(e)
    _set_cookies(response, tokens)
    claims = sec.decode_token(tokens.access_token, "access")
    user = await db.get(User, claims["sub"])
    await db.commit()
    return {"status": "OK", "access_token": tokens.access_token, "expires_in": tokens.expires_in, "user": user_dict(user), "mfa_verified": True}


@router.post("/refresh")
async def refresh(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "auth-refresh", 60)
    _check_csrf(request)
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(401, {"code": "no_refresh", "message": "no refresh token"})
    try:
        tokens = await auth.refresh(db, token, client_ip(request), request.headers.get("user-agent"))
    except AuthError as e:
        _clear_cookies(response)
        raise _err(e)
    _set_cookies(response, tokens)
    claims = sec.decode_token(tokens.access_token, "access")
    user = await db.get(User, claims["sub"])
    return {"status": "OK", "access_token": tokens.access_token, "expires_in": tokens.expires_in, "user": user_dict(user), "mfa_verified": bool(claims.get("mfa"))}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    _check_csrf(request)
    token = request.cookies.get(REFRESH_COOKIE)
    if token:
        from fraudmesh.core.crypto import sha256_hex

        sess = (await db.execute(select(AuthSession).where(AuthSession.refresh_hash == sha256_hex(token)))).scalar_one_or_none()
        if sess:
            await auth.revoke_family(db, sess.family_id, "logout")
            await audit.record(db, audit.Actor(id=sess.user_id, name=sess.user_id, ip=client_ip(request)), "auth.logout", "session", sess.family_id)
    _clear_cookies(response)
    return {"status": "OK"}


@router.get("/me")
async def me(cu: CurrentUser = Depends(current_user)):
    return {**user_dict(cu.user), "session_id": cu.session_id, "mfa_verified": cu.mfa}


@router.post("/mfa/enroll")
async def mfa_enroll(cu: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, cu.user.id)
    uri = await auth.begin_totp_enrollment(db, user)
    return {"otpauth_uri": uri}


@router.post("/mfa/enroll/confirm")
async def mfa_enroll_confirm(body: CodeRequest, cu: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)):
    user = await db.get(User, cu.user.id)
    try:
        await auth.confirm_totp_enrollment(db, user, body.code, cu.actor)
    except AuthError as e:
        raise _err(e)
    return {"status": "OK", "mfa_enabled": True}


@router.get("/sessions")
async def sessions(cu: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (
        await db.execute(
            select(AuthSession)
            .where(AuthSession.user_id == cu.user.id, AuthSession.revoked_at.is_(None), AuthSession.rotated_at.is_(None))
            .order_by(AuthSession.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    return [
        {
            "family_id": r.family_id,
            "created_at": r.created_at,
            "expires_at": r.expires_at,
            "ip": r.ip,
            "user_agent": r.user_agent,
            "mfa_verified": r.mfa_verified,
            "current": r.family_id == cu.family_id,
        }
        for r in rows
    ]


@router.delete("/sessions/{family_id}")
async def revoke_session(family_id: str, cu: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)):
    owned = (
        await db.execute(select(AuthSession.id).where(AuthSession.family_id == family_id, AuthSession.user_id == cu.user.id).limit(1))
    ).scalar_one_or_none()
    if owned is None:
        raise HTTPException(404, "session not found")
    await auth.revoke_family(db, family_id, "user_revoked")
    await audit.record(db, cu.actor, "auth.session.revoked", "session", family_id)
    return {"status": "OK"}


@router.get("/devices")
async def devices(cu: CurrentUser = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(UserDevice).where(UserDevice.user_id == cu.user.id).order_by(UserDevice.last_seen.desc()))).scalars().all()
    return [
        {"id": d.id, "label": d.label, "trusted": d.trusted, "first_seen": d.first_seen, "last_seen": d.last_seen, "last_ip": d.last_ip}
        for d in rows
    ]
