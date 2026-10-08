"""FastAPI dependencies: database session, current user, RBAC guard, audit actor."""

from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.config import get_settings
from fraudmesh.core.ratelimit import client_ip
from fraudmesh.db.models import User
from fraudmesh.db.session import get_db
from fraudmesh.services.audit.service import Actor
from fraudmesh.services.auth import security as sec
from fraudmesh.services.auth.service import is_revoked

_bearer = HTTPBearer(auto_error=False)

SENSITIVE = {"policies:write", "users:manage", "demo:reset"}


@dataclass
class CurrentUser:
    user: User
    session_id: str
    family_id: str | None
    mfa: bool
    ip: str
    user_agent: str | None

    @property
    def actor(self) -> Actor:
        return Actor(id=self.user.id, name=self.user.email, ip=self.ip, user_agent=self.user_agent)


async def current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> CurrentUser:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = sec.decode_token(creds.credentials, "access")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    if await is_revoked(claims.get("sid"), claims.get("fam")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session revoked")
    user = await db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user disabled")
    return CurrentUser(
        user=user,
        session_id=claims.get("sid", ""),
        family_id=claims.get("fam"),
        mfa=bool(claims.get("mfa")),
        ip=client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )


def require(permission: str):
    async def guard(cu: CurrentUser = Depends(current_user)) -> CurrentUser:
        if not sec.has_permission(cu.user.role, permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"role {cu.user.role} lacks permission {permission}")
        if permission in SENSITIVE and get_settings().mfa_required_for_sensitive and not cu.mfa:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "this action requires an MFA-verified session")
        return cu

    return guard
