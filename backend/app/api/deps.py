from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request

from app.config import get_settings
from app.services.broadcaster import Broadcaster
from app.services.engine import FraudMeshEngine, get_engine


def engine_dep() -> FraudMeshEngine:
    engine = get_engine()
    if not engine.ready:
        raise HTTPException(503, "FraudMesh is initialising (training models / loading state)")
    return engine


def broadcaster_dep(request: Request) -> Broadcaster:
    return request.app.state.broadcaster


def require_admin(x_admin_token: str | None = Header(default=None)) -> str:
    """Authorise configuration changes.

    If ``FRAUDMESH_ADMIN_TOKEN`` is unset the prototype runs in open demo mode
    (a warning is logged at start-up and exposed via /api/health).
    """
    settings = get_settings()
    if not settings.admin_auth_enabled:
        return "demo-admin (auth disabled)"
    if not x_admin_token or not hmac.compare_digest(x_admin_token, settings.admin_token):
        raise HTTPException(401, "valid X-Admin-Token header required for configuration changes")
    return "admin"
