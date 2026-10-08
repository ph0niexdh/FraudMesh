"""Security center: operator accounts, sessions, auth activity, IDS summary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.config import get_settings
from fraudmesh.db.models import Alert, AuditLog, AuthSession, Detection, Event, User
from fraudmesh.db.session import get_db
from fraudmesh.services.auth.security import PERMISSIONS

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/overview")
async def overview(cu: CurrentUser = Depends(require("security:read")), db: AsyncSession = Depends(get_db)):
    s = get_settings()
    now = datetime.now(timezone.utc)
    d1 = now - timedelta(hours=24)
    users = (await db.execute(select(User).order_by(User.role, User.email))).scalars().all()
    active_sessions = dict((await db.execute(select(AuthSession.user_id, func.count()).where(
        AuthSession.revoked_at.is_(None), AuthSession.rotated_at.is_(None), AuthSession.expires_at > now).group_by(AuthSession.user_id))).all())
    auth_events = dict((await db.execute(select(AuditLog.action, func.count()).where(AuditLog.ts >= d1, AuditLog.action.like("auth.%")).group_by(AuditLog.action))).all())
    recent = (await db.execute(select(AuditLog).where(AuditLog.action.like("auth.%")).order_by(AuditLog.id.desc()).limit(25))).scalars().all()
    findings = (await db.execute(select(Detection.reason_codes).join(Event, Event.id == Detection.event_id)
                                 .where(Detection.detector == "ids", Event.received_at >= d1).limit(500))).scalars().all()
    finding_counts: dict[str, int] = {}
    for rcs in findings:
        for rc in rcs:
            finding_counts[rc["code"]] = finding_counts.get(rc["code"], 0) + 1
    top_sources = (await db.execute(select(Event.ip, func.max(Event.risk_score), func.count()).where(
        Event.event_type.in_(["NETWORK", "IDS"]), Event.received_at >= d1, Event.risk_score >= 50).group_by(Event.ip)
        .order_by(func.max(Event.risk_score).desc()).limit(10))).all()
    return {
        "operators": [{"id": u.id, "email": u.email, "name": u.display_name, "role": u.role, "mfa_enabled": u.mfa_enabled, "active": u.is_active,
                       "locked": bool(u.locked_until and u.locked_until > now), "last_login_at": u.last_login_at,
                       "active_sessions": int(active_sessions.get(u.id, 0))} for u in users],
        "mfa_adoption": round(sum(1 for u in users if u.mfa_enabled) / len(users), 3) if users else 0,
        "auth_activity_24h": auth_events,
        "recent_auth_events": [{"ts": r.ts, "actor": r.actor, "action": r.action, "ip": r.ip} for r in recent],
        "network": {"ids_findings_24h": dict(sorted(finding_counts.items(), key=lambda kv: -kv[1])),
                    "network_alerts_24h": int(await db.scalar(select(func.count()).select_from(Alert).where(Alert.domain == "network", Alert.created_at >= d1)) or 0),
                    "top_hostile_sources": [{"ip": ip, "max_risk": r, "events": n} for ip, r, n in top_sources]},
        "controls": {
            "password_hashing": "Argon2id (m=64 MiB, t=3, p=2)",
            "access_token_ttl_s": s.access_token_ttl_s,
            "refresh_rotation": "rotating, reuse-detection revokes family",
            "mfa": "TOTP (RFC 6238) with replay protection",
            "mfa_required_for_sensitive_actions": s.mfa_required_for_sensitive,
            "lockout": f"{s.login_max_failures} failures → {s.lockout_seconds // 60} min lock + progressive delay",
            "rate_limits": {"api_per_min": s.rate_limit_per_minute, "auth_per_min": s.auth_rate_limit_per_minute},
            "data_at_rest": "AES-256-GCM for TOTP seeds, PII and face templates; HMAC-SHA256 lookup keys",
            "audit": "hash-chained, append-only (DB trigger)",
            "cookies": {"secure": s.cookie_secure, "samesite": "strict", "csrf": "double-submit token"},
            "environment": s.env,
        },
        "rbac": {perm: sorted(r.value for r in roles) for perm, roles in PERMISSIONS.items()},
    }
