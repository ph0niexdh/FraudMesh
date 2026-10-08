"""Audit trail (read-only) and chain verification."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.db.models import AuditLog
from fraudmesh.db.session import get_db
from fraudmesh.services.audit import service as audit

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def list_audit(action: str | None = Query(default=None, max_length=64), actor: str | None = Query(default=None, max_length=160),
                     resource_id: str | None = Query(default=None, max_length=80), limit: int = Query(100, ge=1, le=500), before_id: int | None = None,
                     cu: CurrentUser = Depends(require("audit:read")), db: AsyncSession = Depends(get_db)):
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action.ilike(f"{action}%"))
    if actor:
        q = q.where(AuditLog.actor.ilike(f"%{actor}%"))
    if resource_id:
        q = q.where(AuditLog.resource_id == resource_id)
    if before_id:
        q = q.where(AuditLog.id < before_id)
    rows = (await db.execute(q.order_by(AuditLog.id.desc()).limit(limit))).scalars().all()
    return [{"id": r.id, "ts": r.ts, "actor": r.actor, "action": r.action, "resource_type": r.resource_type, "resource_id": r.resource_id,
             "old_state": r.old_state, "new_state": r.new_state, "ip": r.ip, "device_id": r.device_id, "request_id": r.request_id,
             "prev_hash": r.prev_hash, "hash": r.hash} for r in rows]


@router.get("/verify")
async def verify(cu: CurrentUser = Depends(require("audit:read")), db: AsyncSession = Depends(get_db)):
    return await audit.verify_chain(db)
