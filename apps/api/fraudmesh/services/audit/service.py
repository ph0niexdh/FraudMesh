"""Append-only, hash-chained audit trail.

Each record's hash = SHA-256(prev_hash || canonical JSON of the record). A Postgres
advisory lock serialises writers so the chain never forks; a DB trigger rejects
UPDATE/DELETE/TRUNCATE. ``verify_chain`` recomputes every hash to detect tampering.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.core.crypto import sha256_hex
from fraudmesh.core.logging import request_id_var
from fraudmesh.db.models import AuditLog

GENESIS = "0" * 64
_LOCK_KEY = 0x46_4D_41_55  # "FMAU"


@dataclass
class Actor:
    id: str | None
    name: str
    ip: str | None = None
    user_agent: str | None = None
    device_id: str | None = None


SYSTEM = Actor(id=None, name="system")


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _record_body(row: AuditLog) -> dict[str, Any]:
    return {
        "ts": row.ts.astimezone(timezone.utc).isoformat(),
        "actor_id": row.actor_id,
        "actor": row.actor,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "old_state": row.old_state,
        "new_state": row.new_state,
        "ip": row.ip,
        "device_id": row.device_id,
    }


async def record(
    db: AsyncSession,
    actor: Actor,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    old_state: dict | None = None,
    new_state: dict | None = None,
    commit: bool = True,
) -> AuditLog:
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _LOCK_KEY})
    prev = (await db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1))).scalar_one_or_none()
    row = AuditLog(
        ts=datetime.now(timezone.utc),
        actor_id=actor.id,
        actor=actor.name,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        old_state=old_state,
        new_state=new_state,
        ip=actor.ip,
        user_agent=(actor.user_agent or "")[:300] or None,
        device_id=actor.device_id,
        request_id=request_id_var.get(),
        prev_hash=prev or GENESIS,
        hash="",
    )
    # Round-trip timestamps through Postgres precision (microseconds) before hashing.
    row.hash = sha256_hex(row.prev_hash + _canonical(_record_body(row)))
    db.add(row)
    if commit:
        await db.commit()
    else:
        await db.flush()
    return row


async def verify_chain(db: AsyncSession, limit: int = 100_000) -> dict[str, Any]:
    rows = (await db.execute(select(AuditLog).order_by(AuditLog.id.asc()).limit(limit))).scalars().all()
    prev = GENESIS
    for row in rows:
        expected = sha256_hex(prev + _canonical(_record_body(row)))
        if row.prev_hash != prev or row.hash != expected:
            return {"valid": False, "checked": len(rows), "broken_at": row.id}
        prev = row.hash
    return {"valid": True, "checked": len(rows), "head": prev}
