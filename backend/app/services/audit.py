"""Audit trail. Details are sanitised — only tokens, ids, scores and key names."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.database.models import AuditLog
from app.utils.logging import redact
from app.utils.timeutil import utcnow


def _safe(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)[:500]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [_safe(v) for v in list(value)[:40]]
    return value


def audit(session: Session, action: str, *, actor: str = "system", entity_type: str | None = None,
          entity_id: str | None = None, details: dict[str, Any] | None = None, timestamp=None) -> None:
    session.add(AuditLog(
        timestamp=timestamp or utcnow(),
        action=action,
        actor=actor[:64],
        entity_type=entity_type,
        entity_id=entity_id,
        details=_safe(details or {}),
    ))
