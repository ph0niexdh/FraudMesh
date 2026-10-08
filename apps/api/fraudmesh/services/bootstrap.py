"""Idempotent first-start bootstrap: operator accounts, policies, model registry."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.config import get_settings
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import User
from fraudmesh.domain import Role
from fraudmesh.services.audit import service as audit
from fraudmesh.services.auth.security import hash_secret

logger = logging.getLogger(__name__)

OPERATORS = [
    ("admin@fraudmesh.local", "Avery Admin", Role.ADMIN),
    ("investigator@fraudmesh.local", "Ira Investigator", Role.INVESTIGATOR),
    ("analyst@fraudmesh.local", "Ana Analyst", Role.ANALYST),
    ("secops@fraudmesh.local", "Sam SecOps", Role.SECURITY_OPERATOR),
    ("auditor@fraudmesh.local", "Aud Auditor", Role.AUDITOR),
]


async def ensure_operators(db: AsyncSession) -> None:
    existing = set((await db.execute(select(User.email))).scalars().all())
    pw_hash = None
    for email, name, role in OPERATORS:
        if email in existing:
            continue
        pw_hash = pw_hash or hash_secret(get_settings().bootstrap_password)
        db.add(User(id=new_id("usr"), email=email, display_name=name, role=role.value, password_hash=pw_hash))
        await audit.record(db, audit.SYSTEM, "user.created", "user", email, new_state={"role": role.value}, commit=False)
        logger.info("bootstrap operator created", extra={"fields": {"email": email, "role": role.value}})
    await db.commit()
