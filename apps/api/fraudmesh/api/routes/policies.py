"""Policy management (ADMIN writes, everyone reads) with versioned audit."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.db.models import Policy
from fraudmesh.db.session import get_db
from fraudmesh.services.audit import service as audit
from fraudmesh.services.policy import engine as policy

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("")
async def list_policies(cu: CurrentUser = Depends(require("policies:read")), db: AsyncSession = Depends(get_db)):
    return {"policies": sorted(await policy.load(db), key=lambda p: p["priority"]), "fields": policy.FIELDS, "operators": sorted(policy.OPS),
            "actions": ["ALLOW", "MONITOR", "STEP_UP", "HOLD", "BLOCK"]}


class Condition(BaseModel):
    field: str
    op: str
    value: Any


class PolicyUpdate(BaseModel):
    name: str = Field(max_length=120)
    description: str = Field(default="", max_length=1000)
    priority: int = Field(ge=1, le=1000)
    enabled: bool = True
    action: Literal["ALLOW", "MONITOR", "STEP_UP", "HOLD", "BLOCK"]
    conditions: list[Condition] = Field(min_length=1, max_length=10)


@router.put("/{policy_id}")
async def upsert_policy(policy_id: str, body: PolicyUpdate, cu: CurrentUser = Depends(require("policies:write")), db: AsyncSession = Depends(get_db)):
    if not policy_id.replace("-", "").isalnum() or len(policy_id) > 40:
        raise HTTPException(422, "invalid policy id")
    conds = [c.model_dump() for c in body.conditions]
    try:
        policy.validate_conditions(conds)
    except policy.PolicyError as exc:
        raise HTTPException(422, str(exc))
    row = await db.get(Policy, policy_id)
    old = None
    if row is None:
        row = Policy(id=policy_id, version=1)
        db.add(row)
    else:
        old = {"name": row.name, "priority": row.priority, "enabled": row.enabled, "action": row.action, "conditions": row.conditions, "version": row.version}
        row.version += 1
    row.name, row.description, row.priority, row.enabled, row.action, row.conditions = body.name, body.description, body.priority, body.enabled, body.action, conds
    row.updated_by, row.updated_at = cu.user.email, datetime.now(timezone.utc)
    await audit.record(db, cu.actor, "policy.update" if old else "policy.create", "policy", policy_id, old_state=old,
                       new_state={"name": row.name, "priority": row.priority, "enabled": row.enabled, "action": row.action, "conditions": conds, "version": row.version})
    return {"id": row.id, "version": row.version}


class EvaluateRequest(BaseModel):
    context: dict[str, Any]


@router.post("/evaluate")
async def evaluate(body: EvaluateRequest, cu: CurrentUser = Depends(require("policies:read")), db: AsyncSession = Depends(get_db)):
    """Dry-run: which policies would match this decision context."""
    unknown = set(body.context) - set(policy.FIELDS)
    if unknown:
        raise HTTPException(422, f"unknown fields: {sorted(unknown)}")
    return policy.evaluate(await policy.load(db), body.context)
