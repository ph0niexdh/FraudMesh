"""Configurable policy engine.

Policies are data (``policies`` table): a priority, a list of conditions (all must
hold) and an action. Every matching policy is reported; the decision is the most
severe matched action (ties → lowest priority number). The decision therefore
depends on the whole context — amount, channel, customer tier, detector-specific
risks and model confidence — not on the risk level alone.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.db.models import Policy
from fraudmesh.domain import ACTION_SEVERITY, Action

FIELDS = {
    "attack_score": "number", "risk_level": "level", "confidence": "number", "event_type": "string",
    "amount": "number", "channel": "string", "customer_risk_tier": "string", "transaction_risk": "number",
    "deepfake_risk": "number", "identity_risk": "number", "graph_risk": "number", "network_risk": "number",
    "behavior_risk": "number", "device_risk": "number", "temporal_risk": "number", "attack_type": "string",
}
OPS = {"gte", "gt", "lte", "lt", "eq", "neq", "in"}
LEVEL_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

DEFAULT_POLICIES = [
    {"id": "POL-CRITICAL-BLOCK", "name": "Critical attack → block", "priority": 10, "action": "BLOCK",
     "description": "Correlated attack score at CRITICAL level is blocked outright.",
     "conditions": [{"field": "risk_level", "op": "gte", "value": "CRITICAL"}]},
    {"id": "POL-DEEPFAKE-HOLD", "name": "Deepfake evidence → hold verification", "priority": 20, "action": "HOLD",
     "description": "High deepfake risk holds identity verification and any money movement for manual review.",
     "conditions": [{"field": "deepfake_risk", "op": "gte", "value": 80}]},
    {"id": "POL-HIGH-VALUE-HOLD", "name": "High risk + high value → hold", "priority": 30, "action": "HOLD",
     "description": "HIGH risk transfers above ₹1,00,000 are held.",
     "conditions": [{"field": "risk_level", "op": "gte", "value": "HIGH"}, {"field": "amount", "op": "gte", "value": 100000}]},
    {"id": "POL-HIGH-STEPUP", "name": "High risk → step-up", "priority": 40, "action": "STEP_UP",
     "description": "HIGH risk without a high-value transfer requires step-up authentication.",
     "conditions": [{"field": "risk_level", "op": "gte", "value": "HIGH"}]},
    {"id": "POL-GRAPH-MULE-HOLD", "name": "Mule network exposure → hold", "priority": 45, "action": "HOLD",
     "description": "Transfers into a beneficiary strongly linked to flagged accounts are held.",
     "conditions": [{"field": "graph_risk", "op": "gte", "value": 75}, {"field": "event_type", "op": "eq", "value": "TRANSACTION"}]},
    {"id": "POL-NETWORK-STEPUP", "name": "Hostile network → step-up login", "priority": 50, "action": "STEP_UP",
     "description": "Logins from infrastructure flagged by IDS / threat intel require step-up.",
     "conditions": [{"field": "network_risk", "op": "gte", "value": 70}, {"field": "event_type", "op": "in", "value": ["LOGIN", "MFA"]}]},
    {"id": "POL-MEDIUM-STEPUP", "name": "Medium risk → step-up", "priority": 60, "action": "STEP_UP",
     "description": "MEDIUM risk on money movement requires step-up.",
     "conditions": [{"field": "risk_level", "op": "gte", "value": "MEDIUM"}, {"field": "event_type", "op": "in", "value": ["TRANSACTION", "BENEFICIARY"]}]},
    {"id": "POL-LOW-CONF-MONITOR", "name": "Uncertain medium risk → monitor", "priority": 70, "action": "MONITOR",
     "description": "MEDIUM risk with low model confidence is monitored rather than actioned.",
     "conditions": [{"field": "risk_level", "op": "gte", "value": "MEDIUM"}, {"field": "confidence", "op": "lt", "value": 0.5}]},
    {"id": "POL-CLOUD-CONTAIN", "name": "Cloud compromise → revoke credentials", "priority": 12, "action": "BLOCK",
     "description": "A correlated cloud-compromise sequence at HIGH or above revokes the principal's keys and sessions.",
     "conditions": [{"field": "attack_type", "op": "in", "value": ["CLOUD_COMPROMISE", "INSIDER_THREAT"]}, {"field": "risk_level", "op": "gte", "value": "HIGH"}]},
    {"id": "POL-VIP-REVIEW", "name": "Private-banking customers: hold instead of block", "priority": 15, "action": "HOLD",
     "description": "For private-banking customers a human reviews before blocking (example of a tier-specific policy).",
     "enabled": False,
     "conditions": [{"field": "customer_risk_tier", "op": "eq", "value": "private"}, {"field": "risk_level", "op": "gte", "value": "HIGH"}]},
]


class PolicyError(ValueError):
    pass


def validate_conditions(conditions: list[dict]) -> None:
    if not conditions:
        raise PolicyError("at least one condition is required")
    for c in conditions:
        if c.get("field") not in FIELDS:
            raise PolicyError(f"unknown field {c.get('field')!r}")
        if c.get("op") not in OPS:
            raise PolicyError(f"unknown operator {c.get('op')!r}")
        kind = FIELDS[c["field"]]
        v = c.get("value")
        if c["op"] == "in":
            if not isinstance(v, list) or not v:
                raise PolicyError("'in' needs a non-empty list")
        elif kind == "number" and not isinstance(v, (int, float)):
            raise PolicyError(f"{c['field']} needs a numeric value")
        elif kind == "level" and v not in LEVEL_ORDER:
            raise PolicyError("risk_level must be LOW/MEDIUM/HIGH/CRITICAL")


def _holds(cond: dict, ctx: dict[str, Any]) -> bool:
    actual = ctx.get(cond["field"])
    if actual is None:
        return False
    op, v = cond["op"], cond["value"]
    if FIELDS[cond["field"]] == "level":
        actual = LEVEL_ORDER.get(actual, -1)
        v = LEVEL_ORDER.get(v, 99) if not isinstance(v, list) else [LEVEL_ORDER.get(x, -1) for x in v]
    if op == "gte":
        return actual >= v
    if op == "gt":
        return actual > v
    if op == "lte":
        return actual <= v
    if op == "lt":
        return actual < v
    if op == "eq":
        return actual == v
    if op == "neq":
        return actual != v
    if op == "in":
        return actual in v
    return False


def evaluate(policies: list[dict], ctx: dict[str, Any]) -> dict:
    matched = []
    for p in sorted(policies, key=lambda p: p["priority"]):
        if not p.get("enabled", True):
            continue
        if all(_holds(c, ctx) for c in p["conditions"]):
            matched.append({"id": p["id"], "name": p["name"], "action": p["action"], "priority": p["priority"]})
    if not matched:
        return {"action": Action.ALLOW.value, "policy": None, "matched": [], "reason": "no policy matched"}
    decision = max(matched, key=lambda m: (ACTION_SEVERITY[Action(m["action"])], -m["priority"]))
    return {"action": decision["action"], "policy": decision, "matched": matched,
            "reason": f"{decision['name']} ({decision['id']})"}


async def load(db: AsyncSession) -> list[dict]:
    rows = (await db.execute(select(Policy))).scalars().all()
    return [
        {"id": r.id, "name": r.name, "description": r.description, "priority": r.priority, "enabled": r.enabled,
         "conditions": r.conditions, "action": r.action, "version": r.version, "updated_by": r.updated_by, "updated_at": r.updated_at}
        for r in rows
    ]


async def ensure_defaults(db: AsyncSession) -> None:
    existing = set((await db.execute(select(Policy.id))).scalars().all())
    for p in DEFAULT_POLICIES:
        if p["id"] in existing:
            continue
        validate_conditions(p["conditions"])
        db.add(Policy(id=p["id"], name=p["name"], description=p["description"], priority=p["priority"],
                      enabled=p.get("enabled", True), conditions=p["conditions"], action=p["action"], updated_by="system"))
    await db.commit()
