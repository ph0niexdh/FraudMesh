from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool

from app.api.deps import broadcaster_dep, engine_dep
from app.database.db import session_scope
from app.database.models import AnalystFeedback, CaseEntity, CaseEvent, Event, FraudCase, RiskScore
from app.schemas.cases import OPEN_STATUSES, FeedbackIn
from app.services.broadcaster import Broadcaster
from app.services.engine import FraudMeshEngine
from app.services.serializers import case_summary, event_to_dict, feedback_to_dict
from app.utils.timeutil import iso

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("")
def list_cases(
    status: str | None = Query(None, description="status name, or 'active' for NEW/INVESTIGATING/HOLD"),
    min_risk: float | None = Query(None, ge=0, le=100),
    severity: str | None = Query(None, max_length=16),
    sort: str = Query("updated", pattern="^(updated|risk|created)$"),
    limit: int = Query(50, ge=1, le=200),
    _: FraudMeshEngine = Depends(engine_dep),
) -> dict:
    q = select(FraudCase)
    if status == "active":
        q = q.where(FraudCase.status.in_(OPEN_STATUSES))
    elif status:
        q = q.where(FraudCase.status == status.upper())
    if min_risk is not None:
        q = q.where(FraudCase.risk_score >= min_risk)
    if severity:
        q = q.where(FraudCase.severity == severity.upper())
    order = {"updated": FraudCase.updated_at.desc(), "risk": FraudCase.risk_score.desc(),
             "created": FraudCase.created_at.desc()}[sort]
    with session_scope() as s:
        rows = s.scalars(q.order_by(order).limit(limit)).all()
        counts = dict(s.execute(select(CaseEvent.case_id, func.count()).where(
            CaseEvent.case_id.in_([r.case_id for r in rows])).group_by(CaseEvent.case_id)).all())
        return {"cases": [case_summary(r, counts.get(r.case_id, 0)) for r in rows]}


def case_detail(case_id: str, engine: FraudMeshEngine) -> dict[str, Any]:
    with session_scope() as s:
        row = s.get(FraudCase, case_id)
        if row is None:
            raise HTTPException(404, "case not found")
        events = s.scalars(select(Event).join(CaseEvent, CaseEvent.event_id == Event.event_id)
                           .where(CaseEvent.case_id == case_id).order_by(Event.timestamp)).all()
        ents = s.scalars(select(CaseEntity).where(CaseEntity.case_id == case_id)).all()
        history = s.scalars(select(RiskScore).where(RiskScore.case_id == case_id).order_by(RiskScore.id)).all()
        feedback = s.scalars(select(AnalystFeedback).where(AnalystFeedback.case_id == case_id)
                             .order_by(AnalystFeedback.created_at)).all()
        ev_dicts = [event_to_dict(e) for e in events]
        entity_list = [{"token": e.entity_token, "type": e.entity_type, "label": e.label, "bank": e.bank_name}
                       for e in ents]
        tokens = [e.entity_token for e in ents]
        with engine.lock:
            graph = engine.graph.export(tokens, depth=1, limit=150, include_events={e.event_id for e in events})
            paths = engine.graph.suspicious_paths(tokens)
        # accounts reached through shared devices/IPs are "related" even if they are not case entities
        related_accounts = {e["token"]: e for e in entity_list if e["type"] == "account"}
        for node in graph["nodes"]:
            if node["type"] == "account" and node["id"] not in related_accounts:
                related_accounts[node["id"]] = {"token": node["id"], "type": "account", "label": node["label"],
                                                "bank": node["bank"], "via_graph": True}
        detail = case_summary(row, len(events))
        detail.update({
            "events": ev_dicts,
            "entities": entity_list,
            "related_accounts": list(related_accounts.values()),
            "related_devices": [e for e in entity_list if e["type"] == "device"],
            "related_ips": [e for e in entity_list if e["type"] == "ip"],
            "related_customers": [e for e in entity_list if e["type"] == "customer"],
            "explanations": row.explanations or [],
            "contributions": row.contributions or {},
            "graph_signals": row.graph_signals or [],
            "detector_outputs": [{"event_id": e["event_id"], "event_type": e["event_type"],
                                  "timestamp": e["timestamp"], "results": e["detector_results"]} for e in ev_dicts],
            "risk_history": [{"event_id": h.event_id, "risk_score": h.risk_score, "timestamp": iso(h.timestamp),
                              "channel_scores": h.channel_scores, "policy_action": h.policy_action} for h in history],
            "analyst_feedback": [feedback_to_dict(f) for f in feedback],
            "graph": graph,
            "suspicious_paths": paths,
            "fusion_weights": engine.fusion_config.weights.model_dump(),
        })
        return detail


@router.get("/{case_id}")
def get_case(case_id: str, engine: FraudMeshEngine = Depends(engine_dep)) -> dict:
    return case_detail(case_id, engine)


@router.post("/{case_id}/feedback")
async def submit_feedback(case_id: str, fb: FeedbackIn, engine: FraudMeshEngine = Depends(engine_dep),
                          bc: Broadcaster = Depends(broadcaster_dep)) -> dict:
    try:
        result = await run_in_threadpool(engine.apply_feedback, case_id, fb)
    except KeyError as err:
        raise HTTPException(404, "case not found") from err
    await bc.publish(result["messages"])
    return {k: v for k, v in result.items() if k != "messages"}
