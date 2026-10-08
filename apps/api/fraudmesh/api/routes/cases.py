"""Case management, investigation, explanation and counterfactual endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.api.routes.events import event_dict
from fraudmesh.db.models import Alert, AuditLog, Case, CaseAction, CaseEntity, CaseEvent, Detection, Event, Feedback, MediaAnalysis, User
from fraudmesh.db.session import get_db
from fraudmesh.services.audit import service as audit
from fraudmesh.services.cases import engine as cases
from fraudmesh.services.graph import risk as graph_risk
from fraudmesh.services.graph import store as graph
from fraudmesh.services.investigation import assistant, counterfactual
from fraudmesh.core import bus
from fraudmesh.core.ids import new_id

router = APIRouter(prefix="/cases", tags=["cases"])


def case_summary(c: Case) -> dict:
    return {
        "id": c.id, "title": c.title, "attack_type": c.attack_type, "severity": c.severity, "status": c.status,
        "risk_score": c.risk_score, "confidence": c.confidence, "recommended_action": c.recommended_action,
        "action_taken": c.action_taken, "primary_customer_id": c.primary_customer_id, "analyst_id": c.analyst_id,
        "raw_alert_count": c.raw_alert_count, "event_count": c.event_count, "amount_at_risk": c.amount_at_risk,
        "first_event_at": c.first_event_at, "last_event_at": c.last_event_at, "created_at": c.created_at, "updated_at": c.updated_at,
        "simulated": c.is_simulated, "domains": (c.fusion or {}).get("domains_present", []),
    }


async def _case(db: AsyncSession, case_id: str) -> Case:
    c = await db.get(Case, case_id)
    if c is None:
        raise HTTPException(404, "case not found")
    return c


@router.get("")
async def list_cases(
    status: str | None = None, severity: str | None = None, q: str | None = Query(default=None, max_length=80),
    limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
    cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db),
):
    stmt = select(Case)
    if status:
        stmt = stmt.where(Case.status.in_([s.strip().upper() for s in status.split(",")]))
    if severity:
        stmt = stmt.where(Case.severity.in_([s.strip().upper() for s in severity.split(",")]))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Case.title.ilike(like), Case.id.ilike(like), Case.primary_customer_id.ilike(like)))
    total = await db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = (await db.execute(stmt.order_by(Case.updated_at.desc()).limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": [case_summary(c) for c in rows]}


@router.get("/{case_id}")
async def get_case(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    c = await _case(db, case_id)
    ents = (await db.execute(select(CaseEntity).where(CaseEntity.case_id == case_id))).scalars().all()
    acts = (await db.execute(select(CaseAction).where(CaseAction.case_id == case_id).order_by(CaseAction.created_at.desc()))).scalars().all()
    fb = (await db.execute(select(Feedback).where(Feedback.case_id == case_id).order_by(Feedback.created_at.desc()))).scalars().all()
    analyst = await db.get(User, c.analyst_id) if c.analyst_id else None
    fusion = dict(c.fusion or {})
    return {
        **case_summary(c),
        "analyst": {"id": analyst.id, "name": analyst.display_name} if analyst else None,
        "story": c.story.split("\n") if c.story else [],
        "fusion": {k: fusion.get(k) for k in ("attack_score", "risk_level", "confidence", "contributions", "corroborating_domains",
                                              "evidence_floor", "model_version", "method", "logit", "bias")},
        "decision": fusion.get("decision"),
        "temporal": fusion.get("temporal"),
        "graph_summary": fusion.get("graph"),
        "entities": [{"id": e.entity_id, "type": e.entity_type, "label": e.label} for e in ents],
        "actions": [{"id": a.id, "action": a.action, "actor": a.actor, "note": a.note, "details": a.details, "created_at": a.created_at} for a in acts],
        "feedback": [{"label": f.label, "note": f.note, "created_at": f.created_at} for f in fb],
    }


@router.get("/{case_id}/timeline")
async def timeline(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    c = await _case(db, case_id)
    rows = (await db.execute(select(Event, CaseEvent.reason).join(CaseEvent, CaseEvent.event_id == Event.id)
                             .where(CaseEvent.case_id == case_id).order_by(Event.ts))).all()
    dets = (await db.execute(select(Detection).where(Detection.event_id.in_([e.id for e, _ in rows])))).scalars().all()
    by_ev: dict[str, list] = {}
    for d in dets:
        by_ev.setdefault(d.event_id, []).append({"detector": d.detector, "domain": d.details.get("domain"), "risk_score": d.risk_score,
                                                 "confidence": d.confidence, "reason_codes": d.reason_codes[:4], "model_version": d.model_version})
    stages = {s["event_id"]: s["stage"] for s in ((c.fusion or {}).get("temporal", {}).get("metadata", {}).get("best", {}) or {}).get("stages", [])}
    return [{**event_dict(e), "correlation_reason": reason, "stage": stages.get(e.id), "detections": by_ev.get(e.id, [])} for e, reason in rows]


@router.get("/{case_id}/graph")
async def case_graph(case_id: str, depth: int = Query(2, ge=1, le=3), cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    await _case(db, case_id)
    ids = (await db.execute(select(CaseEntity.entity_id).where(CaseEntity.case_id == case_id))).scalars().all()
    if not ids:
        return {"nodes": [], "edges": []}
    sub = await graph.neighborhood(list(ids)[:40], depth=depth, limit=120)
    prop = graph_risk.propagate(sub["nodes"], sub["edges"], ignore_flag_reason=case_id)
    case_ids = set(ids)
    for n in sub["nodes"]:
        n["in_case"] = n["id"] in case_ids
        p = prop.get(n["id"])
        n["propagated_risk"] = round(p["risk"], 3) if p else 0.0
        n["propagation_source"] = p["source"] if p else None
    return sub


@router.get("/{case_id}/explanation")
async def explanation(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    """'Why was this blocked?' — every claim references a stored detector output."""
    c = await _case(db, case_id)
    ev_ids = (await db.execute(select(CaseEvent.event_id).where(CaseEvent.case_id == case_id))).scalars().all()
    dets = (await db.execute(select(Detection, Event.event_type, Event.ts).join(Event, Event.id == Detection.event_id)
                             .where(Detection.event_id.in_(ev_ids)))).all()
    fusion = c.fusion or {}
    by_detector: dict[str, dict] = {}
    for d, et, ts in dets:
        cur = by_detector.get(d.detector)
        if cur is None or d.risk_score > cur["risk_score"]:
            by_detector[d.detector] = {"detector": d.detector, "domain": d.details.get("domain"), "risk_score": d.risk_score,
                                       "confidence": d.confidence, "model_version": d.model_version, "event_id": d.event_id,
                                       "event_type": et, "ts": ts, "reason_codes": d.reason_codes[:6], "metadata": d.details.get("metadata", {})}
    txn = by_detector.get("transaction-model")
    shap_rows = (txn or {}).get("metadata", {}).get("shap", [])
    df = by_detector.get("deepfake-detector")
    ids_det = by_detector.get("ids")
    return {
        "case_id": c.id,
        "headline": f"{c.recommended_action}: attack score {c.risk_score:.0f}/100 ({c.severity}) from {len(fusion.get('domains_present', []))} correlated detection domains",
        "decision": fusion.get("decision"),
        "fusion": {k: fusion.get(k) for k in ("attack_score", "risk_level", "confidence", "contributions", "corroborating_domains", "evidence_floor", "method", "model_version")},
        "transaction": {"detector": txn, "shap": shap_rows[1:] if shap_rows else [], "base_value": shap_rows[0] if shap_rows else None,
                        "method": "SHAP TreeExplainer on the LightGBM margin"} if txn else None,
        "deepfake": {"detector": df, "method": "EfficientNet-B4 classifier + Grad-CAM + forensic artifacts"} if df else None,
        "graph": fusion.get("graph"),
        "network": {"detector": ids_det, "findings": (ids_det or {}).get("metadata", {}).get("findings", [])} if ids_det else None,
        "temporal": fusion.get("temporal"),
        "detectors": sorted(by_detector.values(), key=lambda d: -d["risk_score"]),
    }


@router.get("/{case_id}/deepfake")
async def case_deepfake(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    await _case(db, case_id)
    evs = (await db.execute(select(Event).join(CaseEvent, CaseEvent.event_id == Event.id).where(CaseEvent.case_id == case_id))).scalars().all()
    ids = [e.payload.get("media_analysis_id") for e in evs if (e.payload or {}).get("media_analysis_id")]
    rows = (await db.execute(select(MediaAnalysis).where(MediaAnalysis.id.in_(ids)))).scalars().all() if ids else []
    kyc_ids = [e.payload.get("kyc_record_id") for e in evs if (e.payload or {}).get("kyc_record_id")]
    from fraudmesh.db.models import KycRecord

    kycs = (await db.execute(select(KycRecord).where(KycRecord.id.in_(kyc_ids)))).scalars().all() if kyc_ids else []
    return {
        "analyses": [{**r.result, "analysis_id": r.id, "fixture": r.fixture_name, "created_at": r.created_at} for r in rows],
        "kyc": [{"id": k.id, "doc_type": k.doc_type, "decision": k.decision, "scores": k.scores, "checks": k.checks, "fields": k.fields_masked} for k in kycs],
    }


@router.get("/{case_id}/counterfactual")
async def case_counterfactual(case_id: str, scenario: str = Query(..., pattern="^(no_deepfake|trusted_device|no_mfa_reset|normal_amount|no_network|siloed)$"),
                              cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    return await counterfactual.counterfactual(db, await _case(db, case_id), scenario)


@router.get("/{case_id}/counterfactuals")
async def case_counterfactuals(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    c = await _case(db, case_id)
    return [await counterfactual.counterfactual(db, c, name) for name in counterfactual.SCENARIOS]


@router.get("/{case_id}/intervention")
async def case_intervention(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    return await counterfactual.intervention(db, await _case(db, case_id))


@router.get("/{case_id}/siloed")
async def siloed(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    """Siloed vs FraudMesh: every raw alert as a separate tool would see it, vs the one correlated case."""
    c = await _case(db, case_id)
    alerts = (await db.execute(select(Alert, Event.event_type, Event.ts).join(Event, Event.id == Alert.event_id)
                               .where(Alert.case_id == case_id).order_by(Event.ts))).all()
    silo_of = {"transaction": "Transaction monitoring", "behavior": "Behavioural analytics", "identity": "Identity / MFA", "deepfake": "KYC vendor",
               "device": "Device intelligence", "graph": "Link analysis", "network": "SOC / IDS", "temporal": "—"}
    cf = await counterfactual.counterfactual(db, c, "siloed")
    timing = await counterfactual.siloed_vs_fraudmesh(db, c)
    return {
        "timing": timing,
        "siloed": {
            "alerts": [{"id": a.id, "silo": silo_of.get(a.domain, a.domain), "domain": a.domain, "title": a.title, "severity": a.severity,
                        "risk_score": a.risk_score, "event_type": et, "ts": ts} for a, et, ts in alerts],
            "best_single_detector": cf["counterfactual"],
        },
        "fraudmesh": {"cases": 1, "attack_score": c.risk_score, "severity": c.severity, "action": c.recommended_action,
                      "raw_alerts": c.raw_alert_count, "events": c.event_count, "attack_type": c.attack_type, "title": c.title},
        "compression_ratio": f"{c.raw_alert_count}:1",
    }


ACTIONS = {
    "ASSIGN_TO_ME": None, "START_INVESTIGATION": "INVESTIGATING", "CONTAIN": "CONTAINED", "BLOCK_ACCOUNT": "CONTAINED",
    "FREEZE_BENEFICIARY": "CONTAINED", "REVOKE_SESSIONS": "CONTAINED", "RELEASE_HOLD": "INVESTIGATING", "ESCALATE": "INVESTIGATING",
    "RESOLVE": "RESOLVED", "MARK_FALSE_POSITIVE": "FALSE_POSITIVE", "REOPEN": "INVESTIGATING", "NOTE": None,
}


class ActionRequest(BaseModel):
    action: Literal["ASSIGN_TO_ME", "START_INVESTIGATION", "CONTAIN", "BLOCK_ACCOUNT", "FREEZE_BENEFICIARY", "REVOKE_SESSIONS",
                    "RELEASE_HOLD", "ESCALATE", "RESOLVE", "MARK_FALSE_POSITIVE", "REOPEN", "NOTE"]
    note: str | None = Field(default=None, max_length=2000)


@router.post("/{case_id}/action")
async def case_action(case_id: str, body: ActionRequest, cu: CurrentUser = Depends(require("cases:act")), db: AsyncSession = Depends(get_db)):
    c = await _case(db, case_id)
    old = {"status": c.status, "analyst_id": c.analyst_id, "action_taken": c.action_taken}
    if body.action == "ASSIGN_TO_ME":
        c.analyst_id = cu.user.id
        if c.status == "NEW":
            c.status = "INVESTIGATING"
    elif ACTIONS[body.action]:
        c.status = ACTIONS[body.action]
    if body.action in ("BLOCK_ACCOUNT", "FREEZE_BENEFICIARY", "REVOKE_SESSIONS", "CONTAIN"):
        c.action_taken = body.action
    if body.action == "FREEZE_BENEFICIARY":
        bens = (await db.execute(select(CaseEntity.entity_id).where(CaseEntity.case_id == case_id, CaseEntity.entity_type == "Beneficiary"))).scalars().all()
        if bens:
            await graph.flag_entities(list(bens), 0.9, f"beneficiary frozen in case {case_id}")
    c.updated_at = datetime.now(timezone.utc)
    await cases.record_action(db, c, body.action, cu.user.email, body.note)
    await audit.record(db, cu.actor, f"case.{body.action.lower()}", "case", c.id, old_state=old,
                       new_state={"status": c.status, "analyst_id": c.analyst_id, "action_taken": c.action_taken, "note": body.note})
    await bus.publish("case.updated", {"case_id": c.id, "status": c.status, "action": body.action, "actor": cu.user.email,
                                       "severity": c.severity, "risk_score": c.risk_score, "title": c.title})
    return case_summary(c)


class FeedbackRequest(BaseModel):
    label: Literal["CONFIRMED_FRAUD", "FALSE_POSITIVE"]
    note: str | None = Field(default=None, max_length=2000)


@router.post("/{case_id}/feedback")
async def case_feedback(case_id: str, body: FeedbackRequest, cu: CurrentUser = Depends(require("cases:feedback")), db: AsyncSession = Depends(get_db)):
    """Closes the learning loop: confirmed attacker infrastructure seeds graph risk;
    a false positive un-flags entities this case flagged."""
    c = await _case(db, case_id)
    old = {"status": c.status}
    db.add(Feedback(id=new_id("fb"), case_id=c.id, label=body.label, actor_id=cu.user.id, note=body.note))
    ents = (await db.execute(select(CaseEntity).where(CaseEntity.case_id == case_id))).scalars().all()
    attacker = [e.entity_id for e in ents if e.entity_type in ("Device", "Beneficiary", "NetworkIndicator") or
                (e.entity_type == "IP" and not e.entity_id.startswith("ip:100."))]
    if body.label == "CONFIRMED_FRAUD":
        c.status = "RESOLVED"
        if attacker:
            await graph.flag_entities(attacker, 0.95, f"confirmed fraud in case {case_id}")
    else:
        c.status = "FALSE_POSITIVE"
        if attacker:
            await graph.unflag_entities(attacker)
    c.updated_at = datetime.now(timezone.utc)
    await cases.record_action(db, c, f"FEEDBACK_{body.label}", cu.user.email, body.note, {"entities_updated": len(attacker)})
    await audit.record(db, cu.actor, "case.feedback", "case", c.id, old_state=old, new_state={"status": c.status, "label": body.label})
    return {**case_summary(c), "graph_entities_updated": len(attacker)}


@router.get("/{case_id}/audit")
async def case_audit(case_id: str, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    await _case(db, case_id)
    rows = (await db.execute(select(AuditLog).where(AuditLog.resource_id == case_id).order_by(AuditLog.id.desc()).limit(200))).scalars().all()
    acts = (await db.execute(select(CaseAction).where(CaseAction.case_id == case_id).order_by(CaseAction.created_at.desc()))).scalars().all()
    return {
        "audit": [{"id": r.id, "ts": r.ts, "actor": r.actor, "action": r.action, "old_state": r.old_state, "new_state": r.new_state,
                   "hash": r.hash[:16]} for r in rows],
        "automated_actions": [{"action": a.action, "actor": a.actor, "note": a.note, "created_at": a.created_at} for a in acts if a.actor == "policy-engine"],
    }


class AskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=500)


@router.post("/{case_id}/ask")
async def ask(case_id: str, body: AskRequest, cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    return await assistant.answer(db, await _case(db, case_id), body.question)
