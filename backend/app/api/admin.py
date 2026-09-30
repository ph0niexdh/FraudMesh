"""Configuration, policies, metrics, model monitoring, graph, audit and health."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from app.api.deps import broadcaster_dep, engine_dep, require_admin
from app.config import get_settings
from app.database.db import session_scope
from app.database.models import AuditLog, CaseEntity, CaseEvent, FraudCase
from app.policies.fusion import CHANNELS
from app.schemas.cases import OPEN_STATUSES
from app.schemas.config import ACTION_LABELS, FusionConfig, PolicyConfig
from app.services.broadcaster import Broadcaster
from app.services.engine import FraudMeshEngine, get_engine
from app.services.metrics import dashboard_metrics, model_monitoring
from app.utils.timeutil import iso, utcnow

router = APIRouter(prefix="/api", tags=["platform"])


@router.get("/health")
def health(request: Request) -> dict:
    engine = get_engine()
    settings = get_settings()
    return {
        "status": "ok" if engine.ready else "initialising",
        "ready": engine.ready,
        "time": iso(utcnow()),
        "detectors": {
            "transaction": engine.txn.model is not None,
            "behavior": engine.behavior.model is not None,
            "kyc": True,
            "cloud": engine.cloud.model is not None,
            "graph": True,
        },
        "database": settings.database_url.split(":", 1)[0],
        "websocket_clients": request.app.state.broadcaster.client_count,
        "admin_auth_enabled": settings.admin_auth_enabled,
        "simulated_data": True,
        "banner": "SIMULATED DATA — NO REAL BANK INCIDENT",
    }


@router.get("/metrics")
def metrics(request: Request, engine: FraudMeshEngine = Depends(engine_dep)) -> dict:
    with session_scope() as s:
        data = dashboard_metrics(s, engine)
    data["websocket_clients"] = request.app.state.broadcaster.client_count
    return data


@router.get("/models")
def models(engine: FraudMeshEngine = Depends(engine_dep)) -> dict:
    with session_scope() as s:
        return model_monitoring(s, engine)


@router.post("/models/retrain")
async def retrain(actor: str = Depends(require_admin), engine: FraudMeshEngine = Depends(engine_dep),
                  bc: Broadcaster = Depends(broadcaster_dep)) -> dict:
    result = await run_in_threadpool(engine.retrain_transaction_model, actor)
    await bc.publish([{"type": "model.retrained", "data": result}])
    return result


@router.get("/config")
def get_config(engine: FraudMeshEngine = Depends(engine_dep)) -> dict:
    cfg = engine.fusion_config.model_dump()
    return {
        **cfg,
        "weights_sum": round(sum(cfg["weights"].values()), 4),
        "channels": list(CHANNELS),
        "formula": "risk = 100 * Σ weight_c * score_c  (clamped 0–100)",
        "note": "Demonstration configuration values — not scientifically optimised.",
    }


@router.put("/config")
async def put_config(cfg: FusionConfig, rescore: bool = Query(True), actor: str = Depends(require_admin),
                     engine: FraudMeshEngine = Depends(engine_dep), bc: Broadcaster = Depends(broadcaster_dep)) -> dict:
    await run_in_threadpool(engine.update_fusion, cfg, actor)
    msgs = [{"type": "config.updated", "data": cfg.model_dump()}]
    if rescore:
        msgs += await run_in_threadpool(engine.rescore_open_cases)
    await bc.publish(msgs)
    return get_config(engine)


@router.get("/policies")
def get_policies(engine: FraudMeshEngine = Depends(engine_dep)) -> dict:
    return {**engine.policy_config.model_dump(mode="json"), "action_labels": ACTION_LABELS}


@router.put("/policies")
async def put_policies(cfg: PolicyConfig, rescore: bool = Query(True), actor: str = Depends(require_admin),
                       engine: FraudMeshEngine = Depends(engine_dep), bc: Broadcaster = Depends(broadcaster_dep)) -> dict:
    await run_in_threadpool(engine.update_policy, cfg, actor)
    msgs = [{"type": "policy.updated", "data": cfg.model_dump(mode="json")}]
    if rescore:
        msgs += await run_in_threadpool(engine.rescore_open_cases)
    await bc.publish(msgs)
    return get_policies(engine)


@router.get("/graph")
def graph(case_id: str | None = Query(None, max_length=32), entity: str | None = Query(None, max_length=64),
          depth: int = Query(2, ge=0, le=4), limit: int = Query(200, ge=10, le=600),
          engine: FraudMeshEngine = Depends(engine_dep)) -> dict:
    """Entity graph around a case, an entity, or (default) all active cases."""
    include_events: set[str] | None = None
    with session_scope() as s:
        if case_id:
            if s.get(FraudCase, case_id) is None:
                raise HTTPException(404, "case not found")
            centers = list(s.scalars(select(CaseEntity.entity_token).where(CaseEntity.case_id == case_id)))
            include_events = set(s.scalars(select(CaseEvent.event_id).where(CaseEvent.case_id == case_id)))
            depth = min(depth, 1)
        elif entity:
            centers = [entity]
            if entity not in engine.graph.g:
                # allow lookup by display label (synthetic demo ids only)
                match = [n for n, d in engine.graph.g.nodes(data=True) if d.get("label") == entity]
                centers = match[:1]
            if not centers:
                raise HTTPException(404, "entity not found in graph")
            include_events = set()
        else:
            active = s.scalars(select(FraudCase.case_id).where(FraudCase.status.in_(OPEN_STATUSES))
                               .order_by(FraudCase.risk_score.desc()).limit(6)).all()
            centers = list(s.scalars(select(CaseEntity.entity_token).where(CaseEntity.case_id.in_(active))))
            include_events = set(s.scalars(select(CaseEvent.event_id).where(CaseEvent.case_id.in_(active))))
            depth = min(depth, 1)
    with engine.lock:
        data = engine.graph.export(centers, depth=depth, limit=limit, include_events=include_events)
        data["suspicious_paths"] = engine.graph.suspicious_paths(centers)
        data["graph_risk"] = engine.graph.score_entities(centers)
        data["stats"] = engine.graph.stats()
    data["centers"] = centers
    return data


@router.get("/audit")
def audit_log(limit: int = Query(100, ge=1, le=500), action: str | None = Query(None, max_length=48),
              entity_id: str | None = Query(None, max_length=64), _: FraudMeshEngine = Depends(engine_dep)) -> dict:
    q = select(AuditLog)
    if action:
        q = q.where(AuditLog.action == action)
    if entity_id:
        q = q.where(AuditLog.entity_id == entity_id)
    with session_scope() as s:
        rows = s.scalars(q.order_by(AuditLog.id.desc()).limit(limit)).all()
        return {"entries": [{"id": r.id, "timestamp": iso(r.timestamp), "action": r.action, "actor": r.actor,
                             "entity_type": r.entity_type, "entity_id": r.entity_id, "details": r.details}
                            for r in rows]}
