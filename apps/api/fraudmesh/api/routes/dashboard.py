"""Dashboard, alerts, metrics and model endpoints. Every number is computed from the stores."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, case as sql_case, func, literal_column, select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.api.routes.cases import case_summary
from fraudmesh.api.routes.events import event_dict
from fraudmesh.config import get_settings
from fraudmesh.db.models import Alert, Case, CaseEntity, Customer, Event, Feedback, MediaAnalysis, ModelRecord, Policy, Transaction
from fraudmesh.db.session import get_db
from fraudmesh.services.graph import store as graph
from fraudmesh.services.metrics import registry
from fraudmesh.services.metrics.telemetry import snapshot

router = APIRouter(tags=["dashboard"])
OPEN = ("NEW", "INVESTIGATING", "CONTAINED")
LIVE = Event.source != "historical-import"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _count(db, stmt) -> int:
    return int(await db.scalar(stmt) or 0)


async def kpis(db: AsyncSession) -> dict:
    now = _now()
    d1, d2 = now - timedelta(hours=24), now - timedelta(hours=48)

    async def both(model, cond_cur, cond_prev, col=None):
        c = col if col is not None else func.count()
        cur = await db.scalar(select(c).select_from(model).where(cond_cur))
        prev = await db.scalar(select(c).select_from(model).where(cond_prev))
        return {"value": float(cur or 0), "previous": float(prev or 0)}

    active = await _count(db, select(func.count()).select_from(Case).where(Case.status.in_(OPEN), Case.severity.in_(["HIGH", "CRITICAL"])))
    critical = await _count(db, select(func.count()).select_from(Case).where(Case.status.in_(OPEN), Case.severity == "CRITICAL"))
    scanned = await both(Event, and_(Event.event_type == "TRANSACTION", LIVE, Event.received_at >= d1),
                         and_(Event.event_type == "TRANSACTION", LIVE, Event.received_at >= d2, Event.received_at < d1))
    deepfake = await both(MediaAnalysis, and_(MediaAnalysis.created_at >= d1, MediaAnalysis.verdict.in_(["DEEPFAKE_LIKELY", "HIGH_CONFIDENCE_DEEPFAKE", "POSSIBLE_SPOOF"])),
                          and_(MediaAnalysis.created_at >= d2, MediaAnalysis.created_at < d1, MediaAnalysis.verdict.in_(["DEEPFAKE_LIKELY", "HIGH_CONFIDENCE_DEEPFAKE", "POSSIBLE_SPOOF"])))
    network = await both(Alert, and_(Alert.created_at >= d1, Alert.domain == "network"), and_(Alert.created_at >= d2, Alert.created_at < d1, Alert.domain == "network"))
    at_risk = float(await db.scalar(select(func.coalesce(func.sum(Case.amount_at_risk), 0)).where(Case.status.in_(OPEN))) or 0)
    protected = float(await db.scalar(select(func.coalesce(func.sum(Transaction.amount), 0)).join(Event, Event.id == Transaction.event_id)
                                      .where(Transaction.decision.in_(["BLOCK", "HOLD"]), Event.received_at >= d1)) or 0)
    return {
        "active_attacks": {"value": active},
        "critical_cases": {"value": critical},
        "transactions_scanned": scanned,
        "deepfake_alerts": deepfake,
        "network_threats": network,
        "amount_at_risk": {"value": at_risk, "protected_24h": protected, "currency": "INR"},
    }


@router.get("/dashboard")
async def dashboard(cu: CurrentUser = Depends(require("dashboard:read")), db: AsyncSession = Depends(get_db)):
    now = _now()
    d1 = now - timedelta(hours=24)
    hour = func.date_trunc("hour", Event.received_at)
    ev_rows = (await db.execute(select(hour, func.count(), func.sum(sql_case((Event.risk_score >= 40, 1), else_=0)))
                                .where(LIVE, Event.received_at >= d1).group_by(literal_column("1")))).all()
    ahour = func.date_trunc("hour", Alert.created_at)
    al_rows = (await db.execute(select(ahour, Alert.severity, func.count()).where(Alert.created_at >= d1).group_by(literal_column("1"), literal_column("2")))).all()
    chour = func.date_trunc("hour", Case.created_at)
    case_rows = (await db.execute(select(chour, func.count()).where(Case.created_at >= d1).group_by(literal_column("1")))).all()
    buckets: dict[str, dict] = {}
    for i in range(24, -1, -1):
        t = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        buckets[t.isoformat()] = {"t": t.isoformat(), "events": 0, "risky_events": 0, "alerts_critical": 0, "alerts_high": 0, "alerts_medium": 0, "cases": 0}
    for t, n, risky in ev_rows:
        b = buckets.get(t.isoformat())
        if b:
            b["events"], b["risky_events"] = int(n), int(risky or 0)
    for t, sev, n in al_rows:
        b = buckets.get(t.isoformat())
        if b and f"alerts_{sev.lower()}" in b:
            b[f"alerts_{sev.lower()}"] = int(n)
    for t, n in case_rows:
        b = buckets.get(t.isoformat())
        if b:
            b["cases"] = int(n)

    bins = (await db.execute(select(func.width_bucket(Event.risk_score, 0, 100.0001, 10), func.count())
                             .where(LIVE, Event.received_at >= d1).group_by(literal_column("1")))).all()
    hist = [{"bin": f"{(i - 1) * 10}-{i * 10}", "count": 0} for i in range(1, 11)]
    for b, n in bins:
        if 1 <= b <= 10:
            hist[b - 1]["count"] = int(n)
    levels = dict((await db.execute(select(Event.risk_level, func.count()).where(LIVE, Event.received_at >= d1).group_by(Event.risk_level))).all())

    top = (await db.execute(select(Case).where(Case.status.in_(OPEN)).order_by(Case.risk_score.desc(), Case.updated_at.desc()).limit(6))).scalars().all()
    stream = (await db.execute(select(Event).where(LIVE).order_by(Event.received_at.desc()).limit(40))).scalars().all()

    attack_graph = {"nodes": [], "edges": [], "case_id": None}
    focus = top[0] if top else None
    graph_ok = True
    if focus:
        ids = (await db.execute(select(CaseEntity.entity_id).where(CaseEntity.case_id == focus.id))).scalars().all()
        try:
            sub = await graph.neighborhood(list(ids)[:30], depth=1, limit=60)
            attack_graph = {**sub, "case_id": focus.id}
        except Exception:
            graph_ok = False
    else:
        try:
            await graph.ping()
        except Exception:
            graph_ok = False

    raw_alerts = await _count(db, select(func.count()).select_from(Alert).where(Alert.created_at >= d1))
    correlated = await _count(db, select(func.count()).select_from(Alert).where(Alert.created_at >= d1, Alert.case_id.is_not(None)))
    cases_24h = await _count(db, select(func.count()).select_from(Case).where(Case.created_at >= d1))
    n_pol = await _count(db, select(func.count()).select_from(Policy).where(Policy.enabled.is_(True)))
    snap = snapshot()
    return {
        "generated_at": now,
        "demo_mode": get_settings().demo_mode,
        "kpis": await kpis(db),
        "activity": list(buckets.values()),
        "risk_distribution": {"histogram": hist, "levels": {k: int(v) for k, v in levels.items()}},
        "top_attacks": [case_summary(c) for c in top],
        "stream": [event_dict(e) for e in stream],
        "attack_graph": attack_graph,
        "engines": registry.engine_status(graph_ok, n_pol),
        "performance": {
            "raw_alerts_24h": raw_alerts, "correlated_alerts_24h": correlated, "cases_24h": cases_24h,
            "compression_ratio": round(raw_alerts / cases_24h, 1) if cases_24h else None,
            "events_per_sec_1m": snap["events_per_sec_1m"],
            "pipeline_p50_ms": snap["pipeline_stages"].get("pipeline_total", {}).get("p50_ms"),
            "pipeline_p95_ms": snap["pipeline_stages"].get("pipeline_total", {}).get("p95_ms"),
            "correlation_p95_ms": snap["pipeline_stages"].get("correlation", {}).get("p95_ms"),
            "api_p95_ms": snap["api"]["p95_ms"],
            "ws_clients": snap["websocket"]["clients"],
        },
    }


@router.get("/alerts")
async def alerts(limit: int = Query(100, ge=1, le=500), domain: str | None = None, severity: str | None = None,
                 cu: CurrentUser = Depends(require("dashboard:read")), db: AsyncSession = Depends(get_db)):
    q = select(Alert, Event.event_type, Event.customer_id, Event.ts).join(Event, Event.id == Alert.event_id)
    if domain:
        q = q.where(Alert.domain == domain)
    if severity:
        q = q.where(Alert.severity == severity.upper())
    rows = (await db.execute(q.order_by(Alert.created_at.desc()).limit(limit))).all()
    return [{"id": a.id, "event_id": a.event_id, "case_id": a.case_id, "detector": a.detector, "domain": a.domain, "severity": a.severity,
             "title": a.title, "risk_score": a.risk_score, "status": a.status, "created_at": a.created_at, "event_type": et,
             "customer_id": cid, "ts": ts} for a, et, cid, ts in rows]


@router.get("/metrics")
async def metrics(cu: CurrentUser = Depends(require("dashboard:read")), db: AsyncSession = Depends(get_db)):
    now = _now()
    d7 = now - timedelta(days=7)
    by_status = dict((await db.execute(select(Case.status, func.count()).group_by(Case.status))).all())
    by_type = dict((await db.execute(select(Case.attack_type, func.count()).where(Case.created_at >= d7).group_by(Case.attack_type))).all())
    fb = dict((await db.execute(select(Feedback.label, func.count()).group_by(Feedback.label))).all())
    tp, fp = int(fb.get("CONFIRMED_FRAUD", 0)), int(fb.get("FALSE_POSITIVE", 0))
    alerts_by_domain = dict((await db.execute(select(Alert.domain, func.count()).where(Alert.created_at >= d7).group_by(Alert.domain))).all())
    decisions = dict((await db.execute(select(Transaction.decision, func.count()).join(Event, Event.id == Transaction.event_id).where(LIVE).group_by(Transaction.decision))).all())
    verdicts = dict((await db.execute(select(MediaAnalysis.verdict, func.count()).group_by(MediaAnalysis.verdict))).all())
    raw = int(await db.scalar(select(func.count()).select_from(Alert).where(Alert.created_at >= d7)) or 0)
    ncases = int(await db.scalar(select(func.count()).select_from(Case).where(Case.created_at >= d7)) or 0)
    return {
        "telemetry": snapshot(),
        "cases_by_status": by_status,
        "cases_by_attack_type_7d": by_type,
        "alerts_by_domain_7d": alerts_by_domain,
        "transaction_decisions": decisions,
        "deepfake_verdicts": verdicts,
        "alert_compression_7d": {"raw_alerts": raw, "cases": ncases, "ratio": round(raw / ncases, 1) if ncases else None},
        "analyst_feedback": {"confirmed_fraud": tp, "false_positive": fp, "precision": round(tp / (tp + fp), 3) if tp + fp else None},
        "customers": int(await db.scalar(select(func.count()).select_from(Customer)) or 0),
        "graph": await graph.stats(),
    }


@router.get("/models")
async def models(cu: CurrentUser = Depends(require("models:read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(ModelRecord).order_by(ModelRecord.domain, ModelRecord.name))).scalars().all()
    n_pol = int(await db.scalar(select(func.count()).select_from(Policy).where(Policy.enabled.is_(True))) or 0)
    try:
        await graph.ping()
        gok = True
    except Exception:
        gok = False
    return {
        "registry": [{"id": r.id, "name": r.name, "version": r.version, "model_type": r.model_type, "framework": r.framework, "domain": r.domain,
                      "training_date": r.training_date, "dataset": r.dataset, "metrics": r.metrics, "status": r.status, "artifact": r.artifact,
                      "artifact_sha256": r.artifact_sha256, "notes": r.notes} for r in rows],
        "engines": registry.engine_status(gok, n_pol),
    }
