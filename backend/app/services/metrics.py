"""Dashboard and monitoring metrics — all computed from stored data, never static."""
from __future__ import annotations

import os
import re
import resource
from datetime import timedelta
from typing import Any

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database.models import AnalystFeedback, AuditLog, CaseEvent, Event, FraudCase, KycEvent
from app.schemas.cases import OPEN_STATUSES, CaseStatus
from app.services.engine import FraudMeshEngine
from app.utils.timeutil import ensure_utc, utcnow

TOKEN_RE = re.compile(r"^(usr|acc|dev|ip)_[0-9a-f]{10}$")


def dashboard_metrics(s: Session, engine: FraudMeshEngine) -> dict[str, Any]:
    now = utcnow()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    count = lambda q: s.scalar(q) or 0  # noqa: E731
    active = count(select(func.count()).select_from(FraudCase).where(FraudCase.status.in_(OPEN_STATUSES)))
    high = count(select(func.count()).select_from(FraudCase)
                 .where(FraudCase.status.in_(OPEN_STATUSES), FraudCase.risk_score >= 60))
    epm = count(select(func.count()).select_from(Event).where(Event.received_at >= now - timedelta(seconds=60)))
    cases_today = count(select(func.count()).select_from(FraudCase).where(FraudCase.created_at >= today))
    confirmed = count(select(func.count()).select_from(FraudCase).where(FraudCase.status == CaseStatus.CONFIRMED_FRAUD.value))
    false_pos = count(select(func.count()).select_from(FraudCase).where(FraudCase.status == CaseStatus.FALSE_POSITIVE.value))
    total_cases = count(select(func.count()).select_from(FraudCase))
    avg_risk_active = s.scalar(select(func.avg(FraudCase.risk_score)).where(FraudCase.status.in_(OPEN_STATUSES)))
    avg_risk_all = s.scalar(select(func.avg(FraudCase.risk_score)))
    total_events = count(select(func.count()).select_from(Event))
    suspicious = count(select(func.count()).select_from(Event).where(Event.suspicious.is_(True)))
    by_type = dict(s.execute(select(Event.event_type, func.count()).group_by(Event.event_type)).all())
    by_bank = dict(s.execute(select(Event.bank_name, func.count()).where(Event.bank_name.is_not(None))
                             .group_by(Event.bank_name)).all())
    severity = dict(s.execute(select(FraudCase.severity, func.count()).where(FraudCase.status.in_(OPEN_STATUSES))
                              .group_by(FraudCase.severity)).all())
    status = dict(s.execute(select(FraudCase.status, func.count()).group_by(FraudCase.status)).all())
    events_in_cases = count(select(func.count()).select_from(CaseEvent))

    # investigation time: case creation → first decisive analyst action
    durations = []
    decisive = [CaseStatus.CONFIRMED_FRAUD.value, CaseStatus.FALSE_POSITIVE.value, CaseStatus.RESOLVED.value]
    rows = s.execute(select(FraudCase.created_at, func.min(AnalystFeedback.created_at))
                     .join(AnalystFeedback, AnalystFeedback.case_id == FraudCase.case_id)
                     .where(AnalystFeedback.new_status.in_(decisive)).group_by(FraudCase.case_id)).all()
    for created, decided in rows:
        if created and decided:
            durations.append((ensure_utc(decided) - ensure_utc(created)).total_seconds() / 60)

    # events per minute over the last 30 minutes (live throughput sparkline)
    since = now - timedelta(minutes=30)
    recent = s.scalars(select(Event.received_at).where(Event.received_at >= since)).all()
    buckets = [0] * 30
    for r in recent:
        idx = int((ensure_utc(r) - since).total_seconds() // 60)
        if 0 <= idx < 30:
            buckets[idx] += 1

    lat = list(engine.pipeline_latencies)
    case_lat = list(engine.case_build_latencies)
    return {
        "active_cases": active,
        "high_risk_cases": high,
        "events_per_minute": epm,
        "cases_today": cases_today,
        "confirmed_fraud": confirmed,
        "false_positives": false_pos,
        "average_risk_score": round(float(avg_risk_active), 1) if avg_risk_active is not None else 0.0,
        "average_risk_score_all_cases": round(float(avg_risk_all), 1) if avg_risk_all is not None else 0.0,
        "total_cases": total_cases,
        "total_events": total_events,
        "suspicious_events": suspicious,
        "events_by_type": by_type,
        "events_by_bank": by_bank,
        "open_cases_by_severity": severity,
        "cases_by_status": status,
        "alerts_merged_per_case": round(events_in_cases / total_cases, 2) if total_cases else 0.0,
        "avg_investigation_minutes": round(float(np.mean(durations)), 1) if durations else None,
        "events_per_minute_series": buckets,
        "pipeline_latency_ms": {
            "avg": round(float(np.mean(lat)), 2) if lat else None,
            "p95": round(float(np.percentile(lat, 95)), 2) if lat else None,
            "samples": len(lat),
        },
        "case_construction_latency_ms": {
            "avg": round(float(np.mean(case_lat)), 2) if case_lat else None,
            "samples": len(case_lat),
        },
        "websocket_clients": None,
        "generated_at": now.isoformat(),
        "simulated_data": True,
    }


def _histogram(values: list[float], bins: int = 10) -> list[dict[str, Any]]:
    counts, edges = np.histogram(values or [0], bins=bins, range=(0, 1))
    if not values:
        counts = np.zeros(bins, dtype=int)
    return [{"bin": f"{edges[i]:.1f}–{edges[i + 1]:.1f}", "count": int(counts[i])} for i in range(bins)]


def model_monitoring(s: Session, engine: FraudMeshEngine) -> dict[str, Any]:
    scores: dict[str, list[float]] = {"transaction": [], "takeover": [], "behavior_anomaly": [], "kyc": [],
                                      "cloud": [], "graph": []}
    for (results,) in s.execute(select(Event.detector_results)):
        for r in results or []:
            ch = r.get("channel")
            if ch in scores:
                scores[ch].append(float(r.get("score", 0)))
            if ch == "takeover":
                scores["behavior_anomaly"].append(float(r.get("details", {}).get("behavior_score", 0)))
    fb = dict(s.execute(select(AnalystFeedback.action, func.count()).group_by(AnalystFeedback.action)).all())
    recent_fb = s.execute(select(AnalystFeedback).order_by(AnalystFeedback.created_at.desc()).limit(10)).scalars().all()
    confirmed = s.scalar(select(func.count()).select_from(FraudCase)
                         .where(FraudCase.status == CaseStatus.CONFIRMED_FRAUD.value)) or 0
    false_pos = s.scalar(select(func.count()).select_from(FraudCase)
                         .where(FraudCase.status == CaseStatus.FALSE_POSITIVE.value)) or 0
    decided = confirmed + false_pos

    # privacy & audit coverage — measured, not asserted
    rows = s.execute(select(Event.customer_token, Event.account_token, Event.device_token, Event.ip_token)).all()
    ids = [v for row in rows for v in row if v]
    token_cov = sum(1 for v in ids if TOKEN_RE.match(v)) / len(ids) if ids else 1.0
    kyc_total = s.scalar(select(func.count()).select_from(KycEvent)) or 0
    kyc_retained = s.scalar(select(func.count()).select_from(KycEvent).where(KycEvent.media_retained.is_(True))) or 0
    n_events = s.scalar(select(func.count()).select_from(Event)) or 0
    audited = s.scalar(select(func.count(func.distinct(AuditLog.entity_id))).where(AuditLog.action == "event.received")) or 0
    cases = s.scalars(select(FraudCase.explanations)).all()
    with_expl = sum(1 for e in cases if e)
    with_top = sum(1 for e in cases if e and len(e) >= 3)

    usage = resource.getrusage(resource.RUSAGE_SELF)
    det_rows = []
    for det, extra in (
        (engine.txn, {"type": "XGBoost classifier", "trained_at": engine.txn.trained_at,
                      "training_samples": engine.txn.training_samples,
                      "feedback_samples": engine.txn.feedback_samples, "explainer": engine.txn.explainer_kind}),
        (engine.behavior, {"type": "Isolation Forest + takeover rules", "trained_at": engine.behavior.trained_at}),
        (engine.kyc, {"type": "OpenCV heuristics (DEMO)", "display_name": engine.kyc.display_name,
                      "face_detection_available": engine.kyc.face_detection_available}),
        (engine.cloud, {"type": "Isolation Forest + cloud rules", "trained_at": engine.cloud.trained_at}),
    ):
        stats = det.stats.summary()
        ok = (getattr(det, "model", True) is not None) and stats["errors"] == 0
        det_rows.append({"name": det.name, "channel": det.channel,
                         "version": det.version_label, "status": "healthy" if ok else "degraded",
                         **extra, **stats})
    det_rows.append({"name": "entity_graph", "channel": "graph", "version": "networkx-rules-v1", "status": "healthy",
                     "type": "NetworkX graph + structural rules", **engine.graph.stats()})

    return {
        "detectors": det_rows,
        "transaction_evaluation": engine.txn.evaluation,
        "distributions": {k: _histogram(v) for k, v in scores.items()},
        "score_counts": {k: len(v) for k, v in scores.items()},
        "feedback": {"by_action": fb, "confirmed_fraud": confirmed, "false_positives": false_pos,
                     "analyst_precision": round(confirmed / decided, 3) if decided else None,
                     "recent": [{"case_id": f.case_id, "action": f.action, "analyst": f.analyst,
                                 "created_at": f.created_at.isoformat()} for f in recent_fb]},
        "privacy": {
            "pii_tokenization_coverage": round(token_cov, 4),
            "identifier_values_checked": len(ids),
            "kyc_events": kyc_total,
            "raw_kyc_media_retained": kyc_retained,
            "kyc_retention_enabled": engine.settings.kyc_retain_media,
        },
        "explainability": {
            "cases": len(cases),
            "explanation_coverage": round(with_expl / len(cases), 4) if cases else None,
            "top_signal_availability": round(with_top / len(cases), 4) if cases else None,
        },
        "audit": {"events": n_events, "events_with_audit_record": audited,
                  "audit_coverage": round(audited / n_events, 4) if n_events else None},
        "system": {
            "max_rss_mb": round(usage.ru_maxrss / 1024, 1),
            "cpu_user_seconds": round(usage.ru_utime, 1),
            "pid": os.getpid(),
            "uptime_seconds": int((utcnow() - engine.started_at).total_seconds()),
        },
    }
