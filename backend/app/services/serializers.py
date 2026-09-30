from __future__ import annotations

from typing import Any

from app.database.models import AnalystFeedback, Event, FraudCase
from app.utils.timeutil import iso


def event_to_dict(row: Event) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "event_type": row.event_type,
        "timestamp": iso(row.timestamp),
        "received_at": iso(row.received_at),
        "customer_token": row.customer_token,
        "account_token": row.account_token,
        "device_token": row.device_token,
        "ip_token": row.ip_token,
        "customer_label": row.customer_label,
        "account_label": row.account_label,
        "device_label": row.device_label,
        "ip_label": row.ip_label,
        "channel": row.channel,
        "bank_name": row.bank_name,
        "amount": row.amount,
        "metadata": row.event_metadata or {},
        "signal_score": round(row.signal_score or 0.0, 4),
        "suspicious": bool(row.suspicious),
        "detector_results": row.detector_results or [],
        "case_id": row.case_id,
        "source": row.source,
    }


def case_summary(row: FraudCase, event_count: int | None = None) -> dict[str, Any]:
    return {
        "case_id": row.case_id,
        "risk_score": round(row.risk_score, 1),
        "severity": row.severity,
        "status": row.status,
        "created_at": iso(row.created_at),
        "updated_at": iso(row.updated_at),
        "first_event_at": iso(row.first_event_at),
        "last_event_at": iso(row.last_event_at),
        "channel_scores": row.channel_scores or {},
        "graph_score": round(row.graph_score, 4),
        "temporal_score": round(row.temporal_score, 4),
        "confidence": round(row.confidence, 4),
        "policy_action": row.policy_action,
        "policy": row.policy or {},
        "summary": row.summary,
        "banks": row.banks or [],
        "scenario": row.scenario,
        "source": row.source,
        "event_count": event_count,
        "top_signals": [e["text"] for e in (row.explanations or [])[:5]],
    }


def feedback_to_dict(row: AnalystFeedback) -> dict[str, Any]:
    return {
        "id": row.id,
        "case_id": row.case_id,
        "action": row.action,
        "previous_status": row.previous_status,
        "new_status": row.new_status,
        "analyst": row.analyst,
        "notes": row.notes,
        "created_at": iso(row.created_at),
    }
