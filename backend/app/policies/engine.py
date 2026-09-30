"""Policy engine — maps a fused risk score onto a configurable action tier."""
from __future__ import annotations

from typing import Any

from app.schemas.config import ACTION_LABELS, PolicyConfig


def evaluate(risk: float, config: PolicyConfig) -> dict[str, Any]:
    score = int(round(max(0.0, min(100.0, risk))))
    tier = next((t for t in config.tiers if t.min_score <= score <= t.max_score), config.tiers[-1])
    action = tier.action.value
    return {
        "action": action,
        "action_label": ACTION_LABELS[action],
        "reason": f"Risk {score}/100 is within {tier.severity} band {tier.min_score}–{tier.max_score} "
                  f"({tier.policy_id}) → {ACTION_LABELS[action]}",
        "policy_id": tier.policy_id,
        "threshold": tier.min_score,
        "severity": tier.severity,
    }
