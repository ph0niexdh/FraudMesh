"""Risk fusion.

risk = 100 * (w_txn*transaction + w_ato*takeover + w_kyc*kyc + w_cloud*cloud
              + w_graph*graph + w_temporal*temporal), clamped to [0, 100].

The default weights (0.30/0.20/0.20/0.10/0.15/0.05) are demonstration
configuration values, not scientifically optimised parameters.
"""
from __future__ import annotations

from app.schemas.config import FusionConfig

CHANNELS = ("transaction", "takeover", "kyc", "cloud", "graph", "temporal")


def fuse(scores: dict[str, float], config: FusionConfig) -> tuple[float, dict[str, float]]:
    """Return (risk 0..100, per-channel contribution in risk points)."""
    weights = config.weights.model_dump()
    contributions = {ch: round(100 * weights[ch] * float(scores.get(ch, 0.0)), 2) for ch in CHANNELS}
    risk = max(0.0, min(100.0, sum(contributions.values())))
    return round(risk, 1), contributions
