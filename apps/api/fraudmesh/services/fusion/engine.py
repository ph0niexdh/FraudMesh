"""Risk fusion: per-domain detector outputs → one attack score.

Model (weights in ml/artifacts/fusion/fusion.json, fitted by ml/fusion/train.py):

    z = b + Σ_d w_d · r_d + w_c · #{d : r_d ≥ 0.6}
    attack_score = 100 · σ(z)

* Not an average: agreement across independent domains (corroboration) compounds.
* Monotone: every weight is ≥ 0, so raising any detector's risk can never lower
  the attack score.
* Exactly attributable: z is additive, so each domain's contribution is its
  direct term plus an equal share of the corroboration term it participates in.

Each domain takes the strongest detector output observed in that domain (with
its confidence); confidence of the fused score reflects both detector
confidence and how many domains provided evidence at all.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from functools import lru_cache

from fraudmesh.config import get_settings
from fraudmesh.domain import DOMAINS, risk_level

CORROBORATION_THRESHOLD = 0.6
# High-precision domains: one confident, strong detector here is enough to raise an
# alert on its own (e.g. a 0.99 deepfake), even before other domains corroborate it.
# Noisy domains (behaviour, device) only ever count through corroboration.
FLOOR_DOMAINS = {"deepfake", "identity", "network", "transaction"}
FLOOR_FACTOR = 0.85
FLOOR_MIN_CONFIDENCE = 0.6


@lru_cache
def params() -> dict:
    return json.loads((get_settings().artifact_dir / "fusion" / "fusion.json").read_text())


@dataclass
class DomainInput:
    domain: str
    risk: float  # 0-100
    confidence: float  # 0-1
    detector: str
    reasons: list[dict]


def collapse(results: list[dict]) -> dict[str, DomainInput]:
    """Strongest (confidence-weighted) detector per domain."""
    best: dict[str, DomainInput] = {}
    for r in results:
        d = r["domain"]
        if d not in DOMAINS:
            continue
        cand = DomainInput(d, float(r["risk_score"]), float(r.get("confidence", 0.5)), r["detector"], r.get("reason_codes", []))
        cur = best.get(d)
        if cur is None or cand.risk * (0.5 + 0.5 * cand.confidence) > cur.risk * (0.5 + 0.5 * cur.confidence):
            best[d] = cand
    return best


def fuse(domains: dict[str, DomainInput], overrides: dict[str, float | None] | None = None) -> dict:
    """``overrides`` lets the counterfactual engine replace (float) or remove (None) a domain."""
    p = params()
    inputs = {d: v for d, v in domains.items()}
    eff: dict[str, float] = {d: v.risk / 100 for d, v in inputs.items()}
    if overrides:
        for d, val in overrides.items():
            if val is None:
                eff.pop(d, None)
            else:
                eff[d] = max(0.0, min(1.0, val / 100))

    corroborating = [d for d, r in eff.items() if r >= CORROBORATION_THRESHOLD]
    terms = {d: p["weights"].get(d, 0.0) * r for d, r in eff.items()}
    corr_term = p["corroboration_weight"] * len(corroborating)
    z = p["bias"] + sum(terms.values()) + corr_term
    score = 100 / (1 + math.exp(-z))
    floor, floor_domain = 0.0, None
    for d, r in eff.items():
        src = inputs.get(d)
        conf = src.confidence if src else 1.0
        if d in FLOOR_DOMAINS and conf >= FLOOR_MIN_CONFIDENCE and r * 100 * FLOOR_FACTOR > floor:
            floor, floor_domain = r * 100 * FLOOR_FACTOR, d
    floored = floor > score
    score = max(score, floor)

    contributions = []
    positive_total = sum(terms.values()) + corr_term or 1.0
    for d in DOMAINS:
        if d not in eff:
            continue
        logit = terms[d] + (p["corroboration_weight"] if d in corroborating else 0.0)
        src = inputs.get(d)
        contributions.append({
            "domain": d,
            "risk": round(eff[d] * 100, 1),
            "weight": p["weights"].get(d, 0.0),
            "logit_contribution": round(logit, 3),
            "share": round(logit / positive_total, 4) if positive_total else 0.0,
            "corroborating": d in corroborating,
            "detector": src.detector if src else "counterfactual",
            "confidence": round(src.confidence, 3) if src else None,
        })
    contributions.sort(key=lambda c: -c["logit_contribution"])

    present = [inputs[d] for d in eff if d in inputs]
    det_conf = sum(v.confidence for v in present) / len(present) if present else 0.0
    coverage = min(1.0, len(eff) / 5)
    confidence = round(det_conf * (0.55 + 0.45 * coverage), 3)
    return {
        "attack_score": round(score, 1),
        "risk_level": risk_level(score).value,
        "confidence": confidence,
        "logit": round(z, 3),
        "bias": p["bias"],
        "corroborating_domains": corroborating,
        "evidence_floor": {"applied": floored, "domain": floor_domain, "value": round(floor, 1)} if floor_domain else {"applied": False},
        "corroboration_logit": round(corr_term, 3),
        "contributions": contributions,
        "model_version": p["version"],
        "method": "calibrated logistic fusion (monotone, logit-additive) with high-precision evidence floor",
    }
