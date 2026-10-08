"""Calibrate the risk-fusion weights.

Fusion is a logistic model in logit space over per-domain risks r_d ∈ [0,1]
(missing domain → 0, i.e. "no evidence", not "evidence of safety") plus a
corroboration term (number of independent domains ≥ 0.6):

    attack_score = 100 · σ(b + Σ_d w_d·r_d + w_c·corroboration)

Weights are fit on simulated *case-level* vectors: benign cases often have ONE
loud detector (a traveller trips behaviour, a phone upgrade trips device, an
unrelated IDS alert), while attacks light up several domains. The model therefore
learns that agreement across domains matters more than any single score — the
core FraudMesh thesis — instead of us asserting it with hand-tuned numbers.

Usage: PYTHONPATH=apps/api python ml/fusion/train.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from scipy.optimize import minimize
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

DOMAINS = ["transaction", "behavior", "identity", "deepfake", "device", "graph", "network", "temporal"]
OUT = Path(__file__).resolve().parents[1] / "artifacts" / "fusion"


# How often each detector is "loud" (≥0.6) on a benign case. Behavioural and device
# signals fire on travellers and phone upgrades; a high-confidence deepfake score or
# a completed attack sequence rarely fires on genuine customers. (Assumptions —
# documented in the model card; re-fit on labelled production cases.)
BENIGN_LOUD_RATE = {
    "transaction": 0.10, "behavior": 0.30, "identity": 0.12, "deepfake": 0.03,
    "device": 0.25, "graph": 0.10, "network": 0.18, "temporal": 0.04,
}
# Attack templates: (weight, domains that light up, optional domains)
ATTACKS = [
    (0.20, ["transaction", "behavior", "identity", "deepfake", "device", "temporal"], ["graph", "network"]),
    (0.18, ["transaction", "behavior", "identity", "device", "temporal"], ["network", "graph"]),
    (0.16, ["deepfake", "identity"], ["device"]),
    (0.12, ["graph", "transaction"], ["device"]),
    (0.12, ["network", "identity"], ["behavior", "temporal"]),
    (0.08, ["network", "temporal"], []),
    (0.08, ["transaction", "behavior"], []),
    (0.06, ["deepfake"], []),
]


def cases(n: int, seed: int):
    rng = np.random.default_rng(seed)
    X, y = [], []
    idx = {d: i for i, d in enumerate(DOMAINS)}
    tw = np.array([a[0] for a in ATTACKS])
    tw = tw / tw.sum()
    for _ in range(n):
        attack = rng.random() < 0.35
        r = np.zeros(len(DOMAINS))
        if attack:
            _, hot, optional = ATTACKS[rng.choice(len(ATTACKS), p=tw)]
            hot = list(hot) + [d for d in optional if rng.random() < 0.5]
            for d in DOMAINS:
                if d in hot:
                    # attackers evade some detectors: each hot domain is weak 15% of the time
                    r[idx[d]] = np.clip(rng.beta(7, 2) if rng.random() > 0.15 else rng.beta(2, 4), 0, 1)
                elif rng.random() < 0.5:
                    r[idx[d]] = np.clip(rng.beta(1.3, 6), 0, 1)
        else:
            for d in DOMAINS:
                if rng.random() < 0.55:
                    r[idx[d]] = np.clip(rng.beta(1.2, 8), 0, 1)
                if rng.random() < BENIGN_LOUD_RATE[d]:
                    r[idx[d]] = np.clip(rng.beta(5, 2.5), 0, 1)
        corroboration = float((r >= 0.6).sum())
        X.append(np.concatenate([r, [corroboration]]))
        y.append(int(attack))
    return np.array(X), np.array(y)


def fit_monotone_logistic(X: np.ndarray, y: np.ndarray, l2: float) -> tuple[np.ndarray, float]:
    n, d = X.shape

    def loss(theta):
        w, b = theta[:d], theta[d]
        z = X @ w + b
        p = 1 / (1 + np.exp(-z))
        nll = np.mean(np.logaddexp(0, z) - y * z) + l2 * np.dot(w, w) / 2
        g = p - y
        grad_w = X.T @ g / n + l2 * w
        grad_b = g.mean()
        return nll, np.concatenate([grad_w, [grad_b]])

    res = minimize(loss, np.zeros(d + 1), jac=True, method="L-BFGS-B", bounds=[(0, None)] * d + [(None, None)])
    if not res.success:
        raise SystemExit(f"fusion fit failed: {res.message}")
    return res.x[:d], float(res.x[d])


def main() -> None:
    X, y = cases(40_000, 5)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, stratify=y, random_state=5)
    # Logistic loss with L2, fit under w ≥ 0 (monotonicity: more risk in any domain
    # must never lower the attack score). Unconstrained LR learns negative weights for
    # noisy detectors, which would let an attacker *lower* their score by tripping them.
    coef, bias = fit_monotone_logistic(Xtr, ytr, l2=0.0005)
    p = 1 / (1 + np.exp(-(Xte @ coef + bias)))
    weights = {d: round(float(w), 4) for d, w in zip(DOMAINS, coef[:-1])}
    out = {
        "name": "risk-fusion",
        "version": f"logit-fusion-{datetime.now(timezone.utc):%Y%m%d}",
        "model_type": "Calibrated logistic fusion (logit space) with corroboration term",
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "domains": DOMAINS,
        "weights": weights,
        "corroboration_weight": round(float(coef[-1]), 4),
        "corroboration_threshold": 0.6,
        "bias": round(float(bias), 4),
        "metrics": {"roc_auc": round(float(roc_auc_score(yte, p)), 4), "pr_auc": round(float(average_precision_score(yte, p)), 4)},
        "dataset": {"source": "simulated case-level domain-risk vectors", "cases": len(y), "attack_rate": round(float(y.mean()), 3),
                    "benign_loud_rate": BENIGN_LOUD_RATE, "attack_templates": [{"weight": w, "domains": h, "optional": o} for w, h, o in ATTACKS]},
        "limitations": "Weights reflect the simulator's assumptions about detector behaviour; re-fit on labelled production cases.",
    }
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "fusion.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: out[k] for k in ("weights", "corroboration_weight", "bias", "metrics")}, indent=2))


if __name__ == "__main__":
    main()
