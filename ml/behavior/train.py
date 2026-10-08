"""Train the behavioural anomaly model.

Unsupervised: models are fit on *normal* sessions only. Candidates:
  * Isolation Forest
  * Local Outlier Factor (novelty mode)
  * Autoencoder (scikit-learn MLP, 10→6→3→6→10, reconstruction error)

Evaluated on held-out normal sessions + injected anomalous sessions (ROC-AUC,
PR-AUC, latency). Selection: highest ROC-AUC unless another model is within 0.01
and ≥3x faster. Raw scores are mapped to [0,1] via the empirical CDF of normal
validation scores ("more unusual than X% of normal sessions").

Usage:  PYTHONPATH=apps/api python ml/behavior/train.py
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from fraudmesh.services.behavior.autoencoder import AutoencoderScorer
from fraudmesh.services.simulator.datagen import BEHAVIOR_FEATURES, behavior_sessions

OUT = Path(__file__).resolve().parents[1] / "artifacts" / "behavior"
SEED = 11


def _latency(fn, row, n=200) -> float:
    fn(row)
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        fn(row)
        ts.append((time.perf_counter() - t) * 1000)
    return float(np.percentile(ts, 50))


def main() -> None:
    X_train, _ = behavior_sessions(20_000, 0, SEED)
    X_val, _ = behavior_sessions(4_000, 0, SEED + 1)
    X_test, y_test = behavior_sessions(4_000, 400, SEED + 2)

    candidates = {}
    iforest = make_pipeline(StandardScaler(), IsolationForest(n_estimators=300, contamination="auto", random_state=SEED)).fit(X_train)
    candidates["isolation_forest"] = (iforest, lambda m, X: -m.score_samples(X))
    lof = make_pipeline(StandardScaler(), LocalOutlierFactor(n_neighbors=35, novelty=True)).fit(X_train)
    candidates["local_outlier_factor"] = (lof, lambda m, X: -m.score_samples(X))
    ae = AutoencoderScorer(SEED).fit(X_train)
    candidates["autoencoder"] = (ae, lambda m, X: m.score(X))

    comparison = {}
    for name, (model, scorer) in candidates.items():
        s = scorer(model, X_test)
        comparison[name] = {
            "roc_auc": round(float(roc_auc_score(y_test, s)), 4),
            "pr_auc": round(float(average_precision_score(y_test, s)), 4),
            "latency_ms_p50_single_row": round(_latency(lambda r: scorer(model, r), X_test[:1]), 3),
        }

    best = max(comparison, key=lambda k: comparison[k]["roc_auc"])
    chosen, why = best, "highest ROC-AUC on held-out normal + injected anomalous sessions"
    for name, m in comparison.items():
        if name != best and comparison[best]["roc_auc"] - m["roc_auc"] <= 0.01 and m["latency_ms_p50_single_row"] * 3 <= comparison[best]["latency_ms_p50_single_row"]:
            chosen, why = name, f"within 0.01 ROC-AUC of {best} and ≥3x faster"

    model, scorer = candidates[chosen]
    val_scores = np.sort(scorer(model, X_val))
    quantiles = np.quantile(val_scores, np.linspace(0, 1, 201)).tolist()

    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "model.joblib"
    joblib.dump({"name": chosen, "model": model}, path)
    card = {
        "name": "behavior-anomaly",
        "version": f"{chosen}-{datetime.now(timezone.utc):%Y%m%d}",
        "framework": "scikit-learn",
        "model_type": chosen.replace("_", " ").title(),
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "artifact": path.name,
        "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "dataset": {
            "source": "FraudMesh synthetic behaviour generator (behavior_sessions)",
            "train_normal_sessions": len(X_train),
            "test": {"normal": 4000, "anomalous": 400},
            "note": "Features are deviations from each customer's own baseline.",
        },
        "features": BEHAVIOR_FEATURES,
        "comparison": comparison,
        "selected": chosen,
        "selection_rationale": why,
        "metrics": comparison[chosen],
        "score_mapping": {"method": "empirical CDF of normal validation scores", "quantiles": quantiles},
        "limitations": "Synthetic baseline; anomaly ≠ fraud — used as one contributing signal in fusion.",
    }
    (OUT / "model_card.json").write_text(json.dumps(card, indent=2))
    print(json.dumps({"comparison": comparison, "selected": chosen, "why": why}, indent=2))


if __name__ == "__main__":
    main()
