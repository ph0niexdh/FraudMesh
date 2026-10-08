"""Train the network-flow anomaly model (Isolation Forest on Zeek conn metadata).

Fit on benign synthetic flows; evaluated against injected scan / exfiltration /
brute-force flow shapes. Usage: PYTHONPATH=apps/api python ml/ids/train.py
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from fraudmesh.services.ids.features import FLOW_FEATURES, flow_vector
from fraudmesh.services.simulator.datagen import normal_flows

OUT = Path(__file__).resolve().parents[1] / "artifacts" / "ids"


def attack_flows(n: int, seed: int) -> list[dict]:
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(n):
        k = rng.choice(["scan", "exfil", "bruteforce", "beacon"])
        if k == "scan":
            out.append(dict(bytes_out=0, bytes_in=0, duration=float(rng.uniform(0, 0.01)), pkts_out=1, pkts_in=int(rng.integers(0, 2)),
                            dst_port=int(rng.integers(1, 65535)), conn_state=str(rng.choice(["S0", "REJ"])), proto="tcp"))
        elif k == "exfil":
            bo = int(rng.lognormal(17.5, 0.8))
            out.append(dict(bytes_out=bo, bytes_in=int(rng.lognormal(8, 1)), duration=float(rng.uniform(20, 600)), pkts_out=int(bo / 1400),
                            pkts_in=int(rng.integers(50, 500)), dst_port=int(rng.choice([443, 8080, 4444, 22])), conn_state="SF", proto="tcp"))
        elif k == "bruteforce":
            out.append(dict(bytes_out=int(rng.integers(400, 900)), bytes_in=int(rng.integers(150, 400)), duration=float(rng.uniform(0.02, 0.2)),
                            pkts_out=int(rng.integers(4, 7)), pkts_in=int(rng.integers(3, 6)), dst_port=int(rng.choice([22, 3389, 21])),
                            conn_state=str(rng.choice(["SF", "RSTO"])), proto="tcp"))
        else:
            out.append(dict(bytes_out=int(rng.integers(200, 260)), bytes_in=int(rng.integers(0, 40)), duration=float(rng.uniform(0.0, 0.05)),
                            pkts_out=2, pkts_in=1, dst_port=int(rng.integers(1025, 65535)), conn_state="SH", proto="tcp"))
    return out


def vec(flows):
    return np.array([flow_vector(**f) for f in flows])


def main() -> None:
    X_train = vec(normal_flows(30_000, 21))
    X_val = vec(normal_flows(5_000, 22))
    X_te = np.vstack([vec(normal_flows(5_000, 23)), vec(attack_flows(500, 24))])
    y_te = np.concatenate([np.zeros(5000), np.ones(500)])
    model = make_pipeline(StandardScaler(), IsolationForest(n_estimators=200, random_state=21)).fit(X_train)
    auc = roc_auc_score(y_te, -model.score_samples(X_te))
    q = np.quantile(-model.score_samples(X_val), np.linspace(0, 1, 201)).tolist()
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "model.joblib"
    joblib.dump(model, path)
    card = {
        "name": "network-anomaly",
        "version": f"iforest-flows-{datetime.now(timezone.utc):%Y%m%d}",
        "framework": "scikit-learn",
        "model_type": "Isolation Forest (Zeek conn.log metadata)",
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "artifact": path.name,
        "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "dataset": {"source": "synthetic benign flows (datagen.normal_flows)", "train": len(X_train),
                    "test": {"benign": 5000, "attack_shapes": 500, "attack_kinds": ["scan", "exfil", "bruteforce", "beacon"]}},
        "features": FLOW_FEATURES,
        "metrics": {"roc_auc": round(float(auc), 4)},
        "score_mapping": {"method": "empirical CDF of benign validation scores", "quantiles": q},
        "limitations": "Metadata-only (no payload); synthetic benign baseline.",
    }
    (OUT / "model_card.json").write_text(json.dumps(card, indent=2))
    print(json.dumps(card["metrics"]))


if __name__ == "__main__":
    main()
