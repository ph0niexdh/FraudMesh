"""Train the transaction fraud model.

Compares LightGBM and XGBoost on the same synthetic dataset and split, then keeps
the better one by PR-AUC (the right metric under ~5% prevalence), using single-row
inference latency as the tie-breaker (within 0.005 PR-AUC). Probabilities are
calibrated with isotonic regression on a held-out calibration split.

Artifacts → ml/artifacts/transaction/:
  model.txt | model.json   booster
  calibration.json         isotonic mapping
  model_card.json          data, features, metrics, comparison, selection rationale

Usage:  PYTHONPATH=apps/api python ml/transaction/train.py [--rows 80000] [--seed 7]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import lightgbm as lgb
import numpy as np
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

from fraudmesh.services.simulator import datagen
from fraudmesh.services.transaction.features import FEATURE_NAMES, FEATURES, encode_raw, to_frame

OUT = Path(__file__).resolve().parents[1] / "artifacts" / "transaction"


def recall_at_fpr(y, p, fpr_target=0.01) -> float:
    fpr, tpr, _ = roc_curve(y, p)
    return float(np.interp(fpr_target, fpr, tpr))


def latency_ms(predict, row, n=300) -> float:
    predict(row)
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        predict(row)
        ts.append((time.perf_counter() - t) * 1000)
    return float(np.percentile(ts, 50))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=80_000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    raw, y, segs = datagen.transactions(args.rows, args.seed)
    X = to_frame([encode_raw(r) for r in raw])
    segs = np.array(segs)
    idx = np.arange(len(y))
    tr, rest = train_test_split(idx, test_size=0.4, stratify=y, random_state=args.seed)
    cal, te = train_test_split(rest, test_size=0.5, stratify=y[rest], random_state=args.seed)

    results = {}

    # ---------------- LightGBM
    t = time.perf_counter()
    lgbm = lgb.LGBMClassifier(
        n_estimators=600, learning_rate=0.04, num_leaves=31, min_child_samples=40, subsample=0.8, subsample_freq=1,
        colsample_bytree=0.8, reg_lambda=1.0, random_state=args.seed, verbose=-1,
    )
    lgbm.fit(X.iloc[tr], y[tr], eval_set=[(X.iloc[cal], y[cal])], callbacks=[lgb.early_stopping(50, verbose=False)])
    lgb_time = time.perf_counter() - t
    p_lgb = lgbm.predict_proba(X.iloc[te])[:, 1]
    results["lightgbm"] = {
        "roc_auc": roc_auc_score(y[te], p_lgb),
        "pr_auc": average_precision_score(y[te], p_lgb),
        "recall_at_1pct_fpr": recall_at_fpr(y[te], p_lgb),
        "train_seconds": lgb_time,
        "best_iteration": int(lgbm.best_iteration_ or lgbm.n_estimators),
        "latency_ms_p50_single_row": latency_ms(lambda r: lgbm.booster_.predict(r), X.iloc[te[:1]]),
    }

    # ---------------- XGBoost
    t = time.perf_counter()
    xgbm = xgb.XGBClassifier(
        n_estimators=600, learning_rate=0.05, max_depth=6, subsample=0.8, colsample_bytree=0.8, reg_lambda=1.0,
        tree_method="hist", enable_categorical=True, random_state=args.seed, early_stopping_rounds=50, eval_metric="aucpr",
    )
    xgbm.fit(X.iloc[tr], y[tr], eval_set=[(X.iloc[cal], y[cal])], verbose=False)
    xgb_time = time.perf_counter() - t
    p_xgb = xgbm.predict_proba(X.iloc[te])[:, 1]
    results["xgboost"] = {
        "roc_auc": roc_auc_score(y[te], p_xgb),
        "pr_auc": average_precision_score(y[te], p_xgb),
        "recall_at_1pct_fpr": recall_at_fpr(y[te], p_xgb),
        "train_seconds": xgb_time,
        "best_iteration": int(xgbm.best_iteration),
        "latency_ms_p50_single_row": latency_ms(lambda r: xgbm.predict_proba(r), X.iloc[te[:1]]),
    }

    a, b = results["lightgbm"], results["xgboost"]
    if abs(a["pr_auc"] - b["pr_auc"]) <= 0.005:
        chosen = "lightgbm" if a["latency_ms_p50_single_row"] <= b["latency_ms_p50_single_row"] else "xgboost"
        why = "PR-AUC within 0.005; chose the lower single-row latency"
    else:
        chosen = "lightgbm" if a["pr_auc"] > b["pr_auc"] else "xgboost"
        why = "higher PR-AUC on the held-out test split"

    OUT.mkdir(parents=True, exist_ok=True)
    for f in OUT.glob("model.*"):
        f.unlink()
    if chosen == "lightgbm":
        p_cal_raw = lgbm.booster_.predict(X.iloc[cal])
        p_te_raw = lgbm.booster_.predict(X.iloc[te])
        lgbm.booster_.save_model(str(OUT / "model.txt"), num_iteration=lgbm.best_iteration_)
        artifact = OUT / "model.txt"
    else:
        p_cal_raw = xgbm.predict_proba(X.iloc[cal])[:, 1]
        p_te_raw = p_xgb
        xgbm.get_booster().save_model(str(OUT / "model.json"))
        artifact = OUT / "model.json"

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p_cal_raw, y[cal])
    p_te_cal = iso.predict(p_te_raw)
    (OUT / "calibration.json").write_text(json.dumps({"x": iso.X_thresholds_.tolist(), "y": iso.y_thresholds_.tolist()}))

    # per-segment detection rate at the HOLD threshold (calibrated p >= 0.65)
    seg_report = {}
    for s in sorted(set(segs[te])):
        m = segs[te] == s
        seg_report[s] = {"n": int(m.sum()), "flag_rate_at_0.65": round(float((p_te_cal[m] >= 0.65).mean()), 3)}

    card = {
        "name": "transaction-fraud",
        "version": f"{chosen}-{datetime.now(timezone.utc):%Y%m%d}",
        "framework": chosen,
        "model_type": "Gradient-boosted decision trees (binary classification)",
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "artifact": artifact.name,
        "artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "dataset": {
            "source": "FraudMesh synthetic generator (apps/api/fraudmesh/services/simulator/datagen.py)",
            "rows": int(len(y)),
            "fraud_rate": round(float(y.mean()), 4),
            "seed": args.seed,
            "segments": {k: {"weight": v[0], "fraud": bool(v[1])} for k, v in datagen.TXN_SEGMENTS.items()},
            "label_noise": 0.005,
            "splits": {"train": int(len(tr)), "calibration": int(len(cal)), "test": int(len(te))},
        },
        "features": [{"name": f.name, "description": f.description, "kind": f.kind} for f in FEATURES],
        "comparison": {k: {m: round(float(v), 4) if isinstance(v, float) else v for m, v in r.items()} for k, r in results.items()},
        "selected": chosen,
        "selection_rationale": why,
        "metrics": {
            "roc_auc": round(float(roc_auc_score(y[te], p_te_cal)), 4),
            "pr_auc": round(float(average_precision_score(y[te], p_te_cal)), 4),
            "recall_at_1pct_fpr": round(recall_at_fpr(y[te], p_te_cal), 4),
            "brier": round(float(np.mean((p_te_cal - y[te]) ** 2)), 5),
        },
        "segment_report": seg_report,
        "explainability": "SHAP TreeExplainer (exact, tree_path_dependent) on the raw booster margin",
        "limitations": "Trained on synthetic data only; metrics describe separability of the simulator, not real-world performance.",
        "feature_order": FEATURE_NAMES,
    }
    (OUT / "model_card.json").write_text(json.dumps(card, indent=2))
    print(json.dumps({"comparison": card["comparison"], "selected": chosen, "why": why, "metrics": card["metrics"], "segments": seg_report}, indent=2))


if __name__ == "__main__":
    main()
