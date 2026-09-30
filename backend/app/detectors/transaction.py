"""Transaction detector — XGBoost classifier over behavioural features.

The model is trained at start-up on a *deterministic synthetic* dataset (and,
after analyst feedback, on analyst-labelled examples). It is a prototype,
not a production-grade fraud model. Per-prediction explanations use exact
TreeSHAP values: the ``shap`` library when available, otherwise XGBoost's
native ``pred_contribs`` (also TreeSHAP). No explanation values are invented.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import numpy as np
import xgboost as xgb
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from app.detectors.base import DetectorStats, Timer, clamp01, make_result
from app.schemas.events import DetectorResult, NormalizedEvent
from app.services.profiles import CustomerProfile
from app.utils.geo import coords_for, haversine_km
from app.utils.logging import get_logger
from app.utils.timeutil import utcnow, iso

log = get_logger(__name__)

FEATURES = [
    "amount_ratio",          # amount / customer baseline mean
    "velocity_1h",           # transactions by this customer in the last hour
    "beneficiary_new",       # 1 if beneficiary never paid before
    "merchant_new",          # 1 if merchant never used before
    "hour_deviation",        # circular distance from usual hour, 0..1
    "geo_km",                # distance from home city (km)
    "device_new",            # 1 if device not in customer's trusted set
    "frequency_ratio",       # txns in last 24h relative to customer's daily average
    "amount_rarity",         # 1 - share of historical amounts within ±25% of this amount
]

FEATURE_LABELS = {
    "amount_ratio": "Amount deviation from baseline",
    "velocity_1h": "Transaction velocity (1h)",
    "beneficiary_new": "New beneficiary",
    "merchant_new": "New merchant",
    "hour_deviation": "Time-of-day deviation",
    "geo_km": "Geographic deviation",
    "device_new": "Device novelty",
    "frequency_ratio": "Transaction frequency",
    "amount_rarity": "Amount rarity",
}

# rule thresholds that turn features into named, human-readable signals
SIGNAL_RULES = [
    ("amount_deviation", "amount_ratio", 2.5),
    ("new_beneficiary", "beneficiary_new", 0.5),
    ("velocity_spike", "velocity_1h", 3),
    ("new_merchant", "merchant_new", 0.5),
    ("unusual_hour", "hour_deviation", 0.45),
    ("geo_deviation", "geo_km", 300),
    ("new_device", "device_new", 0.5),
    ("frequency_spike", "frequency_ratio", 3.0),
    ("rare_amount", "amount_rarity", 0.85),
]

SEED = 42


def synthetic_training_data(n: int = 8000, fraud_rate: float = 0.12, seed: int = SEED) -> tuple[np.ndarray, np.ndarray]:
    """Deterministic synthetic dataset with overlapping legit/fraud distributions."""
    rng = np.random.default_rng(seed)
    n_f = int(n * fraud_rate)
    n_l = n - n_f

    def block(size: int, fraud: bool) -> np.ndarray:
        if not fraud:
            cols = [
                rng.lognormal(0.0, 0.38, size),
                rng.poisson(0.35, size),
                rng.binomial(1, 0.10, size),
                rng.binomial(1, 0.22, size),
                np.clip(np.abs(rng.normal(0, 2.4, size)) / 12, 0, 1),
                np.clip(rng.exponential(18, size), 0, 5000),
                rng.binomial(1, 0.05, size),
                rng.gamma(2.0, 0.5, size),
                rng.beta(3, 3, size),
            ]
        else:
            far = rng.random(size) < 0.45
            cols = [
                rng.lognormal(1.2, 0.65, size),
                rng.poisson(2.2, size),
                rng.binomial(1, 0.78, size),
                rng.binomial(1, 0.50, size),
                rng.uniform(0, 1, size),
                np.where(far, rng.uniform(250, 3500, size), np.clip(rng.exponential(25, size), 0, 5000)),
                rng.binomial(1, 0.55, size),
                rng.gamma(3.0, 1.1, size),
                rng.beta(8, 1.5, size),
            ]
        return np.column_stack(cols).astype(float)

    X = np.vstack([block(n_l, False), block(n_f, True)])
    y = np.concatenate([np.zeros(n_l), np.ones(n_f)])
    flip = rng.random(len(y)) < 0.02  # label noise so the task is not trivially separable
    y = np.where(flip, 1 - y, y)
    order = rng.permutation(len(y))
    return X[order], y[order].astype(int)


class TransactionDetector:
    name = "transaction_xgboost"
    channel = "transaction"

    def __init__(self, models_dir: Path) -> None:
        self.models_dir = models_dir
        self.model: xgb.XGBClassifier | None = None
        self.version = "0"
        self.trained_at: str | None = None
        self.training_samples = 0
        self.feedback_samples = 0
        self.evaluation: dict[str, Any] = {}
        self.stats = DetectorStats(self.name)
        self._explainer: Any = None
        self.explainer_kind = "none"

    # ------------------------------------------------------------------ training
    def train(self, extra_X: np.ndarray | None = None, extra_y: np.ndarray | None = None) -> None:
        X, y = synthetic_training_data()
        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, random_state=SEED, stratify=y)
        weights = np.ones(len(y_tr))
        if extra_X is not None and extra_y is not None and len(extra_y) > 0:
            X_tr = np.vstack([X_tr, extra_X])
            y_tr = np.concatenate([y_tr, extra_y])
            weights = np.concatenate([weights, np.full(len(extra_y), 5.0)])
            self.feedback_samples = int(len(extra_y))
        model = xgb.XGBClassifier(
            n_estimators=160, max_depth=4, learning_rate=0.08, subsample=0.9, colsample_bytree=0.9,
            random_state=SEED, n_jobs=1, eval_metric="logloss", tree_method="hist",
        )
        model.fit(X_tr, y_tr, sample_weight=weights)
        self.model = model
        self.training_samples = int(len(y_tr))
        prob = model.predict_proba(X_te)[:, 1]
        pred = (prob >= 0.5).astype(int)
        fp = int(((pred == 1) & (y_te == 0)).sum())
        tn = int(((pred == 0) & (y_te == 0)).sum())
        self.evaluation = {
            "dataset": "synthetic hold-out (25%, deterministic seed) — not real bank data",
            "threshold": 0.5,
            "samples": int(len(y_te)),
            "precision": round(float(precision_score(y_te, pred)), 4),
            "recall": round(float(recall_score(y_te, pred)), 4),
            "f1": round(float(f1_score(y_te, pred)), 4),
            "pr_auc": round(float(average_precision_score(y_te, prob)), 4),
            "roc_auc": round(float(roc_auc_score(y_te, prob)), 4),
            "false_positive_rate": round(fp / max(1, fp + tn), 4),
        }
        prior = int(self.version) if self.version.isdigit() else 0
        self.version = str(prior + 1)
        self.trained_at = iso(utcnow())
        self._build_explainer()
        self._save()
        log.info("transaction model v%s trained on %d samples (%d analyst-labelled)",
                 self.version, self.training_samples, self.feedback_samples)

    def _build_explainer(self) -> None:
        self._explainer = None
        try:
            import shap  # noqa: WPS433

            self._explainer = shap.TreeExplainer(self.model)
            self.explainer_kind = "shap.TreeExplainer"
        except Exception as err:  # pragma: no cover - depends on environment
            log.warning("SHAP unavailable (%s); using XGBoost native TreeSHAP contributions", type(err).__name__)
            self.explainer_kind = "xgboost.pred_contribs (TreeSHAP)"

    def _save(self) -> None:
        """Persist as XGBoost JSON (no pickle) with a SHA-256 manifest for integrity."""
        assert self.model is not None
        path = self.models_dir / "transaction_xgb.json"
        self.model.save_model(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.models_dir / "transaction_xgb.manifest").write_text(
            json.dumps({"sha256": digest, "version": self.version, "features": FEATURES})
        )

    @property
    def version_label(self) -> str:
        return f"xgb-synthetic-v{self.version}"

    # ---------------------------------------------------------------- features
    @staticmethod
    def build_features(event: NormalizedEvent, prof: CustomerProfile | None) -> dict[str, float]:
        md = event.metadata
        now = event.timestamp
        if prof is None:
            return {f: 0.0 for f in FEATURES} | {"amount_ratio": 1.0, "device_new": 1.0}
        mean = prof.amount_mean or event.amount
        amount_ratio = event.amount / mean if mean > 0 else 1.0
        velocity = prof.count_since(prof.txn_times, now, timedelta(hours=1))
        ben = md.get("beneficiary_token")
        beneficiary_new = 1.0 if ben and ben not in prof.beneficiaries else 0.0
        merchant = md.get("merchant")
        merchant_new = 1.0 if merchant and merchant not in prof.merchants else 0.0
        usual = prof.usual_hour
        if usual is None:
            hour_dev = 0.0
        else:
            diff = abs(now.hour + now.minute / 60 - usual)
            hour_dev = min(diff, 24 - diff) / 12
        geo = haversine_km(coords_for(prof.home_city), coords_for(md.get("city"))) if prof.home_city else 0.0
        device_new = 1.0 if event.device_token and event.device_token not in prof.devices else 0.0
        day_count = prof.count_since(prof.txn_times, now, timedelta(hours=24)) + 1
        span_days = 30.0
        daily_avg = max(1.0, len(prof.txn_times) / span_days)
        frequency_ratio = day_count / daily_avg
        if len(prof.amounts) >= 5:
            arr = np.asarray(prof.amounts)
            near = np.mean(np.abs(arr - event.amount) <= 0.25 * max(event.amount, 1.0))
            amount_rarity = 1.0 - float(near)
        else:
            amount_rarity = 0.5
        return {
            "amount_ratio": round(float(amount_ratio), 4),
            "velocity_1h": float(velocity),
            "beneficiary_new": beneficiary_new,
            "merchant_new": merchant_new,
            "hour_deviation": round(float(hour_dev), 4),
            "geo_km": round(float(geo), 1),
            "device_new": device_new,
            "frequency_ratio": round(float(frequency_ratio), 4),
            "amount_rarity": round(float(amount_rarity), 4),
        }

    # --------------------------------------------------------------- inference
    def _contributions(self, x: np.ndarray) -> list[float] | None:
        assert self.model is not None
        try:
            if self._explainer is not None:
                vals = self._explainer.shap_values(x)
                vals = np.asarray(vals)
                return [float(v) for v in vals.reshape(-1)[: len(FEATURES)]]
            contribs = self.model.get_booster().predict(xgb.DMatrix(x, feature_names=None), pred_contribs=True)
            return [float(v) for v in contribs[0][: len(FEATURES)]]
        except Exception as err:  # pragma: no cover
            log.warning("explanation failed: %s", type(err).__name__)
            return None

    def detect(self, event: NormalizedEvent, prof: CustomerProfile | None) -> DetectorResult:
        assert self.model is not None, "model not trained"
        with Timer() as t:
            feats = self.build_features(event, prof)
            x = np.asarray([[feats[f] for f in FEATURES]], dtype=float)
            prob = float(self.model.predict_proba(x)[0, 1])
            contribs = self._contributions(x)
            signal_details: list[dict[str, Any]] = []
            shap_map = dict(zip(FEATURES, contribs)) if contribs else {}
            for name, feat, thr in SIGNAL_RULES:
                if feats[feat] >= thr:
                    signal_details.append({
                        "name": name,
                        "label": FEATURE_LABELS[feat],
                        "feature": feat,
                        "value": feats[feat],
                        # weight used for ranking: the SHAP contribution (log-odds) when positive
                        "weight": round(max(shap_map.get(feat, 0.0), 0.0), 4) if shap_map else 0.1,
                    })
            history = len(prof.amounts) if prof else 0
            confidence = (0.45 + 0.55 * min(1.0, history / 25)) * (0.6 + 0.4 * abs(2 * prob - 1))
            details: dict[str, Any] = {
                "features": feats,
                "probability": round(prob, 4),
                "baseline_mean": round(prof.amount_mean, 2) if prof else None,
                "amount": event.amount,
                "explainer": self.explainer_kind,
            }
            if contribs:
                details["shap_values"] = {f: round(v, 4) for f, v in shap_map.items()}
                details["shap_base_value"] = self._base_value()
        self.stats.record(t.ms)
        return make_result(
            detector=self.name, channel=self.channel, score=prob, confidence=clamp01(confidence),
            signal_details=signal_details, model_version=self.version_label, details=details, latency_ms=t.ms,
        )

    def _base_value(self) -> float | None:
        try:
            if self._explainer is not None:
                ev = np.asarray(self._explainer.expected_value).reshape(-1)
                return round(float(ev[0]), 4)
        except Exception:  # pragma: no cover
            return None
        return None
