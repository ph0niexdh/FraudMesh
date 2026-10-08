"""Transaction fraud detector (trained GBDT + isotonic calibration + SHAP)."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import warnings

import numpy as np

from fraudmesh.config import get_settings
from fraudmesh.detection.base import BaseDetector, DetectorResult, DetectorStatus, Reason
from fraudmesh.services.metrics.telemetry import telemetry
from fraudmesh.services.transaction.features import FEATURE_NAMES, LABELS, encode_raw, to_frame

# Context keys that, when absent, were defaulted (reduces confidence)
_CONTEXT_KEYS = ["amount_deviation", "velocity_24h", "device_age_days", "ip_risk", "geo_distance_km", "account_age_days",
                 "secs_since_login", "beneficiary_inbound_senders", "graph_risk"]


class TransactionDetector(BaseDetector):
    name = "transaction-model"
    domain = "transaction"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = False
        self.error: str | None = None
        self.card: dict = {}
        self.booster = None
        self.explainer = None
        self.last_inference_at: float | None = None

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            d = get_settings().artifact_dir / "transaction"
            try:
                self.card = json.loads((d / "model_card.json").read_text())
                path = d / self.card["artifact"]
                if hashlib.sha256(path.read_bytes()).hexdigest() != self.card["artifact_sha256"]:
                    raise ValueError("model artifact checksum mismatch")
                cal = json.loads((d / "calibration.json").read_text())
                self._cal_x, self._cal_y = np.array(cal["x"]), np.array(cal["y"])
                import shap

                if self.card["framework"] == "lightgbm":
                    import lightgbm as lgb

                    self.booster = lgb.Booster(model_file=str(path))
                    self._predict = lambda X: self.booster.predict(X)
                else:
                    import xgboost as xgb

                    self.booster = xgb.Booster()
                    self.booster.load_model(str(path))
                    self._predict = lambda X: self.booster.predict(xgb.DMatrix(X, enable_categorical=True))
                self.explainer = shap.TreeExplainer(self.booster)
            except Exception as exc:
                self.error = f"{type(exc).__name__}: {exc}"
            self._loaded = True

    @property
    def model_version(self) -> str:
        self._load()
        return self.card.get("version", "unavailable")

    def status(self) -> DetectorStatus:
        self._load()
        return DetectorStatus(
            name=self.name, domain=self.domain, status="ONLINE" if self.booster is not None else "OFFLINE",
            model_version=self.model_version, model_type=self.card.get("model_type", ""), detail=self.error or "",
        )

    def calibrate(self, p: np.ndarray) -> np.ndarray:
        return np.interp(p, self._cal_x, self._cal_y)

    def predict_raw(self, raw: dict) -> tuple[float, float, dict]:
        """(raw model probability, calibrated probability, encoded features)"""
        self._load()
        if self.booster is None:
            raise RuntimeError(self.error or "transaction model offline")
        enc = encode_raw(raw)
        X = to_frame([enc])
        p_raw = float(self._predict(X)[0])
        return p_raw, float(self.calibrate(np.array([p_raw]))[0]), enc

    def explain(self, raw: dict, top: int = 8) -> list[dict]:
        self._load()
        enc = encode_raw(raw)
        X = to_frame([enc])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            sv = self.explainer.shap_values(X)
        sv = sv[1] if isinstance(sv, list) else sv
        vals = np.asarray(sv)[0]
        # merge the two cyclic time-of-day components into one human feature
        merged: dict[str, float] = {}
        for name, v in zip(FEATURE_NAMES, vals):
            key = "hour" if name in ("hour_sin", "hour_cos") else name
            merged[key] = merged.get(key, 0.0) + float(v)
        display_values = {**raw, "hour": raw.get("hour")}
        rows = []
        for key, v in sorted(merged.items(), key=lambda kv: -abs(kv[1]))[:top]:
            rows.append({
                "feature": key,
                "label": "Time of day" if key == "hour" else LABELS.get(key, key),
                "value": display_values.get(key, enc.get(key)),
                "shap": round(v, 4),
                "direction": "increases risk" if v > 0 else "decreases risk",
            })
        base = self.explainer.expected_value
        base = float(base[1] if isinstance(base, (list, np.ndarray)) and np.size(base) > 1 else base)
        return [{"base_value_logodds": round(base, 4)}] + rows

    def score(self, raw: dict) -> DetectorResult:
        t = time.perf_counter()
        p_raw, p, _ = self.predict_raw(raw)
        shap_rows = self.explain(raw)
        top = shap_rows[1:]
        coverage = sum(1 for k in _CONTEXT_KEYS if k in raw) / len(_CONTEXT_KEYS)
        decisiveness = abs(p - 0.5) * 2
        confidence = float(np.clip(0.5 * decisiveness + 0.5 * coverage, 0.05, 0.99))
        reasons = [
            Reason(code=f"TXN_{r['feature'].upper()}", message=f"{r['label']}: {r['direction']}", weight=r["shap"])
            for r in top
            if r["shap"] > 0.05 and p >= 0.2  # low scores: no "risk factors" to report
        ][:5]
        ms = (time.perf_counter() - t) * 1000
        telemetry.observe_inference(self.name, ms)
        self.last_inference_at = time.time()
        return DetectorResult(
            detector=self.name, domain=self.domain, risk_score=round(100 * p, 2), confidence=confidence,
            reason_codes=reasons, model_version=self.model_version, latency_ms=ms,
            metadata={"fraud_probability": round(p, 4), "raw_probability": round(p_raw, 4), "shap": shap_rows,
                      "feature_coverage": round(coverage, 2)},
        )


transaction_detector = TransactionDetector()
