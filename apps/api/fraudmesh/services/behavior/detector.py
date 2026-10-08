"""Behavioural anomaly detector (trained unsupervised model, customer-relative features)."""

from __future__ import annotations

import hashlib
import json
import threading
import time

import joblib
import numpy as np

from fraudmesh.config import get_settings
from fraudmesh.detection.base import BaseDetector, DetectorResult, DetectorStatus, Reason
from fraudmesh.services.metrics.telemetry import telemetry
from fraudmesh.services.simulator.datagen import BEHAVIOR_FEATURES

FEATURE_LABELS = {
    "login_hour_deviation": "Login time unusual for this customer",
    "txn_frequency_ratio": "Transaction frequency vs normal",
    "amount_deviation": "Amount vs customer history",
    "location_deviation_km": "Location far from usual",
    "device_change": "Device changed",
    "ip_change": "Network/IP changed",
    "session_duration_ratio": "Session duration vs normal",
    "navigation_speed_ratio": "Navigation speed vs normal (scripted / remote access)",
    "failed_logins": "Failed logins before success",
    "days_since_last_login": "Dormant account reactivated",
}


class BehaviorDetector(BaseDetector):
    name = "behavior-model"
    domain = "behavior"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loaded = False
        self.error: str | None = None
        self.card: dict = {}
        self.model = None
        self.kind = ""

    def _load(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            d = get_settings().artifact_dir / "behavior"
            try:
                self.card = json.loads((d / "model_card.json").read_text())
                path = d / self.card["artifact"]
                # Verify before unpickling: only our own committed artifact is ever loaded.
                if hashlib.sha256(path.read_bytes()).hexdigest() != self.card["artifact_sha256"]:
                    raise ValueError("model artifact checksum mismatch")
                obj = joblib.load(path)
                self.model, self.kind = obj["model"], obj["name"]
                self._q = np.array(self.card["score_mapping"]["quantiles"])
            except Exception as exc:
                self.error = f"{type(exc).__name__}: {exc}"
            self._loaded = True

    @property
    def model_version(self) -> str:
        self._load()
        return self.card.get("version", "unavailable")

    def status(self) -> DetectorStatus:
        self._load()
        return DetectorStatus(self.name, self.domain, "ONLINE" if self.model is not None else "OFFLINE",
                              self.model_version, self.card.get("model_type", ""), self.error or "")

    def _raw_score(self, X: np.ndarray) -> np.ndarray:
        if self.kind == "autoencoder":
            return self.model.score(X)
        return -self.model.score_samples(X)

    def score(self, features: dict) -> DetectorResult:
        self._load()
        if self.model is None:
            raise RuntimeError(self.error or "behavior model offline")
        t = time.perf_counter()
        x = np.array([[float(features.get(f, 0.0)) for f in BEHAVIOR_FEATURES]])
        raw = float(self._raw_score(x)[0])
        # empirical CDF against normal sessions → "more unusual than X% of normal sessions"
        pct = float(np.searchsorted(self._q, raw) / len(self._q))
        # stretch the top tail: 95th pct → ~50 risk, 99.5th → ~90
        risk = float(np.clip((pct - 0.80) / 0.20, 0, 1) ** 1.5 * 100)
        reasons: list[Reason] = []
        if self.kind == "autoencoder":
            err = self.model.feature_errors(x)[0]
            share = err / (err.sum() + 1e-9)
            for i in np.argsort(-err)[:4]:
                if share[i] >= 0.12 and err[i] > 1.0:
                    f = BEHAVIOR_FEATURES[i]
                    reasons.append(Reason(code=f"BEH_{f.upper()}", message=FEATURE_LABELS[f], weight=round(float(share[i]), 3)))
        ms = (time.perf_counter() - t) * 1000
        telemetry.observe_inference(self.name, ms)
        provided = sum(1 for f in BEHAVIOR_FEATURES if f in features) / len(BEHAVIOR_FEATURES)
        return DetectorResult(
            detector=self.name, domain=self.domain, risk_score=round(risk, 2),
            confidence=float(np.clip(0.4 + 0.6 * provided, 0, 0.95)), reason_codes=reasons,
            model_version=self.model_version, latency_ms=ms,
            metadata={"anomaly_score": round(pct, 4), "raw_score": round(raw, 4), "features": {f: round(float(v), 3) for f, v in zip(BEHAVIOR_FEATURES, x[0])}},
        )


behavior_detector = BehaviorDetector()
