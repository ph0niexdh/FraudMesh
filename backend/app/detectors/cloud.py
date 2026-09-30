"""Cloud-security anomaly detector — Isolation Forest + transparent rules.

``cloud_risk_score = clamp(sum(rule points) + 0.25 * isolation_forest_anomaly)``
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from app.detectors.base import DetectorStats, Timer, clamp01, make_result
from app.schemas.events import DetectorResult, NormalizedEvent
from app.services.profiles import PrincipalProfile
from app.utils.timeutil import iso, utcnow

PRIVILEGED_ACTIONS = {
    "PRIVILEGED_API_CALL", "iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy", "kms:Decrypt", "kms:DisableKey", "secretsmanager:GetSecretValue",
    "sts:AssumeRole", "payments:UpdateLimits", "cloudtrail:StopLogging",
}
ESCALATION_ACTIONS = {"iam:AttachRolePolicy", "iam:PutUserPolicy", "iam:UpdateAssumeRolePolicy"}

FEATURES = ["privileged", "new_access_key", "region_unusual", "calls_per_min_log", "resource_created",
            "privilege_escalation", "auth_failures", "hour_deviation"]

RULES: dict[str, tuple[float, str]] = {
    "privileged_api_call": (0.30, "Unusual privileged API call"),
    "privilege_escalation": (0.22, "Privilege-escalation-like activity"),
    "new_access_key": (0.15, "New access key created / first use"),
    "unusual_region": (0.15, "API call from an unusual cloud region"),
    "api_burst": (0.12, "Abnormal API-call burst"),
    "suspicious_resource_creation": (0.10, "Suspicious resource creation"),
    "auth_anomaly": (0.10, "Unusual authentication pattern"),
    "logging_tampering": (0.25, "Audit logging disabled"),
}


def synthetic_normal_cloud(n: int = 2500, seed: int = 11) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return np.column_stack([
        rng.binomial(1, 0.04, n),
        rng.binomial(1, 0.01, n),
        rng.binomial(1, 0.03, n),
        np.log1p(rng.gamma(2.0, 6.0, n)),
        rng.binomial(1, 0.08, n),
        rng.binomial(1, 0.005, n),
        rng.poisson(0.1, n),
        np.clip(np.abs(rng.normal(0, 2.5, n)) / 12, 0, 1),
    ]).astype(float)


class CloudDetector:
    name = "cloud_anomaly"
    channel = "cloud"
    version_label = "iforest-synthetic-v1+rules-v1"

    def __init__(self) -> None:
        self.model: IsolationForest | None = None
        self.stats = DetectorStats(self.name)
        self.trained_at: str | None = None
        self._lo, self._hi = 0.0, 1.0

    def train(self) -> None:
        X = synthetic_normal_cloud()
        self.model = IsolationForest(n_estimators=150, contamination="auto", random_state=11).fit(X)
        raw = -self.model.score_samples(X)
        self._lo, self._hi = float(np.percentile(raw, 50)), float(np.percentile(raw, 99.5))
        self.trained_at = iso(utcnow())

    def detect(self, event: NormalizedEvent, prof: PrincipalProfile | None) -> DetectorResult:
        assert self.model is not None
        with Timer() as t:
            md = event.metadata
            action = str(md.get("action", ""))
            region = md.get("region")
            privileged = bool(md.get("privileged")) or action in PRIVILEGED_ACTIONS
            escalation = action in ESCALATION_ACTIONS or bool(md.get("privilege_escalation"))
            new_key = bool(md.get("new_access_key")) or action == "iam:CreateAccessKey"
            known_regions = prof.regions if prof else set()
            region_unusual = bool(region) and bool(known_regions) and region not in known_regions
            if prof is not None and not known_regions and region and region != "ap-south-1":
                region_unusual = True
            calls = float(md.get("api_calls_per_min", 0) or 0)
            if prof is not None:
                calls = max(calls, float(sum(1 for c in prof.call_times if event.timestamp - timedelta(minutes=1) <= c <= event.timestamp)))
            resource_created = bool(md.get("resource_created"))
            auth_failures = float(md.get("auth_failures", 0) or 0)
            hour_dev = 0.0
            if prof is not None and prof.hours:
                usual = float(np.median(prof.hours))
                diff = abs(event.timestamp.hour - usual)
                hour_dev = min(diff, 24 - diff) / 12
            feats = {
                "privileged": float(privileged),
                "new_access_key": float(new_key),
                "region_unusual": float(region_unusual),
                "calls_per_min_log": round(float(np.log1p(calls)), 4),
                "resource_created": float(resource_created),
                "privilege_escalation": float(escalation),
                "auth_failures": auth_failures,
                "hour_deviation": round(hour_dev, 4),
            }
            x = np.asarray([[feats[f] for f in FEATURES]])
            raw = float(-self.model.score_samples(x)[0])
            anomaly = clamp01((raw - self._lo) / max(1e-6, self._hi - self._lo))

            fired: list[str] = []
            if privileged and (prof is None or action not in prof.actions):
                fired.append("privileged_api_call")
            if escalation:
                fired.append("privilege_escalation")
            if new_key:
                fired.append("new_access_key")
            if region_unusual:
                fired.append("unusual_region")
            if calls >= 60:
                fired.append("api_burst")
            if resource_created and (privileged or region_unusual):
                fired.append("suspicious_resource_creation")
            if auth_failures >= 3 or md.get("mfa_used") is False:
                fired.append("auth_anomaly")
            if action == "cloudtrail:StopLogging":
                fired.append("logging_tampering")
            points = sum(RULES[s][0] for s in fired)
            score = clamp01(points + 0.25 * anomaly)
            signal_details: list[dict[str, Any]] = [
                {"name": s, "label": RULES[s][1], "weight": RULES[s][0], "points": round(RULES[s][0] * 100)}
                for s in fired
            ]
            history = prof.history_events if prof else 0
            confidence = 0.5 + 0.3 * min(1.0, history / 10) + 0.2 * min(1.0, len(fired) / 2)
        self.stats.record(t.ms)
        return make_result(
            detector=self.name, channel=self.channel, score=score, confidence=confidence,
            signal_details=signal_details, model_version=self.version_label, latency_ms=t.ms,
            details={"features": feats, "anomaly_score": round(anomaly, 4), "cloud_risk_score": round(score, 4),
                     "cloud_signals": fired, "action": action, "region": region},
        )
