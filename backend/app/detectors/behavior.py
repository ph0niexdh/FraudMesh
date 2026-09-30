"""Behavioural / account-takeover detector.

Two transparent components:

1. **Isolation Forest** over per-login features, trained at start-up on
   deterministic synthetic *normal* sessions → ``behavior_score`` (0..1).
2. **Deterministic takeover rules**, accumulated over the customer's session
   inside the temporal window (each rule counts once) → rule points.

``takeover_score = clamp(sum(rule points) + 0.2 * behavior_score)``.
Rule weights are demo configuration values, not calibrated probabilities.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from app.detectors.base import DetectorStats, Timer, clamp01, make_result
from app.schemas.events import DetectorResult, EventType, NormalizedEvent
from app.services.profiles import CustomerProfile
from app.utils.geo import coords_for, haversine_km
from app.utils.timeutil import iso, utcnow

FEATURES = [
    "hour_deviation", "device_new", "ip_new", "travel_speed_kmh_log", "logins_10m",
    "device_switches_1h", "ip_switches_1h", "mfa_reset", "failed_attempts", "credential_change",
]

RULES: dict[str, tuple[float, str]] = {
    "new_device": (0.18, "Login from a device never seen for this customer"),
    "device_change": (0.10, "New device registered on the account"),
    "new_ip": (0.12, "Login from a new IP / network"),
    "mfa_reset": (0.15, "MFA factor reset"),
    "impossible_travel": (0.15, "Impossible-travel-like location change"),
    "unusual_login_time": (0.06, "Login at an unusual time of day"),
    "login_burst": (0.10, "Burst of logins in a short period"),
    "device_switching": (0.08, "Multiple devices used within an hour"),
    "ip_switching": (0.06, "Multiple IPs used within an hour"),
    "abnormal_session": (0.08, "Abnormal session behaviour (failed attempts / credential change)"),
}


def synthetic_normal_sessions(n: int = 3000, seed: int = 7) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return np.column_stack([
        np.clip(np.abs(rng.normal(0, 1.8, n)) / 12, 0, 1),
        rng.binomial(1, 0.04, n),
        rng.binomial(1, 0.12, n),
        np.log1p(np.clip(rng.exponential(8, n), 0, 200)),
        rng.poisson(0.3, n),
        rng.binomial(1, 0.03, n),
        rng.binomial(1, 0.10, n),
        rng.binomial(1, 0.01, n),
        rng.poisson(0.15, n),
        rng.binomial(1, 0.01, n),
    ]).astype(float)


class BehaviorDetector:
    name = "behavior_takeover"
    channel = "takeover"
    version_label = "iforest-synthetic-v1+rules-v1"

    def __init__(self) -> None:
        self.model: IsolationForest | None = None
        self.stats = DetectorStats(self.name)
        self.trained_at: str | None = None
        self._lo = 0.0
        self._hi = 1.0
        self.window = timedelta(minutes=15)

    def train(self) -> None:
        X = synthetic_normal_sessions()
        self.model = IsolationForest(n_estimators=150, contamination="auto", random_state=7).fit(X)
        raw = -self.model.score_samples(X)
        self._lo, self._hi = float(np.percentile(raw, 50)), float(np.percentile(raw, 99.5))
        self.trained_at = iso(utcnow())

    def anomaly(self, x: np.ndarray) -> float:
        assert self.model is not None
        raw = float(-self.model.score_samples(x)[0])
        # 0 at the median synthetic-normal session, 1 at/above its 99.5th percentile
        return clamp01((raw - self._lo) / max(1e-6, self._hi - self._lo))

    def build_features(self, event: NormalizedEvent, prof: CustomerProfile | None) -> tuple[dict[str, float], set[str]]:
        md = event.metadata
        now = event.timestamp
        fired: set[str] = set()
        if prof is None:
            feats = {f: 0.0 for f in FEATURES}
            return feats, fired
        cold_start = prof.history_events == 0
        device_new = 1.0 if event.device_token and event.device_token not in prof.devices and not cold_start else 0.0
        ip_new = 1.0 if event.ip_token and event.ip_token not in prof.ips and not cold_start else 0.0
        usual = prof.usual_hour
        hour_dev = 0.0
        if usual is not None:
            diff = abs(now.hour + now.minute / 60 - usual)
            hour_dev = min(diff, 24 - diff) / 12
        speed = 0.0
        loc = coords_for(md.get("city"))
        if prof.last_location is not None and loc is not None:
            prev_loc, prev_ts = prof.last_location
            hours = max((now - prev_ts).total_seconds() / 3600, 1 / 60)
            speed = haversine_km(prev_loc, loc) / hours
        hour_window = [s for s in prof.session_since(now, timedelta(hours=1))]
        devices_1h = {s.device for s in hour_window if s.device} | ({event.device_token} if event.device_token else set())
        ips_1h = {s.ip for s in hour_window if s.ip} | ({event.ip_token} if event.ip_token else set())
        logins_10m = prof.count_since(prof.login_times, now, timedelta(minutes=10))
        failed = float(md.get("failed_attempts", 0) or 0)
        cred_change = 1.0 if md.get("password_changed") or md.get("credential_change") else 0.0
        mfa = 1.0 if event.event_type == EventType.mfa_reset else 0.0
        feats = {
            "hour_deviation": round(hour_dev, 4),
            "device_new": device_new,
            "ip_new": ip_new,
            "travel_speed_kmh_log": round(float(np.log1p(min(speed, 20000))), 4),
            "logins_10m": float(logins_10m),
            "device_switches_1h": float(max(0, len(devices_1h) - 1)),
            "ip_switches_1h": float(max(0, len(ips_1h) - 1)),
            "mfa_reset": mfa,
            "failed_attempts": failed,
            "credential_change": cred_change,
        }
        if device_new or event.event_type == EventType.device_change:
            fired.add("new_device")
        if event.event_type == EventType.device_change:
            fired.add("device_change")
        if ip_new:
            fired.add("new_ip")
        if mfa:
            fired.add("mfa_reset")
        if speed > 900:
            fired.add("impossible_travel")
        if hour_dev >= 0.5:
            fired.add("unusual_login_time")
        if logins_10m >= 3:
            fired.add("login_burst")
        if len(devices_1h) >= 2 and device_new:
            fired.add("device_switching")
        if len(ips_1h) >= 2 and ip_new:
            fired.add("ip_switching")
        if failed >= 3 or cred_change:
            fired.add("abnormal_session")
        return feats, fired

    def detect(self, event: NormalizedEvent, prof: CustomerProfile | None) -> DetectorResult:
        assert self.model is not None
        with Timer() as t:
            feats, fired = self.build_features(event, prof)
            x = np.asarray([[feats[f] for f in FEATURES]], dtype=float)
            behavior_score = self.anomaly(x)
            # accumulate distinct takeover signals across the customer's recent session
            session_signals: set[str] = set()
            if prof is not None:
                for entry in prof.session_since(event.timestamp, self.window):
                    session_signals |= entry.signals
            all_signals = fired | {s for s in session_signals if s in RULES}
            rule_points = sum(RULES[s][0] for s in all_signals)
            takeover = clamp01(rule_points + 0.2 * behavior_score)
            signal_details: list[dict[str, Any]] = [
                {
                    "name": s,
                    "label": RULES[s][1],
                    "weight": RULES[s][0],
                    "points": round(RULES[s][0] * 100),
                    "current_event": s in fired,
                }
                for s in all_signals
            ]
            history = prof.history_events if prof else 0
            confidence = 0.5 + 0.35 * min(1.0, history / 15) + 0.15 * min(1.0, len(all_signals) / 3)
        self.stats.record(t.ms)
        return make_result(
            detector=self.name, channel=self.channel, score=takeover, confidence=confidence,
            signal_details=signal_details, model_version=self.version_label, latency_ms=t.ms,
            details={
                "features": feats,
                "behavior_score": round(behavior_score, 4),
                "takeover_score": round(takeover, 4),
                "rule_points": round(rule_points, 4),
                "current_event_signals": sorted(fired),
                "top_signals": [s["name"] for s in sorted(signal_details, key=lambda s: -s["weight"])[:5]],
            },
        )
