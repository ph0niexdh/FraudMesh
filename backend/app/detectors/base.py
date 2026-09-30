"""Shared detector plumbing: result construction, latency and health stats."""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from app.schemas.events import DetectorResult
from app.utils.timeutil import utcnow


def clamp01(x: float) -> float:
    return float(min(1.0, max(0.0, x)))


@dataclass
class DetectorStats:
    name: str
    inferences: int = 0
    errors: int = 0
    latencies: deque = field(default_factory=lambda: deque(maxlen=500))
    last_error: str | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, latency_ms: float) -> None:
        with self.lock:
            self.inferences += 1
            self.latencies.append(latency_ms)

    def record_error(self, err: Exception) -> None:
        with self.lock:
            self.errors += 1
            self.last_error = f"{type(err).__name__}"

    def summary(self) -> dict[str, Any]:
        with self.lock:
            lat = list(self.latencies)
        return {
            "inferences": self.inferences,
            "errors": self.errors,
            "avg_latency_ms": round(float(np.mean(lat)), 3) if lat else None,
            "p95_latency_ms": round(float(np.percentile(lat, 95)), 3) if lat else None,
            "last_error": self.last_error,
        }


class Timer:
    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        self.ms = (time.perf_counter() - self.start) * 1000


def make_result(
    *,
    detector: str,
    channel: str,
    score: float,
    confidence: float,
    signal_details: list[dict[str, Any]],
    model_version: str,
    details: dict[str, Any] | None = None,
    latency_ms: float = 0.0,
) -> DetectorResult:
    signal_details = sorted(signal_details, key=lambda s: -float(s.get("weight", 0)))
    return DetectorResult(
        score=round(clamp01(score), 4),
        confidence=round(clamp01(confidence), 4),
        signals=[s["name"] for s in signal_details],
        detector=detector,
        channel=channel,
        timestamp=utcnow(),
        model_version=model_version,
        signal_details=signal_details,
        details=details or {},
        latency_ms=round(latency_ms, 3),
    )
