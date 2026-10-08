"""Lightweight in-process telemetry: latency percentiles, throughput, error counts.

Rolling windows (last N observations) keep memory bounded. Exposed via /api/metrics
and streamed to the dashboard.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock


def _pct(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return round(s[idx], 2)


@dataclass
class _Series:
    values: deque = field(default_factory=lambda: deque(maxlen=500))
    count: int = 0
    errors: int = 0
    last_at: float | None = None

    def add(self, ms: float, error: bool = False) -> None:
        self.values.append(ms)
        self.count += 1
        self.errors += int(error)
        self.last_at = time.time()

    def summary(self) -> dict:
        v = list(self.values)
        return {
            "count": self.count,
            "errors": self.errors,
            "p50_ms": _pct(v, 0.5),
            "p95_ms": _pct(v, 0.95),
            "p99_ms": _pct(v, 0.99),
            "last_at": self.last_at,
        }


class Telemetry:
    def __init__(self) -> None:
        self._lock = Lock()
        self.api: dict[str, _Series] = defaultdict(_Series)
        self.inference: dict[str, _Series] = defaultdict(_Series)
        self.stages: dict[str, _Series] = defaultdict(_Series)
        self._event_times: deque = deque(maxlen=5000)
        self.events_by_type: dict[str, int] = defaultdict(int)
        self.ws_clients = 0
        self.ws_messages = 0
        self.started_at = time.time()

    def observe_api(self, route: str, ms: float, status: int) -> None:
        with self._lock:
            self.api[route].add(ms, status >= 500)

    def observe_inference(self, detector: str, ms: float, error: bool = False) -> None:
        with self._lock:
            self.inference[detector].add(ms, error)

    def observe_stage(self, stage: str, ms: float) -> None:
        with self._lock:
            self.stages[stage].add(ms)

    def count_event(self, event_type: str) -> None:
        with self._lock:
            self._event_times.append(time.time())
            self.events_by_type[event_type] += 1

    def events_per_sec(self, window_s: int = 60) -> float:
        cutoff = time.time() - window_s
        with self._lock:
            n = sum(1 for t in self._event_times if t >= cutoff)
        return round(n / window_s, 3)

    def snapshot(self) -> dict:
        with self._lock:
            api_all = [v for s in self.api.values() for v in s.values]
            return {
                "uptime_s": round(time.time() - self.started_at, 1),
                "events_per_sec_1m": None,  # filled below outside the lock
                "events_by_type": dict(self.events_by_type),
                "api": {
                    "p50_ms": _pct(api_all, 0.5),
                    "p95_ms": _pct(api_all, 0.95),
                    "requests": sum(s.count for s in self.api.values()),
                    "errors_5xx": sum(s.errors for s in self.api.values()),
                    "routes": {k: v.summary() for k, v in sorted(self.api.items(), key=lambda kv: -kv[1].count)[:20]},
                },
                "inference": {k: v.summary() for k, v in self.inference.items()},
                "pipeline_stages": {k: v.summary() for k, v in self.stages.items()},
                "websocket": {"clients": self.ws_clients, "messages_sent": self.ws_messages},
            }


telemetry = Telemetry()


def snapshot() -> dict:
    snap = telemetry.snapshot()
    snap["events_per_sec_1m"] = telemetry.events_per_sec(60)
    return snap
