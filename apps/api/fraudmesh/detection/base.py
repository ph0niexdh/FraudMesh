"""Detector contract shared by every detection engine.

Every detector returns a ``DetectorResult`` with the same shape, so fusion, case
management and the UI never need to know which implementation produced it.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from fraudmesh.domain import risk_level


@dataclass
class Reason:
    code: str
    message: str
    weight: float = 0.0  # signed contribution in the detector's own units (e.g. SHAP value)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DetectorResult:
    detector: str
    domain: str  # transaction | behavior | identity | deepfake | device | graph | network | temporal
    risk_score: float  # 0-100
    confidence: float  # 0-1: how much the detector trusts its own output (coverage / data quality)
    reason_codes: list[Reason] = field(default_factory=list)
    model_version: str = ""
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        return risk_level(self.risk_score).value

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "domain": self.domain,
            "risk_score": round(float(self.risk_score), 2),
            "risk_level": self.risk_level,
            "confidence": round(float(self.confidence), 3),
            "reason_codes": [r.to_dict() for r in self.reason_codes],
            "model_version": self.model_version,
            "latency_ms": round(float(self.latency_ms), 2),
            "metadata": self.metadata,
        }


@dataclass
class DetectorStatus:
    name: str
    domain: str
    status: str  # ONLINE | DEGRADED | OFFLINE
    model_version: str
    model_type: str
    detail: str = ""


class BaseDetector(ABC):
    name: str = "base"
    domain: str = "transaction"

    @property
    @abstractmethod
    def model_version(self) -> str: ...

    @abstractmethod
    def status(self) -> DetectorStatus: ...


class Timer:
    def __enter__(self) -> "Timer":
        self.t = time.perf_counter()
        return self

    def __exit__(self, *exc) -> None:
        self.ms = (time.perf_counter() - self.t) * 1000
