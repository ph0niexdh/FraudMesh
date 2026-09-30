from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, model_validator


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    HOLD_INVESTIGATE = "HOLD_INVESTIGATE"
    BLOCK_HOLD_INVESTIGATE = "BLOCK_HOLD_INVESTIGATE"


ACTION_LABELS = {
    PolicyAction.ALLOW.value: "ALLOW",
    PolicyAction.STEP_UP.value: "STEP-UP AUTHENTICATION",
    PolicyAction.HOLD_INVESTIGATE.value: "HOLD + INVESTIGATE",
    PolicyAction.BLOCK_HOLD_INVESTIGATE.value: "BLOCK / HOLD + INVESTIGATE",
}


class FusionWeights(BaseModel):
    transaction: float = Field(0.30, ge=0, le=1)
    takeover: float = Field(0.20, ge=0, le=1)
    kyc: float = Field(0.20, ge=0, le=1)
    cloud: float = Field(0.10, ge=0, le=1)
    graph: float = Field(0.15, ge=0, le=1)
    temporal: float = Field(0.05, ge=0, le=1)


class FusionConfig(BaseModel):
    """Demonstration configuration — not scientifically optimised values."""

    weights: FusionWeights = Field(default_factory=FusionWeights)
    temporal_window_minutes: int = Field(15, ge=1, le=24 * 60)
    suspicious_event_threshold: float = Field(0.35, ge=0.05, le=0.95)
    min_correlated_signals: int = Field(2, ge=1, le=10)
    case_creation_min_risk: float = Field(15.0, ge=0, le=100)


class PolicyTier(BaseModel):
    policy_id: str = Field(pattern=r"^[A-Z0-9_-]{2,32}$")
    severity: str = Field(pattern=r"^[A-Z_]{2,16}$")
    min_score: int = Field(ge=0, le=100)
    max_score: int = Field(ge=0, le=100)
    action: PolicyAction


class PolicyConfig(BaseModel):
    tiers: list[PolicyTier]

    @model_validator(mode="after")
    def _contiguous(self) -> "PolicyConfig":
        tiers = sorted(self.tiers, key=lambda t: t.min_score)
        if not tiers or tiers[0].min_score != 0 or tiers[-1].max_score != 100:
            raise ValueError("policy tiers must cover 0-100")
        for prev, cur in zip(tiers, tiers[1:]):
            if cur.min_score != prev.max_score + 1:
                raise ValueError(f"tiers must be contiguous: {prev.policy_id} ends {prev.max_score}, "
                                 f"{cur.policy_id} starts {cur.min_score}")
        for t in tiers:
            if t.min_score > t.max_score:
                raise ValueError(f"{t.policy_id}: min_score > max_score")
        self.tiers = tiers
        return self


def default_policy() -> PolicyConfig:
    return PolicyConfig(
        tiers=[
            PolicyTier(policy_id="POL-LOW", severity="LOW", min_score=0, max_score=29, action=PolicyAction.ALLOW),
            PolicyTier(policy_id="POL-MEDIUM", severity="MEDIUM", min_score=30, max_score=59, action=PolicyAction.STEP_UP),
            PolicyTier(policy_id="POL-HIGH", severity="HIGH", min_score=60, max_score=79, action=PolicyAction.HOLD_INVESTIGATE),
            PolicyTier(policy_id="POL-CRITICAL", severity="CRITICAL", min_score=80, max_score=100,
                       action=PolicyAction.BLOCK_HOLD_INVESTIGATE),
        ]
    )
