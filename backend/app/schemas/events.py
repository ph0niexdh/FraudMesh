"""Event schemas.

``EventIn`` accepts either raw (synthetic) identifiers — which are tokenized
on ingestion — or pre-tokenized values. ``NormalizedEvent`` is the common
schema every downstream component consumes.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EventType(str, Enum):
    transaction = "transaction"
    login = "login"
    device_change = "device_change"
    mfa_reset = "mfa_reset"
    kyc_verification = "kyc_verification"
    cloud_event = "cloud_event"


BANKS = ("SBI", "HDFC Bank", "ICICI Bank")
_BANK_ALIASES = {"SBI": "SBI", "HDFC": "HDFC Bank", "HDFC BANK": "HDFC Bank", "ICICI": "ICICI Bank", "ICICI BANK": "ICICI Bank"}


class EventIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    event_type: EventType
    timestamp: datetime | None = None
    # raw (synthetic) identifiers — tokenized on ingestion, never stored
    customer_id: str | None = Field(default=None, max_length=128)
    account_id: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=128)
    ip_address: str | None = Field(default=None, max_length=64)
    # or already-tokenized identifiers
    customer_token: str | None = Field(default=None, max_length=64)
    account_token: str | None = Field(default=None, max_length=64)
    device_token: str | None = Field(default=None, max_length=64)
    ip_token: str | None = Field(default=None, max_length=64)
    channel: str = Field(default="mobile", max_length=32)
    amount: float = Field(default=0.0, ge=0, le=1e10)
    bank_name: str | None = Field(default=None, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("bank_name")
    @classmethod
    def _bank(cls, v: str | None) -> str | None:
        if v is None:
            return None
        canon = _BANK_ALIASES.get(v.strip().upper())
        if canon is None:
            raise ValueError(f"bank_name must be one of {BANKS} (synthetic demo entities)")
        return canon

    @field_validator("metadata")
    @classmethod
    def _metadata_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(v) > 64:
            raise ValueError("metadata may contain at most 64 keys")
        if len(str(v)) > 16_000:
            raise ValueError("metadata too large")
        return v

    @model_validator(mode="after")
    def _needs_identity(self) -> "EventIn":
        has_entity = any(
            [self.customer_id, self.customer_token, self.account_id, self.account_token,
             self.device_id, self.device_token, self.ip_address, self.ip_token]
        )
        if not has_entity and self.event_type != EventType.cloud_event:
            raise ValueError("event must reference at least one customer/account/device/ip")
        if self.event_type == EventType.transaction and self.amount <= 0:
            raise ValueError("transaction events require a positive amount")
        return self


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1)


class NormalizedEvent(BaseModel):
    event_id: str
    event_type: EventType
    timestamp: datetime
    customer_token: str | None = None
    account_token: str | None = None
    device_token: str | None = None
    ip_token: str | None = None
    channel: str = "mobile"
    amount: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def bank_name(self) -> str | None:
        return self.metadata.get("bank_name")


class DetectorResult(BaseModel):
    """Standardised detector output (spec fields + transparent extras)."""

    score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    signals: list[str] = Field(default_factory=list)
    detector: str
    timestamp: datetime
    channel: str
    model_version: str = ""
    signal_details: list[dict[str, Any]] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0
