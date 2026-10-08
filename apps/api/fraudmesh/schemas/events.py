"""Inbound event contracts (Pydantic v2). Every field is bounded and typed."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from fraudmesh.domain import EventType

_ID = r"^[A-Za-z0-9_.:\-]{1,64}$"


class Geo(BaseModel):
    lat: float = Field(ge=-90, le=90)
    lon: float = Field(ge=-180, le=180)
    city: str | None = Field(default=None, max_length=80)
    country: str | None = Field(default=None, max_length=2)


class DeviceInfo(BaseModel):
    id: str | None = Field(default=None, pattern=_ID)
    fingerprint: str | None = Field(default=None, max_length=256)
    os: str | None = Field(default=None, max_length=40)
    model: str | None = Field(default=None, max_length=80)
    browser: str | None = Field(default=None, max_length=60)
    timezone: str | None = Field(default=None, max_length=40)
    emulator: bool = False
    rooted: bool = False
    remote_access_tool: bool = False


class LoginPayload(BaseModel):
    success: bool
    method: Literal["password", "sso", "biometric", "otp"] = "password"
    failure_reason: str | None = Field(default=None, max_length=60)
    user_agent: str | None = Field(default=None, max_length=300)
    session_duration_s: float | None = Field(default=None, ge=0, le=86_400)
    navigation_speed_ratio: float | None = Field(default=None, ge=0, le=100)


class DevicePayload(BaseModel):
    action: Literal["registered", "changed", "attested", "removed"] = "registered"


class MfaPayload(BaseModel):
    action: Literal["challenge", "success", "failure", "reset", "enrolled", "disabled", "factor_changed"]
    factor: Literal["totp", "sms", "push", "email", "hardware_key"] = "totp"
    channel_changed_to: str | None = Field(default=None, max_length=40)


class KycPayload(BaseModel):
    kyc_record_id: str | None = Field(default=None, pattern=_ID)
    media_analysis_id: str | None = Field(default=None, pattern=_ID, description="selfie analysis performed during this KYC attempt")
    document_type: str | None = Field(default=None, max_length=40)
    # pre-scored results from an external KYC vendor (0-100); internal verifications reference kyc_record_id
    kyc_risk: float | None = Field(default=None, ge=0, le=100)
    deepfake_risk: float | None = Field(default=None, ge=0, le=100)
    decision: str | None = Field(default=None, max_length=24)


class BiometricPayload(BaseModel):
    media_analysis_id: str | None = Field(default=None, pattern=_ID)
    modality: Literal["face", "voice"] = "face"
    deepfake_risk: float | None = Field(default=None, ge=0, le=100)
    liveness: Literal["PASSED", "FAILED", "INCONCLUSIVE", "NOT_APPLICABLE"] | None = None
    face_match: float | None = Field(default=None, ge=-1, le=1)


class TransactionPayload(BaseModel):
    amount: float = Field(gt=0, le=1e9)
    currency: str = Field(default="INR", pattern=r"^[A-Z]{3}$")
    channel: Literal["upi", "imps", "neft", "card", "wallet"] = "upi"
    merchant_category: str = Field(default="p2p_transfer", max_length=40)
    beneficiary_id: str | None = Field(default=None, pattern=_ID)
    beneficiary_name: str | None = Field(default=None, max_length=120)
    merchant_id: str | None = Field(default=None, pattern=_ID)
    balance_before: float | None = Field(default=None, ge=0)


class BeneficiaryPayload(BaseModel):
    action: Literal["added", "removed", "modified"] = "added"
    beneficiary_id: str = Field(pattern=_ID)
    beneficiary_name: str | None = Field(default=None, max_length=120)
    bank: str | None = Field(default=None, max_length=60)


class NetworkPayload(BaseModel):
    sensor: Literal["zeek", "suricata"]
    log_type: str | None = Field(default=None, max_length=16)
    record: dict[str, Any]

    @field_validator("record")
    @classmethod
    def _bounded(cls, v: dict) -> dict:
        if len(str(v)) > 20_000:
            raise ValueError("telemetry record too large")
        return v


class CloudPayload(BaseModel):
    provider: Literal["aws", "gcp", "azure"] = "aws"
    principal: str = Field(max_length=160)
    action: str = Field(max_length=120)
    resource: str | None = Field(default=None, max_length=300)
    region: str | None = Field(default=None, max_length=40)
    result: Literal["success", "denied"] = "success"
    mfa_used: bool = True


PAYLOADS: dict[EventType, type[BaseModel]] = {
    EventType.LOGIN: LoginPayload,
    EventType.DEVICE: DevicePayload,
    EventType.MFA: MfaPayload,
    EventType.KYC: KycPayload,
    EventType.BIOMETRIC: BiometricPayload,
    EventType.DEEPFAKE: BiometricPayload,
    EventType.TRANSACTION: TransactionPayload,
    EventType.BENEFICIARY: BeneficiaryPayload,
    EventType.NETWORK: NetworkPayload,
    EventType.IDS: NetworkPayload,
    EventType.CLOUD: CloudPayload,
}


class EventIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str | None = Field(default=None, pattern=_ID, description="client idempotency key")
    event_type: EventType
    timestamp: datetime | None = None
    source: str = Field(default="api", max_length=48)
    customer_id: str | None = Field(default=None, pattern=_ID)
    account_id: str | None = Field(default=None, pattern=_ID)
    session_id: str | None = Field(default=None, pattern=_ID)
    ip: str | None = Field(default=None, max_length=45)
    device: DeviceInfo | None = None
    geo: Geo | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        import ipaddress

        ipaddress.ip_address(v)
        return v

    @field_validator("timestamp")
    @classmethod
    def _tz(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v

    @model_validator(mode="after")
    def _payload(self) -> "EventIn":
        model = PAYLOADS[self.event_type]
        self.payload = model.model_validate(self.payload).model_dump()
        if self.event_type not in (EventType.NETWORK, EventType.IDS, EventType.CLOUD) and not (self.customer_id or self.account_id):
            raise ValueError("customer_id or account_id is required for customer events")
        return self


class TypedEventIn(BaseModel):
    """Body for the typed endpoints (/events/login etc.) — event_type comes from the path."""

    model_config = ConfigDict(extra="forbid")

    event_id: str | None = Field(default=None, pattern=_ID)
    timestamp: datetime | None = None
    source: str = Field(default="api", max_length=48)
    customer_id: str | None = Field(default=None, pattern=_ID)
    account_id: str | None = Field(default=None, pattern=_ID)
    session_id: str | None = Field(default=None, pattern=_ID)
    ip: str | None = Field(default=None, max_length=45)
    device: DeviceInfo | None = None
    geo: Geo | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
