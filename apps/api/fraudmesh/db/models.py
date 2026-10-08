"""PostgreSQL schema (SQLAlchemy 2.0 typed ORM).

Relational/transactional data lives here; entity relationships live in Neo4j.
Graph entity ids are the same strings used in ``events.entities`` so the two
stores join on id without duplicating relationship data.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ---------------------------------------------------------------- identity / auth
class User(Base):
    """Platform operators (analysts, investigators, admins)."""

    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_pending_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)  # replay protection
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = _now()


class AuthSession(Base):
    """One row per refresh token. Rotation creates a new row in the same family;
    presenting an already-rotated token revokes the whole family (reuse detection)."""

    __tablename__ = "auth_sessions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    family_id: Mapped[str] = mapped_column(String(40), index=True)
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True)
    device_id: Mapped[str | None] = mapped_column(String(40))
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)


class UserDevice(Base):
    __tablename__ = "user_devices"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    fingerprint_hash: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(160))
    trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = _now()
    last_seen: Mapped[datetime] = _now()
    last_ip: Mapped[str | None] = mapped_column(String(64))
    __table_args__ = (Index("ix_user_devices_user_fp", "user_id", "fingerprint_hash", unique=True),)


class OtpChallenge(Base):
    __tablename__ = "otp_challenges"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(40), index=True)
    purpose: Mapped[str] = mapped_column(String(32))
    channel: Mapped[str] = mapped_column(String(16))
    destination_masked: Mapped[str | None] = mapped_column(String(64))
    code_hash: Mapped[str] = mapped_column(String(255))  # argon2id
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


# ---------------------------------------------------------------- customers
class Customer(Base):
    """End customers of the protected institution (synthetic in demo mode)."""

    __tablename__ = "customers"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(120))
    email_masked: Mapped[str | None] = mapped_column(String(160))
    phone_masked: Mapped[str | None] = mapped_column(String(40))
    email_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    phone_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    segment: Mapped[str] = mapped_column(String(32), default="retail")
    risk_tier: Mapped[str] = mapped_column(String(16), default="standard")
    home_city: Mapped[str | None] = mapped_column(String(80))
    home_lat: Mapped[float | None] = mapped_column(Float)
    home_lon: Mapped[float | None] = mapped_column(Float)
    kyc_status: Mapped[str] = mapped_column(String(24), default="VERIFIED")
    population: Mapped[str] = mapped_column(String(24), default="normal")  # normal | mule | fraudster (synthetic label)
    profile: Mapped[dict] = mapped_column(JSONB, default=dict)  # behavioural baseline
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _now()


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    number_masked: Mapped[str] = mapped_column(String(24))
    number_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    kind: Mapped[str] = mapped_column(String(24), default="savings")
    currency: Mapped[str] = mapped_column(String(3), default="INR")
    balance: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(16), default="ACTIVE")
    opened_at: Mapped[datetime] = _now()


class FaceTemplate(Base):
    """Encrypted face embeddings. Raw face images are never persisted."""

    __tablename__ = "face_templates"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str] = mapped_column(ForeignKey("customers.id", ondelete="CASCADE"), index=True)
    embedding_enc: Mapped[bytes] = mapped_column(LargeBinary)
    model_version: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))  # enrollment | kyc_document | selfie
    created_at: Mapped[datetime] = _now()


# ---------------------------------------------------------------- events & detection
class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(24), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = _now()
    source: Mapped[str] = mapped_column(String(48))
    customer_id: Mapped[str | None] = mapped_column(String(40), index=True)
    account_id: Mapped[str | None] = mapped_column(String(40), index=True)
    device_id: Mapped[str | None] = mapped_column(String(64), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    session_id: Mapped[str | None] = mapped_column(String(64))
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    entities: Mapped[list] = mapped_column(JSONB, default=list)  # [{"id","type","role"}]
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100
    confidence: Mapped[float] = mapped_column(Float, default=0.0)  # 0-1
    risk_level: Mapped[str] = mapped_column(String(12), default="LOW")
    model: Mapped[str | None] = mapped_column(String(80))
    action: Mapped[str | None] = mapped_column(String(24))
    reason_codes: Mapped[list] = mapped_column(JSONB, default=list)
    case_id: Mapped[str | None] = mapped_column(String(40), index=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    simulation_run_id: Mapped[str | None] = mapped_column(String(40), index=True)
    __table_args__ = (Index("ix_events_received", "received_at"),)


class Detection(Base):
    """One prediction by one detector for one event (the 'predictions' table)."""

    __tablename__ = "detections"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    detector: Mapped[str] = mapped_column(String(40), index=True)
    model_version: Mapped[str] = mapped_column(String(80))
    risk_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    reason_codes: Mapped[list] = mapped_column(JSONB, default=list)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    latency_ms: Mapped[float] = mapped_column(Float)
    created_at: Mapped[datetime] = _now()


class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    customer_id: Mapped[str | None] = mapped_column(String(40), index=True)
    account_id: Mapped[str | None] = mapped_column(String(40), index=True)
    amount: Mapped[float] = mapped_column(Float)
    currency: Mapped[str] = mapped_column(String(3), default="INR")
    channel: Mapped[str] = mapped_column(String(24))
    merchant_category: Mapped[str | None] = mapped_column(String(40))
    beneficiary_id: Mapped[str | None] = mapped_column(String(40), index=True)
    beneficiary_new: Mapped[bool] = mapped_column(Boolean, default=False)
    fraud_probability: Mapped[float] = mapped_column(Float, default=0.0)
    decision: Mapped[str] = mapped_column(String(16), default="ALLOW")
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    case_id: Mapped[str | None] = mapped_column(String(40), index=True)
    detector: Mapped[str] = mapped_column(String(40))
    domain: Mapped[str] = mapped_column(String(24))
    severity: Mapped[str] = mapped_column(String(12))
    title: Mapped[str] = mapped_column(String(200))
    risk_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="OPEN")
    created_at: Mapped[datetime] = _now()


class MediaAnalysis(Base):
    """Deepfake / liveness result. Stores scores and evidence geometry, not raw media
    (except registered non-PII demo fixtures)."""

    __tablename__ = "media_analyses"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str | None] = mapped_column(String(40), index=True)
    event_id: Mapped[str | None] = mapped_column(String(40), index=True)
    media_type: Mapped[str] = mapped_column(String(12))
    media_sha256: Mapped[str] = mapped_column(String(64))
    fixture_name: Mapped[str | None] = mapped_column(String(80))
    verdict: Mapped[str] = mapped_column(String(32))
    deepfake_probability: Mapped[float] = mapped_column(Float)
    result: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = _now()


class KycRecord(Base):
    __tablename__ = "kyc_records"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str | None] = mapped_column(String(40), index=True)
    event_id: Mapped[str | None] = mapped_column(String(40), index=True)
    doc_type: Mapped[str] = mapped_column(String(40))
    doc_number_hmac: Mapped[str | None] = mapped_column(String(64), index=True)
    fields_masked: Mapped[dict] = mapped_column(JSONB, default=dict)
    checks: Mapped[list] = mapped_column(JSONB, default=list)
    scores: Mapped[dict] = mapped_column(JSONB, default=dict)
    decision: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[datetime] = _now()


class VerificationSession(Base):
    """Customer identity-verification workflow (login → ... → final decision)."""

    __tablename__ = "verification_sessions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    customer_id: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(16), default="IN_PROGRESS")
    current_stage: Mapped[str] = mapped_column(String(24))
    stages: Mapped[dict] = mapped_column(JSONB, default=dict)
    scores: Mapped[dict] = mapped_column(JSONB, default=dict)
    decision: Mapped[dict | None] = mapped_column(JSONB)
    device_id: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


# ---------------------------------------------------------------- cases
class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    attack_type: Mapped[str] = mapped_column(String(60))
    severity: Mapped[str] = mapped_column(String(12), index=True)
    status: Mapped[str] = mapped_column(String(16), default="NEW", index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    recommended_action: Mapped[str] = mapped_column(String(24))
    action_taken: Mapped[str | None] = mapped_column(String(24))
    fusion: Mapped[dict] = mapped_column(JSONB, default=dict)
    story: Mapped[str] = mapped_column(Text, default="")
    primary_customer_id: Mapped[str | None] = mapped_column(String(40), index=True)
    analyst_id: Mapped[str | None] = mapped_column(String(40))
    raw_alert_count: Mapped[int] = mapped_column(Integer, default=0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    amount_at_risk: Mapped[float] = mapped_column(Float, default=0.0)
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    correlation_window_s: Mapped[int] = mapped_column(Integer, default=900)
    is_simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


class CaseEvent(Base):
    __tablename__ = "case_events"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), primary_key=True)
    reason: Mapped[str] = mapped_column(String(200))
    added_at: Mapped[datetime] = _now()


class CaseEntity(Base):
    __tablename__ = "case_entities"
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(120))
    risk: Mapped[float] = mapped_column(Float, default=0.0)


class CaseAction(Base):
    __tablename__ = "case_actions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(160))  # user email or "policy-engine"
    note: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = _now()


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)
    label: Mapped[str] = mapped_column(String(24))  # CONFIRMED_FRAUD | FALSE_POSITIVE
    actor_id: Mapped[str] = mapped_column(String(40))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()


# ---------------------------------------------------------------- governance
class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    conditions: Mapped[list] = mapped_column(JSONB, default=list)
    action: Mapped[str] = mapped_column(String(24))
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str | None] = mapped_column(String(160))
    updated_at: Mapped[datetime] = _now()


class ModelRecord(Base):
    __tablename__ = "model_registry"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    version: Mapped[str] = mapped_column(String(40))
    model_type: Mapped[str] = mapped_column(String(80))
    framework: Mapped[str] = mapped_column(String(40))
    domain: Mapped[str] = mapped_column(String(24))
    training_date: Mapped[str | None] = mapped_column(String(40))
    dataset: Mapped[str] = mapped_column(Text)
    metrics: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(16))
    artifact: Mapped[str | None] = mapped_column(String(300))
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    notes: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (Index("ix_model_name_version", "name", "version", unique=True),)


class AuditLog(Base):
    """Append-only, hash-chained. UPDATE/DELETE are rejected by a DB trigger."""

    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(160))
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(40))
    resource_id: Mapped[str | None] = mapped_column(String(80), index=True)
    old_state: Mapped[dict | None] = mapped_column(JSONB)
    new_state: Mapped[dict | None] = mapped_column(JSONB)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    device_id: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(40))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class SimulationRun(Base):
    __tablename__ = "simulation_runs"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16))
    started_by: Mapped[str] = mapped_column(String(160))
    seed: Mapped[int] = mapped_column(Integer)
    total_steps: Mapped[int] = mapped_column(Integer, default=0)
    emitted: Mapped[int] = mapped_column(Integer, default=0)
    case_ids: Mapped[list] = mapped_column(JSONB, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = _now()
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
