"""SQLAlchemy ORM models.

Only portable column types are used (String, Integer, Float, Boolean,
DateTime(timezone=True), JSON) so the same schema runs on SQLite and
PostgreSQL. Identifiers are always tokens; no raw PII columns exist.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"
    customer_token: Mapped[str] = mapped_column(String(32), primary_key=True)
    display_label: Mapped[str] = mapped_column(String(64))
    home_city: Mapped[str | None] = mapped_column(String(64))
    segment: Mapped[str | None] = mapped_column(String(32))
    baseline_amount_mean: Mapped[float] = mapped_column(Float, default=0.0)
    baseline_amount_std: Mapped[float] = mapped_column(Float, default=0.0)
    typical_login_hour: Mapped[int] = mapped_column(Integer, default=12)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Account(Base):
    __tablename__ = "accounts"
    account_token: Mapped[str] = mapped_column(String(32), primary_key=True)
    customer_token: Mapped[str | None] = mapped_column(String(32), ForeignKey("customers.customer_token"), index=True)
    bank_name: Mapped[str] = mapped_column(String(32), index=True)
    display_label: Mapped[str] = mapped_column(String(64))
    account_type: Mapped[str] = mapped_column(String(32), default="savings")
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=True)


class Device(Base):
    __tablename__ = "devices"
    device_token: Mapped[str] = mapped_column(String(32), primary_key=True)
    display_label: Mapped[str] = mapped_column(String(64))
    device_type: Mapped[str | None] = mapped_column(String(32))
    os: Mapped[str | None] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IpAddress(Base):
    __tablename__ = "ip_addresses"
    ip_token: Mapped[str] = mapped_column(String(32), primary_key=True)
    display_label: Mapped[str] = mapped_column(String(64))
    city: Mapped[str | None] = mapped_column(String(64))
    network_type: Mapped[str | None] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Event(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    customer_token: Mapped[str | None] = mapped_column(String(32), index=True)
    account_token: Mapped[str | None] = mapped_column(String(32), index=True)
    device_token: Mapped[str | None] = mapped_column(String(32), index=True)
    ip_token: Mapped[str | None] = mapped_column(String(32), index=True)
    customer_label: Mapped[str | None] = mapped_column(String(64))
    account_label: Mapped[str | None] = mapped_column(String(64))
    device_label: Mapped[str | None] = mapped_column(String(64))
    ip_label: Mapped[str | None] = mapped_column(String(64))
    channel: Mapped[str] = mapped_column(String(32), index=True)
    bank_name: Mapped[str | None] = mapped_column(String(32), index=True)
    amount: Mapped[float] = mapped_column(Float, default=0.0)
    event_metadata: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    signal_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    suspicious: Mapped[bool] = mapped_column(Boolean, default=False)
    detector_results: Mapped[list] = mapped_column(JSON, default=list)
    case_id: Mapped[str | None] = mapped_column(String(32), index=True)
    source: Mapped[str] = mapped_column(String(16), default="live", index=True)


class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), ForeignKey("events.event_id", ondelete="CASCADE"), index=True)
    customer_token: Mapped[str | None] = mapped_column(String(32), index=True)
    account_token: Mapped[str | None] = mapped_column(String(32), index=True)
    beneficiary_token: Mapped[str | None] = mapped_column(String(32), index=True)
    merchant: Mapped[str | None] = mapped_column(String(64))
    amount: Mapped[float] = mapped_column(Float)
    currency: Mapped[str] = mapped_column(String(8), default="INR")
    city: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class KycEvent(Base):
    __tablename__ = "kyc_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), ForeignKey("events.event_id", ondelete="CASCADE"), index=True)
    customer_token: Mapped[str | None] = mapped_column(String(32), index=True)
    kyc_token: Mapped[str | None] = mapped_column(String(32))
    media_sha256: Mapped[str | None] = mapped_column(String(64))
    media_retained: Mapped[bool] = mapped_column(Boolean, default=False)
    manipulation_score: Mapped[float] = mapped_column(Float, default=0.0)
    face_detected: Mapped[bool | None] = mapped_column(Boolean)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    detector_version: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CloudEvent(Base):
    __tablename__ = "cloud_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), ForeignKey("events.event_id", ondelete="CASCADE"), index=True)
    principal_token: Mapped[str | None] = mapped_column(String(32), index=True)
    action: Mapped[str | None] = mapped_column(String(64))
    resource_token: Mapped[str | None] = mapped_column(String(32))
    region: Mapped[str | None] = mapped_column(String(32))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FraudCase(Base):
    __tablename__ = "fraud_cases"
    case_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(24), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    channel_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    graph_score: Mapped[float] = mapped_column(Float, default=0.0)
    temporal_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    explanations: Mapped[list] = mapped_column(JSON, default=list)
    contributions: Mapped[dict] = mapped_column(JSON, default=dict)
    graph_signals: Mapped[list] = mapped_column(JSON, default=list)
    policy_action: Mapped[str] = mapped_column(String(32))
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[str] = mapped_column(Text, default="")
    primary_customer: Mapped[str | None] = mapped_column(String(32))
    banks: Mapped[list] = mapped_column(JSON, default=list)
    scenario: Mapped[str | None] = mapped_column(String(48))
    source: Mapped[str] = mapped_column(String(16), default="live", index=True)


class CaseEvent(Base):
    __tablename__ = "case_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("fraud_cases.case_id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(String(64), ForeignKey("events.event_id", ondelete="CASCADE"), index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CaseEntity(Base):
    __tablename__ = "case_entities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("fraud_cases.case_id", ondelete="CASCADE"), index=True)
    entity_token: Mapped[str] = mapped_column(String(32), index=True)
    entity_type: Mapped[str] = mapped_column(String(24))
    label: Mapped[str | None] = mapped_column(String(64))
    bank_name: Mapped[str | None] = mapped_column(String(32))


class RiskScore(Base):
    __tablename__ = "risk_scores"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str | None] = mapped_column(String(32), index=True)
    event_id: Mapped[str | None] = mapped_column(String(64), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    channel_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    policy_action: Mapped[str | None] = mapped_column(String(32))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(32), ForeignKey("fraud_cases.case_id", ondelete="CASCADE"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    previous_status: Mapped[str | None] = mapped_column(String(24))
    new_status: Mapped[str | None] = mapped_column(String(24))
    analyst: Mapped[str] = mapped_column(String(64))
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class PolicyRecord(Base):
    __tablename__ = "policies"
    key: Mapped[str] = mapped_column(String(32), primary_key=True)
    config: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(64), default="system")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    action: Mapped[str] = mapped_column(String(48), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    entity_type: Mapped[str | None] = mapped_column(String(32))
    entity_id: Mapped[str | None] = mapped_column(String(64), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


Index("ix_events_type_ts", Event.event_type, Event.timestamp)
