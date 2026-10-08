"""Shared domain vocabulary (enums + risk-level thresholds)."""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "ADMIN"
    INVESTIGATOR = "INVESTIGATOR"
    ANALYST = "ANALYST"
    SECURITY_OPERATOR = "SECURITY_OPERATOR"
    AUDITOR = "AUDITOR"


class EventType(StrEnum):
    LOGIN = "LOGIN"
    DEVICE = "DEVICE"
    MFA = "MFA"
    KYC = "KYC"
    BIOMETRIC = "BIOMETRIC"
    DEEPFAKE = "DEEPFAKE"
    TRANSACTION = "TRANSACTION"
    BENEFICIARY = "BENEFICIARY"
    NETWORK = "NETWORK"
    IDS = "IDS"
    CLOUD = "CLOUD"


class EntityType(StrEnum):
    CUSTOMER = "Customer"
    ACCOUNT = "Account"
    DEVICE = "Device"
    IP = "IP"
    SESSION = "Session"
    MFA = "MFA"
    PHONE = "Phone"
    EMAIL = "Email"
    KYC_DOCUMENT = "KYCDocument"
    FACE = "Face"
    TRANSACTION = "Transaction"
    BENEFICIARY = "Beneficiary"
    MERCHANT = "Merchant"
    CLOUD_IDENTITY = "CloudIdentity"
    CLOUD_RESOURCE = "CloudResource"
    NETWORK_INDICATOR = "NetworkIndicator"
    CASE = "Case"


class RelType(StrEnum):
    OWNS = "OWNS"
    USES = "USES"
    LOGGED_IN_FROM = "LOGGED_IN_FROM"
    AUTHENTICATED_WITH = "AUTHENTICATED_WITH"
    VERIFIED_BY = "VERIFIED_BY"
    SHARES_DEVICE = "SHARES_DEVICE"
    SHARES_IP = "SHARES_IP"
    SENT_TO = "SENT_TO"
    RECEIVED_FROM = "RECEIVED_FROM"
    ACCESSED = "ACCESSED"
    CREATED = "CREATED"
    LINKED_TO = "LINKED_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseStatus(StrEnum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Action(StrEnum):
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    STEP_UP = "STEP_UP"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


ACTION_SEVERITY = {Action.ALLOW: 0, Action.MONITOR: 1, Action.STEP_UP: 2, Action.HOLD: 3, Action.BLOCK: 4}

# Risk score (0-100) → level. Shared by every detector and by fusion.
LEVEL_THRESHOLDS = ((85.0, RiskLevel.CRITICAL), (65.0, RiskLevel.HIGH), (40.0, RiskLevel.MEDIUM))


def risk_level(score: float) -> RiskLevel:
    for threshold, level in LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


# Which detector "domain" each event type feeds in risk fusion.
DOMAINS = ("transaction", "behavior", "identity", "deepfake", "device", "graph", "network", "temporal")
