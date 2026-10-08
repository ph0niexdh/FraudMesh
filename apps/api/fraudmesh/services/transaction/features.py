"""Transaction feature schema — the single definition shared by training
(ml/transaction/train.py) and online scoring (services/transaction/detector.py)."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

MERCHANT_CATEGORIES = ["grocery", "utilities", "dining", "retail", "electronics", "travel", "gaming", "crypto", "p2p_transfer", "cash_withdrawal"]
CHANNELS = ["upi", "imps", "neft", "card", "wallet"]


@dataclass(frozen=True)
class Feature:
    name: str
    description: str
    kind: str = "numeric"  # numeric | binary | categorical


FEATURES: list[Feature] = [
    Feature("log_amount", "log(1 + amount)"),
    Feature("amount_deviation", "z-score of amount vs the customer's own history"),
    Feature("amount_to_balance", "amount / available balance"),
    Feature("velocity_1h", "customer transactions in the last hour"),
    Feature("velocity_24h", "customer transactions in the last 24 hours"),
    Feature("spend_24h_ratio", "24h spend / typical daily spend"),
    Feature("merchant_category", "merchant category", "categorical"),
    Feature("channel", "payment channel", "categorical"),
    Feature("hour_sin", "time of day (sine)"),
    Feature("hour_cos", "time of day (cosine)"),
    Feature("is_night", "local time 00:00-05:00", "binary"),
    Feature("device_age_days", "days since this device was first seen for the customer"),
    Feature("is_new_device", "device never seen for this customer", "binary"),
    Feature("device_shared_customers", "other customers seen on this device (graph)"),
    Feature("ip_risk", "IP reputation risk 0-1 (threat intel + hosting/proxy/tor)"),
    Feature("geo_distance_km", "distance from the customer's home location (log km)"),
    Feature("beneficiary_new", "first payment to this beneficiary", "binary"),
    Feature("beneficiary_inbound_senders", "distinct customers paying this beneficiary (graph, mule signal)"),
    Feature("account_age_days", "account age in days (log)"),
    Feature("secs_since_login", "seconds since session login (log)"),
    Feature("failed_logins_24h", "failed logins in the last 24 hours"),
    Feature("mfa_changes_24h", "MFA reset/changes in the last 24 hours"),
    Feature("kyc_risk", "most recent KYC risk 0-1"),
    Feature("deepfake_risk", "most recent deepfake risk for the customer's verification media 0-1"),
    Feature("network_risk", "most recent network/IDS risk linked to the session IP 0-1"),
    Feature("behavior_anomaly", "behavioural anomaly score 0-1 for the session"),
    Feature("graph_risk", "propagated graph risk of the customer/account 0-1"),
]
FEATURE_NAMES = [f.name for f in FEATURES]
CATEGORICAL = [f.name for f in FEATURES if f.kind == "categorical"]
CAT_VOCAB = {"merchant_category": MERCHANT_CATEGORIES, "channel": CHANNELS}

# Human-readable names for explanations
LABELS = {
    "log_amount": "Transaction amount",
    "amount_deviation": "Amount vs customer history",
    "amount_to_balance": "Share of balance",
    "velocity_1h": "Transactions in last hour",
    "velocity_24h": "Transactions in last 24h",
    "spend_24h_ratio": "24h spend vs typical",
    "merchant_category": "Merchant category",
    "channel": "Payment channel",
    "hour_sin": "Time of day",
    "hour_cos": "Time of day",
    "is_night": "Night-time transaction",
    "device_age_days": "Device age",
    "is_new_device": "New device",
    "device_shared_customers": "Device shared with other customers",
    "ip_risk": "IP reputation",
    "geo_distance_km": "Distance from home",
    "beneficiary_new": "New beneficiary",
    "beneficiary_inbound_senders": "Beneficiary receives from many customers",
    "account_age_days": "Account age",
    "secs_since_login": "Time since login",
    "failed_logins_24h": "Failed logins (24h)",
    "mfa_changes_24h": "MFA changes (24h)",
    "kyc_risk": "KYC risk",
    "deepfake_risk": "Deepfake risk",
    "network_risk": "Network / IDS risk",
    "behavior_anomaly": "Behavioural anomaly",
    "graph_risk": "Graph risk",
}


def encode_raw(raw: dict) -> dict:
    """Map raw context values → model features (same transforms in training and serving)."""
    hour = float(raw.get("hour", 12.0))
    return {
        "log_amount": math.log1p(max(0.0, float(raw["amount"]))),
        "amount_deviation": float(np.clip(raw.get("amount_deviation", 0.0), -5, 25)),
        "amount_to_balance": float(np.clip(raw.get("amount_to_balance", 0.0), 0, 5)),
        "velocity_1h": float(raw.get("velocity_1h", 0)),
        "velocity_24h": float(raw.get("velocity_24h", 0)),
        "spend_24h_ratio": float(np.clip(raw.get("spend_24h_ratio", 0.0), 0, 50)),
        "merchant_category": raw.get("merchant_category", "retail") if raw.get("merchant_category") in MERCHANT_CATEGORIES else "retail",
        "channel": raw.get("channel", "upi") if raw.get("channel") in CHANNELS else "upi",
        "hour_sin": math.sin(2 * math.pi * hour / 24),
        "hour_cos": math.cos(2 * math.pi * hour / 24),
        "is_night": 1.0 if 0 <= hour < 5 else 0.0,
        "device_age_days": math.log1p(max(0.0, float(raw.get("device_age_days", 365)))),
        "is_new_device": 1.0 if raw.get("is_new_device") else 0.0,
        "device_shared_customers": float(min(20, raw.get("device_shared_customers", 0))),
        "ip_risk": float(np.clip(raw.get("ip_risk", 0.0), 0, 1)),
        "geo_distance_km": math.log1p(max(0.0, float(raw.get("geo_distance_km", 0.0)))),
        "beneficiary_new": 1.0 if raw.get("beneficiary_new") else 0.0,
        "beneficiary_inbound_senders": float(min(50, raw.get("beneficiary_inbound_senders", 0))),
        "account_age_days": math.log1p(max(0.0, float(raw.get("account_age_days", 365)))),
        "secs_since_login": math.log1p(max(0.0, float(raw.get("secs_since_login", 600)))),
        "failed_logins_24h": float(min(50, raw.get("failed_logins_24h", 0))),
        "mfa_changes_24h": float(min(10, raw.get("mfa_changes_24h", 0))),
        "kyc_risk": float(np.clip(raw.get("kyc_risk", 0.0), 0, 1)),
        "deepfake_risk": float(np.clip(raw.get("deepfake_risk", 0.0), 0, 1)),
        "network_risk": float(np.clip(raw.get("network_risk", 0.0), 0, 1)),
        "behavior_anomaly": float(np.clip(raw.get("behavior_anomaly", 0.0), 0, 1)),
        "graph_risk": float(np.clip(raw.get("graph_risk", 0.0), 0, 1)),
    }


def to_frame(rows: list[dict]):
    import pandas as pd

    df = pd.DataFrame(rows, columns=FEATURE_NAMES)
    for c in CATEGORICAL:
        df[c] = pd.Categorical(df[c], categories=CAT_VOCAB[c])
    return df
