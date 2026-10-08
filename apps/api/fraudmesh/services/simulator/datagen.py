"""Synthetic training data (reproducible, seeded).

Populations are intentionally *overlapping*: legitimate customers travel, change
phones, buy expensive things at night and pay new people; fraudsters sometimes
use the victim's own device (authorised-push-payment scams) or skip signals.
That keeps the learning problem honest — no single feature separates classes.

Every row is generated from a scenario with documented parameters, so model
cards can state exactly what the models were trained on.
"""

from __future__ import annotations

import numpy as np

from fraudmesh.services.transaction.features import CHANNELS, MERCHANT_CATEGORIES

TXN_SEGMENTS = {
    # name: (weight, is_fraud)
    "routine": (0.62, 0),
    "traveller": (0.06, 0),
    "new_phone": (0.05, 0),
    "big_purchase": (0.07, 0),
    "night_owl": (0.06, 0),
    "new_payee": (0.08, 0),
    "risky_but_legit": (0.015, 0),
    "ato": (0.012, 1),
    "mule": (0.010, 1),
    "deepfake_onboarding": (0.006, 1),
    "card_testing": (0.008, 1),
    "app_scam": (0.009, 1),
}


def _pick(rng, items, p=None):
    return items[rng.choice(len(items), p=p)]


def _base(rng) -> dict:
    hour = float(np.clip(rng.normal(14, 4), 6, 23.5))
    amount_typ = float(np.exp(rng.normal(7.3, 0.9)))  # ~ INR 1,500 typical
    return {
        "amount": amount_typ * float(np.exp(rng.normal(0, 0.5))),
        "amount_deviation": float(rng.normal(0, 1)),
        "amount_to_balance": float(np.clip(rng.beta(1.2, 12), 0, 1)),
        "velocity_1h": int(rng.poisson(0.3)),
        "velocity_24h": int(rng.poisson(2.5)),
        "spend_24h_ratio": float(np.clip(rng.lognormal(0, 0.5), 0, 50)),
        "merchant_category": _pick(rng, MERCHANT_CATEGORIES, [0.25, 0.12, 0.15, 0.18, 0.05, 0.04, 0.03, 0.005, 0.15, 0.025]),
        "channel": _pick(rng, CHANNELS, [0.5, 0.12, 0.05, 0.25, 0.08]),
        "hour": hour,
        "device_age_days": float(rng.gamma(2.0, 200)),
        "is_new_device": 0,
        "device_shared_customers": int(rng.random() < 0.04),  # household/shared tablet
        "ip_risk": float(np.clip(rng.beta(1.2, 18), 0, 1)),
        "geo_distance_km": float(np.abs(rng.normal(0, 8))),
        "beneficiary_new": int(rng.random() < 0.06),
        "beneficiary_inbound_senders": int(rng.poisson(1.2)),
        "account_age_days": float(rng.gamma(2.5, 500)),
        "secs_since_login": float(rng.lognormal(5.5, 1.0)),
        "failed_logins_24h": int(rng.random() < 0.08) * int(rng.integers(1, 3)),
        "mfa_changes_24h": int(rng.random() < 0.004),
        "kyc_risk": float(np.clip(rng.beta(1.2, 20), 0, 1)),
        "deepfake_risk": float(np.clip(rng.beta(1.0, 30), 0, 1)),
        "network_risk": float(np.clip(rng.beta(1.0, 25), 0, 1)),
        "behavior_anomaly": float(np.clip(rng.beta(2, 9), 0, 1)),
        "graph_risk": float(np.clip(rng.beta(1.2, 20), 0, 1)),
    }


def _apply(rng, seg: str, r: dict) -> dict:
    u = rng.random
    if seg == "traveller":
        r["geo_distance_km"] = float(rng.uniform(300, 6000))
        r["ip_risk"] = float(np.clip(rng.beta(2, 10), 0, 1))
        r["behavior_anomaly"] = float(np.clip(rng.beta(3, 5), 0, 1))
        r["hour"] = float(rng.uniform(0, 24))
    elif seg == "new_phone":
        r["is_new_device"] = 1
        r["device_age_days"] = float(rng.uniform(0, 2))
        r["mfa_changes_24h"] = int(u() < 0.35)
        r["behavior_anomaly"] = float(np.clip(rng.beta(3, 6), 0, 1))
    elif seg == "big_purchase":
        r["amount"] *= float(rng.uniform(5, 30))
        r["amount_deviation"] = float(rng.uniform(3, 12))
        r["amount_to_balance"] = float(rng.uniform(0.2, 0.9))
        r["merchant_category"] = _pick(rng, ["electronics", "travel", "retail"])
    elif seg == "night_owl":
        r["hour"] = float(rng.uniform(0, 5))
        r["behavior_anomaly"] = float(np.clip(rng.beta(2, 6), 0, 1))
    elif seg == "new_payee":
        r["beneficiary_new"] = 1
        r["merchant_category"] = "p2p_transfer"
        r["amount"] *= float(rng.uniform(1, 6))
        r["amount_deviation"] = float(rng.uniform(0, 4))
    elif seg == "risky_but_legit":  # hard negatives: several weak signals at once
        r["is_new_device"] = int(u() < 0.6)
        r["device_age_days"] = 0.5 if r["is_new_device"] else r["device_age_days"]
        r["beneficiary_new"] = int(u() < 0.6)
        r["hour"] = float(rng.uniform(0, 6)) if u() < 0.5 else r["hour"]
        r["amount_deviation"] = float(rng.uniform(1, 6))
        r["ip_risk"] = float(rng.uniform(0.1, 0.5))
        r["geo_distance_km"] = float(rng.uniform(50, 2000))
    elif seg == "ato":
        r["is_new_device"] = int(u() < 0.85)
        r["device_age_days"] = float(rng.uniform(0, 1)) if r["is_new_device"] else r["device_age_days"]
        r["ip_risk"] = float(np.clip(rng.beta(4, 3), 0, 1)) if u() < 0.75 else r["ip_risk"]
        r["geo_distance_km"] = float(rng.uniform(200, 3000)) if u() < 0.7 else r["geo_distance_km"]
        r["mfa_changes_24h"] = int(u() < 0.55)
        r["failed_logins_24h"] = int(rng.integers(0, 8)) if u() < 0.5 else 0
        r["beneficiary_new"] = int(u() < 0.85)
        r["amount"] *= float(rng.uniform(3, 40))
        r["amount_deviation"] = float(rng.uniform(2, 15))
        r["amount_to_balance"] = float(rng.uniform(0.4, 1.0))
        r["hour"] = float(rng.uniform(0, 5)) if u() < 0.55 else r["hour"]
        r["secs_since_login"] = float(rng.uniform(30, 400))
        r["merchant_category"] = _pick(rng, ["p2p_transfer", "crypto", "electronics"], [0.7, 0.2, 0.1])
        r["channel"] = _pick(rng, ["imps", "upi", "neft"])
        r["behavior_anomaly"] = float(np.clip(rng.beta(6, 3), 0, 1))
        r["network_risk"] = float(np.clip(rng.beta(3, 4), 0, 1)) if u() < 0.4 else r["network_risk"]
        r["kyc_risk"] = float(np.clip(rng.beta(4, 3), 0, 1)) if u() < 0.25 else r["kyc_risk"]
        r["deepfake_risk"] = float(np.clip(rng.beta(6, 2), 0, 1)) if u() < 0.2 else r["deepfake_risk"]
        r["graph_risk"] = float(np.clip(rng.beta(3, 4), 0, 1)) if u() < 0.4 else r["graph_risk"]
    elif seg == "mule":
        r["beneficiary_inbound_senders"] = int(rng.integers(4, 30))
        r["beneficiary_new"] = int(u() < 0.7)
        r["device_shared_customers"] = int(rng.integers(1, 6)) if u() < 0.5 else 0
        r["amount"] *= float(rng.uniform(1, 8))
        r["amount_deviation"] = float(rng.uniform(0, 6))
        r["velocity_24h"] = int(rng.integers(3, 15))
        r["account_age_days"] = float(rng.uniform(5, 120)) if u() < 0.6 else r["account_age_days"]
        r["merchant_category"] = "p2p_transfer"
        r["graph_risk"] = float(np.clip(rng.beta(5, 3), 0, 1)) if u() < 0.7 else r["graph_risk"]
    elif seg == "deepfake_onboarding":
        r["account_age_days"] = float(rng.uniform(0, 20))
        r["kyc_risk"] = float(np.clip(rng.beta(5, 2), 0, 1))
        r["deepfake_risk"] = float(np.clip(rng.beta(7, 2), 0, 1)) if u() < 0.8 else r["deepfake_risk"]
        r["is_new_device"] = int(u() < 0.5)
        r["beneficiary_new"] = int(u() < 0.8)
        r["amount"] *= float(rng.uniform(2, 20))
        r["amount_deviation"] = float(rng.uniform(1, 8))
        r["device_shared_customers"] = int(rng.integers(0, 4))
    elif seg == "card_testing":
        r["amount"] = float(rng.uniform(1, 150))
        r["velocity_1h"] = int(rng.integers(5, 30))
        r["velocity_24h"] = int(rng.integers(10, 60))
        r["channel"] = "card"
        r["merchant_category"] = _pick(rng, ["gaming", "electronics", "retail", "crypto"])
        r["ip_risk"] = float(np.clip(rng.beta(3, 3), 0, 1)) if u() < 0.6 else r["ip_risk"]
        r["network_risk"] = float(np.clip(rng.beta(3, 3), 0, 1)) if u() < 0.5 else r["network_risk"]
    elif seg == "app_scam":  # authorised push payment: victim's own device and IP
        r["beneficiary_new"] = 1
        r["amount"] *= float(rng.uniform(5, 50))
        r["amount_deviation"] = float(rng.uniform(3, 20))
        r["amount_to_balance"] = float(rng.uniform(0.5, 1.0))
        r["merchant_category"] = _pick(rng, ["p2p_transfer", "crypto"], [0.8, 0.2])
        r["beneficiary_inbound_senders"] = int(rng.integers(2, 12)) if u() < 0.5 else r["beneficiary_inbound_senders"]
        r["behavior_anomaly"] = float(np.clip(rng.beta(4, 4), 0, 1))
        r["secs_since_login"] = float(rng.lognormal(6.5, 0.7))  # long hesitant session
    return r


def transactions(n: int, seed: int) -> tuple[list[dict], np.ndarray, list[str]]:
    rng = np.random.default_rng(seed)
    names = list(TXN_SEGMENTS)
    weights = np.array([TXN_SEGMENTS[s][0] for s in names])
    weights = weights / weights.sum()
    segs = rng.choice(len(names), size=n, p=weights)
    rows, labels, seg_names = [], [], []
    for i in segs:
        seg = names[i]
        r = _apply(rng, seg, _base(rng))
        r["amount_deviation"] = float(r["amount_deviation"])
        label = TXN_SEGMENTS[seg][1]
        if rng.random() < 0.005:  # label noise (mis-labelled chargebacks / undetected fraud)
            label = 1 - label
        rows.append(r)
        labels.append(label)
        seg_names.append(seg)
    return rows, np.array(labels), seg_names


# ------------------------------------------------------------------ behaviour sessions
BEHAVIOR_FEATURES = [
    "login_hour_deviation",
    "txn_frequency_ratio",
    "amount_deviation",
    "location_deviation_km",
    "device_change",
    "ip_change",
    "session_duration_ratio",
    "navigation_speed_ratio",
    "failed_logins",
    "days_since_last_login",
]


def behavior_sessions(n_normal: int, n_anomalous: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Rows are already *relative to the customer's own baseline*."""
    rng = np.random.default_rng(seed)

    def normal(k):
        return np.column_stack([
            # hours from typical login hour: mostly near habit, but genuine customers also
            # bank late in the evening / early morning (30% spread over the day)
            np.where(rng.random(k) < 0.7, np.abs(rng.normal(0, 1.5, k)), rng.uniform(0, 10, k)),
            rng.lognormal(0, 0.35, k),
            np.abs(rng.normal(0, 1, k)),
            np.log1p(np.abs(rng.normal(0, 10, k)) * (1 + 40 * (rng.random(k) < 0.05))),
            (rng.random(k) < 0.05).astype(float),
            (rng.random(k) < 0.2).astype(float),
            rng.lognormal(0, 0.4, k),
            rng.lognormal(0, 0.3, k),
            (rng.random(k) < 0.07) * rng.integers(1, 3, k),
            rng.gamma(1.5, 2, k),
        ])

    def anomalous(k):
        x = normal(k)
        # each anomalous session perturbs a random subset of 2-5 dimensions
        for row in x:
            dims = rng.choice(len(BEHAVIOR_FEATURES), size=rng.integers(2, 6), replace=False)
            for d in dims:
                if d == 0:
                    row[d] = rng.uniform(5, 12)
                elif d == 1:
                    row[d] = rng.uniform(3, 15)
                elif d == 2:
                    row[d] = rng.uniform(4, 15)
                elif d == 3:
                    row[d] = np.log1p(rng.uniform(300, 5000))
                elif d in (4, 5):
                    row[d] = 1.0
                elif d == 6:
                    row[d] = rng.choice([rng.uniform(0.05, 0.25), rng.uniform(4, 10)])
                elif d == 7:
                    row[d] = rng.uniform(3, 8)  # scripted / remote-access navigation
                elif d == 8:
                    row[d] = rng.integers(3, 12)
                elif d == 9:
                    row[d] = rng.uniform(60, 400)
        return x

    X = np.vstack([normal(n_normal), anomalous(n_anomalous)])
    y = np.concatenate([np.zeros(n_normal), np.ones(n_anomalous)])
    return X, y


# ------------------------------------------------------------------ network flows (Zeek conn.log shape)
def normal_flows(n: int, seed: int) -> list[dict]:
    """Benign client traffic: HTTPS browsing/API calls, DNS, occasional bulk downloads."""
    rng = np.random.default_rng(seed)
    out = []
    for _ in range(n):
        kind = rng.choice(["https", "dns", "download", "api", "http"], p=[0.5, 0.25, 0.05, 0.15, 0.05])
        if kind == "dns":
            out.append(dict(bytes_out=int(rng.integers(30, 80)), bytes_in=int(rng.integers(60, 300)), duration=float(rng.uniform(0.001, 0.08)),
                            pkts_out=1, pkts_in=1, dst_port=53, conn_state="SF", proto="udp"))
        elif kind == "download":
            bi = int(rng.lognormal(15, 1.2))
            out.append(dict(bytes_out=int(rng.lognormal(8, 0.8)), bytes_in=bi, duration=float(rng.lognormal(2, 1)),
                            pkts_out=int(bi / 20000) + 5, pkts_in=int(bi / 1400) + 5, dst_port=443, conn_state="SF", proto="tcp"))
        else:
            bo = int(rng.lognormal(7, 1.0))
            bi = int(rng.lognormal(9, 1.3))
            out.append(dict(bytes_out=bo, bytes_in=bi, duration=float(rng.lognormal(0, 1.2)), pkts_out=int(bo / 900) + 3,
                            pkts_in=int(bi / 1300) + 3, dst_port=int(rng.choice([443, 443, 443, 80, 8443])) if kind != "http" else 80,
                            conn_state=str(rng.choice(["SF", "SF", "SF", "SF", "S1", "RSTO"])), proto="tcp"))
    return out
