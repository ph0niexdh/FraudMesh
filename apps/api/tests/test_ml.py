"""ML inference tests: trained transaction, behaviour and network models."""

from __future__ import annotations

import time

from fraudmesh.services.behavior.detector import behavior_detector
from fraudmesh.services.ids.detector import network_detector
from fraudmesh.services.ids.telemetry import parse
from fraudmesh.services.transaction.detector import transaction_detector

NORMAL = {"amount": 1800, "amount_deviation": 0.2, "velocity_24h": 2, "hour": 13, "device_age_days": 400, "ip_risk": 0.03, "geo_distance_km": 4,
          "account_age_days": 1500, "secs_since_login": 300, "merchant_category": "grocery", "channel": "upi", "graph_risk": 0.02}
ATO = {"amount": 185000, "amount_deviation": 11, "amount_to_balance": 0.9, "hour": 2.3, "device_age_days": 0, "is_new_device": True, "ip_risk": 0.8,
       "geo_distance_km": 1450, "beneficiary_new": True, "beneficiary_inbound_senders": 3, "account_age_days": 1500, "secs_since_login": 120,
       "mfa_changes_24h": 1, "merchant_category": "p2p_transfer", "channel": "imps", "behavior_anomaly": 0.8, "graph_risk": 0.6}


def test_transaction_model_separates_and_explains():
    lo, hi = transaction_detector.score(NORMAL), transaction_detector.score(ATO)
    assert lo.risk_score < 10 < 90 < hi.risk_score
    shap_rows = hi.metadata["shap"]
    assert "base_value_logodds" in shap_rows[0] and len(shap_rows) > 3
    assert any(r["shap"] > 0 for r in shap_rows[1:])
    assert hi.model_version.startswith(("lightgbm", "xgboost"))


def test_transaction_model_latency():
    transaction_detector.score(NORMAL)
    t = time.perf_counter()
    for _ in range(20):
        transaction_detector.score(NORMAL)
    assert (time.perf_counter() - t) / 20 < 0.1


def test_transaction_calibration_monotone():
    import numpy as np

    xs = np.linspace(0, 1, 50)
    ys = transaction_detector.calibrate(xs)
    assert all(b >= a - 1e-9 for a, b in zip(ys, ys[1:]))


def test_behavior_model():
    base = {"login_hour_deviation": 1, "txn_frequency_ratio": 1, "amount_deviation": 0.4, "location_deviation_km": 1.5, "device_change": 0, "ip_change": 0,
            "session_duration_ratio": 1, "navigation_speed_ratio": 1, "failed_logins": 0, "days_since_last_login": 1}
    assert behavior_detector.score(base).risk_score < 20
    odd = behavior_detector.score({**base, "device_change": 1, "ip_change": 1, "location_deviation_km": 7.3, "navigation_speed_ratio": 4, "amount_deviation": 11})
    assert odd.risk_score > 80 and odd.reason_codes


async def test_ids_benign_vs_scan(app):
    now = time.time()
    benign = parse({"ts": now, "uid": "C1", "id.orig_h": "100.64.12.7", "id.orig_p": 51000, "id.resp_h": "10.0.0.5", "id.resp_p": 443, "proto": "tcp",
                    "duration": 1.2, "orig_bytes": 1800, "resp_bytes": 24000, "orig_pkts": 12, "resp_pkts": 22, "conn_state": "SF"}, log_type="conn")
    assert (await network_detector.analyze(benign)).risk_score < 30
    last = None
    for port in range(20, 45):
        scan = parse({"ts": now, "uid": f"S{port}", "id.orig_h": "198.51.100.77", "id.orig_p": 40000, "id.resp_h": "10.0.0.5", "id.resp_p": port,
                      "proto": "tcp", "duration": 0.001, "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 1, "resp_pkts": 0, "conn_state": "REJ"}, log_type="conn")
        last = await network_detector.analyze(scan)
    assert any(r.code == "PORT_SCAN" for r in last.reason_codes)


def test_suricata_eve_parsing():
    obs = parse({"timestamp": "2026-10-08T02:21:00Z", "event_type": "alert", "src_ip": "192.0.2.10", "src_port": 1, "dest_ip": "10.0.0.5",
                 "dest_port": 443, "proto": "TCP", "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 1, "category": "x"}})
    assert obs.sensor == "suricata" and obs.signature == "ET TEST" and obs.signature_severity == 1
