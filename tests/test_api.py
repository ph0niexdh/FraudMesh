"""API endpoint tests (FastAPI TestClient)."""
import io

import cv2
import numpy as np

from conftest import unique, unique_digits, unique_ip

ADMIN = {"X-Admin-Token": "test-admin-token"}


def test_health(client):
    body = client.get("/api/health").json()
    assert body["ready"] is True and body["simulated_data"] is True
    assert "SIMULATED DATA" in body["banner"]


def test_post_event_and_list_with_filters(client):
    acct = f"SBI-DEMO-{unique_digits(5)}"
    r = client.post("/api/events", json={"event_type": "login", "customer_id": "CUSTOMER_API1", "account_id": acct,
                                         "bank_name": "SBI", "device_id": "DEVICE-AAA1", "metadata": {"city": "Pune"}})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["event"]["account_label"] == acct
    assert body["event"]["customer_token"].startswith("usr_")
    assert any(d["detector"] == "behavior_takeover" for d in body["detector_results"])
    listed = client.get("/api/events", params={"account": acct}).json()
    assert listed["total"] == 1 and listed["events"][0]["event_id"] == body["event"]["event_id"]
    assert client.get("/api/events", params={"bank": "SBI", "event_type": "login", "limit": 5}).status_code == 200
    assert client.get(f"/api/events/{body['event']['event_id']}").status_code == 200
    # duplicate id rejected
    dup = client.post("/api/events", json={"event_id": body["event"]["event_id"], "event_type": "login",
                                           "customer_id": "CUSTOMER_API1"})
    assert dup.status_code == 409


def test_validation_errors_do_not_echo_input(client):
    r = client.post("/api/events", json={"event_type": "transaction", "customer_id": "CUSTOMER_X", "amount": -5,
                                         "metadata": {"secret": "hunter2"}})
    assert r.status_code == 422 and "hunter2" not in r.text


def test_batch_and_case_flow(client):
    tag = unique("")
    dev, ip = f"DEVICE-{tag[:4]}", unique_ip()
    base = {"customer_id": f"CUSTOMER_B{tag}", "account_id": f"HDFC-DEMO-{unique_digits(5)}", "bank_name": "HDFC",
            "device_id": dev, "ip_address": ip}
    batch = {"events": [
        {**base, "event_type": "login", "metadata": {"city": "Delhi"}},
        {**base, "event_type": "mfa_reset", "metadata": {"password_changed": True}},
        {**base, "event_type": "kyc_verification", "metadata": {"demo_manipulation_score": 0.92}},
    ]}
    r = client.post("/api/events/batch", json=batch)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["processed"] == 3 and len(body["cases"]) == 1
    case_id = body["cases"][0]

    cases = client.get("/api/cases", params={"status": "active"}).json()["cases"]
    assert any(c["case_id"] == case_id for c in cases)
    detail = client.get(f"/api/cases/{case_id}").json()
    for key in ("case_id", "risk_score", "severity", "status", "created_at", "updated_at", "events", "entities",
                "channel_scores", "graph_score", "temporal_score", "explanations", "policy_action",
                "analyst_feedback", "graph", "risk_history"):
        assert key in detail
    assert len(detail["events"]) == 3 and detail["graph"]["nodes"]

    fb = client.post(f"/api/cases/{case_id}/feedback", json={"action": "HOLD", "analyst": "api-test", "notes": "x"})
    assert fb.status_code == 200 and fb.json()["case"]["status"] == "HOLD"
    fb = client.post(f"/api/cases/{case_id}/feedback", json={"action": "MARK_LEGITIMATE", "analyst": "api-test"})
    assert fb.json()["case"]["status"] == "FALSE_POSITIVE"
    assert len(client.get(f"/api/cases/{case_id}").json()["analyst_feedback"]) == 2
    assert client.get("/api/cases/FM-00000").status_code == 404
    assert client.post(f"/api/cases/{case_id}/feedback", json={"action": "DELETE_EVERYTHING"}).status_code == 422


def test_metrics_models_graph_audit(client):
    m = client.get("/api/metrics").json()
    for key in ("active_cases", "high_risk_cases", "events_per_minute", "cases_today", "confirmed_fraud",
                "false_positives", "average_risk_score"):
        assert key in m
    assert m["total_events"] > 0
    models = client.get("/api/models").json()
    assert {d["name"] for d in models["detectors"]} >= {"transaction_xgboost", "behavior_takeover",
                                                         "kyc_media_demo", "cloud_anomaly", "entity_graph"}
    assert models["privacy"]["pii_tokenization_coverage"] == 1.0
    assert models["privacy"]["raw_kyc_media_retained"] == 0
    assert client.get("/api/graph").status_code == 200
    assert client.get("/api/audit", params={"limit": 5}).json()["entries"]


def test_config_and_policies_require_admin(client):
    cfg = client.get("/api/config").json()
    assert cfg["weights"]["transaction"] == 0.30 and cfg["temporal_window_minutes"] == 15
    new = {**{k: cfg[k] for k in ("weights", "temporal_window_minutes", "suspicious_event_threshold",
                                  "min_correlated_signals", "case_creation_min_risk")}}
    new["weights"] = {**cfg["weights"], "transaction": 0.25, "graph": 0.20}
    assert client.put("/api/config", json=new).status_code == 401
    r = client.put("/api/config", json=new, headers=ADMIN)
    assert r.status_code == 200 and r.json()["weights"]["graph"] == 0.20
    pol = client.get("/api/policies").json()
    tiers = pol["tiers"]
    tiers[1]["min_score"], tiers[0]["max_score"] = 25, 24
    assert client.put("/api/policies", json={"tiers": tiers}, headers=ADMIN).status_code == 200
    tiers[0]["max_score"] = 10  # creates a gap
    assert client.put("/api/policies", json={"tiers": tiers}, headers=ADMIN).status_code == 422
    # restore defaults
    new["weights"] = cfg["weights"]
    client.put("/api/config", json=new, headers=ADMIN)
    tiers[0]["max_score"], tiers[1]["min_score"] = 29, 30
    client.put("/api/policies", json={"tiers": tiers}, headers=ADMIN)


def _png(face_like: bool = False) -> bytes:
    img = np.full((240, 240, 3), 180, np.uint8)
    cv2.circle(img, (120, 120), 60, (90, 120, 200), -1)
    ok, enc = cv2.imencode(".png", img)
    return enc.tobytes()


def test_kyc_upload_validation(client):
    bad = client.post("/api/kyc/analyze", files={"file": ("x.png", b"not an image", "image/png")})
    assert bad.status_code == 422
    exe = client.post("/api/kyc/analyze", files={"file": ("x.exe", b"MZ\x90\x00" * 100, "application/octet-stream")})
    assert exe.status_code == 422
    too_big = client.post("/api/kyc/analyze", files={"file": ("x.png", b"\x89PNG\r\n\x1a\n" + b"0" * (6 * 1024 * 1024),
                                                             "image/png")})
    assert too_big.status_code == 422
    ok = client.post("/api/kyc/analyze", files={"file": ("id.png", _png(), "image/png")},
                     data={"customer_id": "CUSTOMER_KYC1", "bank_name": "SBI", "submit_event": "true"})
    assert ok.status_code == 200, ok.text
    body = ok.json()
    assert body["display_name"] == "Prototype KYC / Media Authenticity Detector"
    assert body["media_retained"] is False and len(body["media_sha256"]) == 64
    assert 0 <= body["detector_result"]["score"] <= 1 and body["event_id"]


def test_demo_endpoints(client):
    sc = client.get("/api/demo/scenarios").json()
    assert {s["name"] for s in sc["scenarios"]} >= {"normal", "unusual_transaction", "account_takeover",
                                                    "synthetic_identity", "kyc_manipulation",
                                                    "coordinated_cross_channel_fraud"}
    assert client.post("/api/demo/reset", json={}).status_code == 401
    assert client.post("/api/demo/simulate", json={"scenario": "nope"}).status_code == 422
