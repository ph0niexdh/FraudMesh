"""Unit tests for fusion, policy, temporal sequences, graph propagation, MRZ, intel, privacy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from fraudmesh.core import privacy
from fraudmesh.services.correlation import temporal
from fraudmesh.services.fusion import engine as fusion
from fraudmesh.services.graph import risk as graph_risk
from fraudmesh.services.ids import intel
from fraudmesh.services.kyc import mrz
from fraudmesh.services.policy import engine as policy

DOMS = ["transaction", "behavior", "identity", "deepfake", "device", "graph", "network", "temporal"]


def _inputs(**risks):
    return {d: fusion.DomainInput(d, r, 0.8, f"{d}-det", []) for d, r in risks.items()}


def test_fusion_spec_example_is_critical():
    out = fusion.fuse(_inputs(transaction=82, behavior=71, deepfake=96, device=89, graph=91, network=74))
    assert out["attack_score"] >= 95 and out["risk_level"] == "CRITICAL"
    assert abs(sum(c["share"] for c in out["contributions"]) - 1.0) < 0.01


def test_fusion_is_not_an_average_single_noisy_signal_stays_low():
    assert fusion.fuse(_inputs(behavior=85))["attack_score"] < 20
    assert fusion.fuse(_inputs(device=80))["attack_score"] < 20


def test_fusion_corroboration_compounds():
    one = fusion.fuse(_inputs(identity=75))["attack_score"]
    two = fusion.fuse(_inputs(identity=75, transaction=75))["attack_score"]
    assert two > one + 15


@pytest.mark.parametrize("domain", DOMS)
def test_fusion_is_monotone_in_every_domain(domain):
    base = {d: 40.0 for d in DOMS}
    lo = fusion.fuse(_inputs(**base))["attack_score"]
    hi = fusion.fuse(_inputs(**{**base, domain: 90.0}))["attack_score"]
    assert hi >= lo


def test_fusion_evidence_floor_for_high_precision_detector():
    out = fusion.fuse(_inputs(deepfake=97))
    assert out["evidence_floor"]["applied"] and out["attack_score"] >= 80


def test_fusion_counterfactual_override_removes_domain():
    inp = _inputs(deepfake=96, identity=80)
    assert fusion.fuse(inp, {"deepfake": None})["attack_score"] < fusion.fuse(inp)["attack_score"]


def test_policy_matrix():
    pols = [dict(p, enabled=p.get("enabled", True)) for p in policy.DEFAULT_POLICIES]
    assert policy.evaluate(pols, {"risk_level": "CRITICAL", "attack_score": 97})["action"] == "BLOCK"
    assert policy.evaluate(pols, {"risk_level": "LOW", "attack_score": 5, "event_type": "TRANSACTION"})["action"] == "ALLOW"
    assert policy.evaluate(pols, {"risk_level": "MEDIUM", "attack_score": 50, "deepfake_risk": 92})["action"] == "HOLD"
    held = policy.evaluate(pols, {"risk_level": "HIGH", "attack_score": 70, "amount": 150000, "event_type": "TRANSACTION"})
    assert held["action"] == "HOLD" and len(held["matched"]) >= 2
    assert policy.evaluate(pols, {"risk_level": "HIGH", "attack_score": 75, "attack_type": "CLOUD_COMPROMISE"})["action"] == "BLOCK"


def test_policy_validation_rejects_bad_conditions():
    with pytest.raises(policy.PolicyError):
        policy.validate_conditions([{"field": "nope", "op": "gte", "value": 1}])
    with pytest.raises(policy.PolicyError):
        policy.validate_conditions([{"field": "amount", "op": "gte", "value": "lots"}])
    with pytest.raises(policy.PolicyError):
        policy.validate_conditions([])


def _ev(i, et, p=None, ctx=None, risk=60):
    t = datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc)
    return {"id": f"e{i}", "ts": t + timedelta(minutes=i), "event_type": et, "payload": p or {}, "ctx": ctx or {}, "risk_score": risk, "reason_codes": []}


def test_temporal_recognises_ato_with_deepfake():
    evs = [_ev(0, "LOGIN", {"success": True}, {"is_new_device": True}), _ev(2, "MFA", {"action": "reset"}),
           _ev(4, "KYC", {}, {"deepfake_risk": 0.95}, 90), _ev(7, "BENEFICIARY", {"action": "added"}), _ev(10, "TRANSACTION", {"amount": 185000})]
    res, best = temporal.analyze(evs)
    assert best["pattern"] == "ATO_DEEPFAKE" and res.risk_score > 80


def test_temporal_requires_defining_stage():
    evs = [_ev(0, "LOGIN", {"success": True}, {"is_new_device": True}), _ev(1, "TRANSACTION", {"amount": 64000}),
           _ev(2, "LOGIN", {"success": True}), _ev(3, "TRANSACTION", {"amount": 71000})]
    _, best = temporal.analyze(evs)
    assert best is None or best["pattern"] != "DEEPFAKE_KYC"


def test_temporal_span_limit():
    evs = [_ev(0, "LOGIN", {"success": True}, {"is_new_device": True}), _ev(200, "MFA", {"action": "reset"})]
    _, best = temporal.analyze(evs)
    assert best is None or best["pattern"] not in ("ATO", "ATO_DEEPFAKE")


def test_graph_propagation_is_controlled():
    nodes = [{"id": "dev", "type": "Device", "flagged": True, "risk": 0.9}, {"id": "acc", "type": "Account", "risk": 0},
             {"id": "cust", "type": "Customer", "risk": 0}, {"id": "other", "type": "Account", "risk": 0}]
    edges = [{"src": "cust", "dst": "dev", "type": "USES", "confidence": 0.9}, {"src": "cust", "dst": "acc", "type": "OWNS", "confidence": 1.0},
             {"src": "acc", "dst": "other", "type": "SENT_TO", "confidence": 1.0}]
    p = graph_risk.propagate(nodes, edges)
    assert p["cust"]["risk"] > p["acc"]["risk"] > p["other"]["risk"]
    assert p["cust"]["risk"] < 0.9  # never exceeds the seed
    assert p["other"]["risk"] < 0.5  # third-degree entity is not marked fraudulent


def test_graph_event_risk_is_not_a_seed_and_case_nodes_ignored():
    nodes = [{"id": "doc", "type": "KYCDocument", "risk": 0.9}, {"id": "case:x", "type": "Case", "risk": 1.0, "flagged": True},
             {"id": "cust", "type": "Customer", "risk": 0}]
    edges = [{"src": "cust", "dst": "doc", "type": "VERIFIED_BY", "confidence": 0.95}, {"src": "case:x", "dst": "cust", "type": "ASSOCIATED_WITH", "confidence": 0.9}]
    assert graph_risk.propagate(nodes, edges) == {}


def test_graph_time_decay():
    old = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    nodes = [{"id": "dev", "type": "Device", "flagged": True, "risk": 0.9}, {"id": "cust", "type": "Customer", "risk": 0}]
    fresh = graph_risk.propagate(nodes, [{"src": "cust", "dst": "dev", "type": "USES", "confidence": 0.9}])
    stale = graph_risk.propagate(nodes, [{"src": "cust", "dst": "dev", "type": "USES", "confidence": 0.9, "last_seen": old}])
    assert stale["cust"]["risk"] < fresh["cust"]["risk"] / 4


def test_mrz_check_digits_icao_example():
    assert mrz.check_digit("L898902C3") == "6"  # ICAO Doc 9303 specimen
    assert mrz.check_digit("740812") == "2"


def test_mrz_td1_parse_with_ocr_confusion():
    lines = ["IDDMODM48271937<<<<<<<<<<<<<<<", "8403124F3108309DM0<<<<<<<<<<<8", "DEMO<<AVA<<<<<<<<<<<<<<<<<<<<<"]
    r = mrz.parse(lines)
    assert r["valid"] and r["date_of_birth"] == "1984-03-12" and r["nationality"] == "DMO" and r["surname"] == "DEMO"


def test_intel_and_dga():
    assert intel.ip_reputation("203.0.113.5")["category"] == "known_malicious"
    assert intel.ip_reputation("100.64.3.3")["category"] == "residential_isp"
    assert intel.dga_score("x7kq9zv2mtr8wplq4n.example.com") > 0.5
    assert intel.dga_score("www.google.com") < 0.3
    assert intel.user_agent("OpenBullet/1.4")["risk"] > 0.9


def test_privacy_masking():
    assert privacy.mask_phone("+91 9876501234") == "+91 ******1234"
    assert privacy.mask_email("asha.verma@mail.example").startswith("a") and "asha" not in privacy.mask_email("asha.verma@mail.example")
    assert privacy.mask_account("123456789012") == "XXXX9012"
