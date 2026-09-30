from datetime import timedelta

import pytest
from pydantic import ValidationError

from app.graph.entity_graph import EntityGraph
from app.policies.engine import evaluate
from app.policies.fusion import fuse
from app.schemas.config import FusionConfig, FusionWeights, PolicyConfig, PolicyTier, default_policy
from app.schemas.events import EventType, NormalizedEvent
from app.utils.timeutil import utcnow


# ---------------------------------------------------------------- risk fusion
def test_fusion_matches_documented_formula():
    scores = {"transaction": 0.87, "takeover": 0.92, "kyc": 0.91, "cloud": 0.73, "graph": 0.96, "temporal": 1.0}
    risk, contrib = fuse(scores, FusionConfig())
    expected = 100 * (0.30 * 0.87 + 0.20 * 0.92 + 0.20 * 0.91 + 0.10 * 0.73 + 0.15 * 0.96 + 0.05 * 1.0)
    assert risk == pytest.approx(expected, abs=0.1)
    assert sum(contrib.values()) == pytest.approx(risk, abs=0.1)


def test_fusion_is_clamped_and_configurable():
    heavy = FusionConfig(weights=FusionWeights(transaction=1, takeover=1, kyc=1, cloud=1, graph=1, temporal=1))
    risk, _ = fuse({c: 1.0 for c in ("transaction", "takeover", "kyc", "cloud", "graph", "temporal")}, heavy)
    assert risk == 100.0
    only_txn = FusionConfig(weights=FusionWeights(transaction=1, takeover=0, kyc=0, cloud=0, graph=0, temporal=0))
    assert fuse({"transaction": 0.5, "kyc": 1.0}, only_txn)[0] == 50.0
    assert fuse({}, FusionConfig())[0] == 0.0


# ---------------------------------------------------------------- policy engine
@pytest.mark.parametrize("risk,action,severity", [
    (0, "ALLOW", "LOW"), (29, "ALLOW", "LOW"), (30, "STEP_UP", "MEDIUM"), (59.4, "STEP_UP", "MEDIUM"),
    (60, "HOLD_INVESTIGATE", "HIGH"), (79, "HOLD_INVESTIGATE", "HIGH"), (80, "BLOCK_HOLD_INVESTIGATE", "CRITICAL"),
    (100, "BLOCK_HOLD_INVESTIGATE", "CRITICAL"),
])
def test_default_policy_thresholds(risk, action, severity):
    res = evaluate(risk, default_policy())
    assert res["action"] == action and res["severity"] == severity
    assert {"action", "reason", "policy_id", "threshold"} <= set(res)


def test_policy_thresholds_configurable_and_validated():
    custom = PolicyConfig(tiers=[
        PolicyTier(policy_id="P1", severity="LOW", min_score=0, max_score=49, action="ALLOW"),
        PolicyTier(policy_id="P2", severity="HIGH", min_score=50, max_score=100, action="HOLD_INVESTIGATE"),
    ])
    assert evaluate(55, custom)["policy_id"] == "P2"
    with pytest.raises(ValidationError):  # gap between 49 and 60
        PolicyConfig(tiers=[
            PolicyTier(policy_id="P1", severity="LOW", min_score=0, max_score=49, action="ALLOW"),
            PolicyTier(policy_id="P2", severity="HIGH", min_score=60, max_score=100, action="HOLD_INVESTIGATE"),
        ])


# ---------------------------------------------------------------- graph construction
def _login(eid, cust, acct, bank, dev, ip, ts):
    return NormalizedEvent(event_id=eid, event_type=EventType.login, timestamp=ts, customer_token=cust,
                           account_token=acct, device_token=dev, ip_token=ip, metadata={"bank_name": bank})


def test_graph_builds_entities_and_relationships():
    g = EntityGraph()
    now = utcnow()
    delta = g.add_event(_login("e1", "usr_1", "acc_1", "SBI", "dev_x", "ip_1", now), {"account": "SBI-DEMO-1"})
    assert set(delta["nodes"]) == {"usr_1", "acc_1", "dev_x", "ip_1"}
    rels = {(e["source"], e["relation"], e["target"]) for e in delta["edges"]}
    assert ("usr_1", "OWNS", "acc_1") in rels and ("acc_1", "USED", "dev_x") in rels
    assert ("dev_x", "LOGGED_IN_FROM", "ip_1") in rels
    txn = NormalizedEvent(event_id="t1", event_type=EventType.transaction, timestamp=now, customer_token="usr_1",
                          account_token="acc_1", amount=100, metadata={"beneficiary_token": "acc_2"})
    g.add_event(txn, {})
    assert g.g.has_edge("acc_1", "txn_t1", key="INITIATED") and g.g.has_edge("txn_t1", "acc_2", key="ASSOCIATED_WITH")


def test_graph_detects_cross_bank_device_reuse():
    g = EntityGraph()
    now = utcnow()
    g.add_event(_login("e1", "usr_1", "acc_sbi", "SBI", "dev_x", "ip_1", now), {})
    solo = g.score_entities({"dev_x", "acc_sbi"})
    assert solo["score"] == 0
    g.add_event(_login("e2", "usr_2", "acc_hdfc", "HDFC Bank", "dev_x", "ip_1", now + timedelta(minutes=1)), {})
    g.add_event(_login("e3", "usr_3", "acc_icici", "ICICI Bank", "dev_x", "ip_1", now + timedelta(minutes=2)), {})
    res = g.score_entities({"dev_x"})
    names = {s["name"] for s in res["signals"]}
    assert {"device_reuse", "device_multi_customer", "cross_bank_link"} <= names
    assert res["score"] > 0.9
    assert g.suspicious_paths({"dev_x", "acc_sbi"})


def test_same_person_multiple_banks_is_not_device_reuse():
    g = EntityGraph()
    now = utcnow()
    g.add_event(_login("e1", "usr_1", "acc_sbi", "SBI", "dev_x", "ip_1", now), {})
    g.add_event(_login("e2", "usr_1", "acc_hdfc", "HDFC Bank", "dev_x", "ip_1", now), {})
    assert g.score_entities({"dev_x"})["score"] == 0
