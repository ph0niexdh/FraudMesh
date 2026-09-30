"""Cross-channel correlation and case engine tests."""
from datetime import timedelta

from sqlalchemy import select

from app.database.db import session_scope
from app.database.models import AuditLog, CaseEvent, FraudCase
from app.schemas.events import EventIn
from app.utils.timeutil import utcnow
from conftest import build_history, unique, unique_digits, unique_ip


def _setup_parties(engine):
    tag = unique("")
    victim = dict(customer=f"CUSTOMER_V{tag}", account=f"SBI-DEMO-{unique_digits(5)}", bank="SBI",
                  device=f"DEVICE-{tag[:4]}", ip=unique_ip())
    mule1 = dict(customer=f"CUSTOMER_M{tag}", account=f"HDFC-DEMO-{unique_digits(5)}", bank="HDFC Bank",
                 device=f"DEVICE-{tag[2:6]}", ip=unique_ip())
    mule2 = dict(customer=f"CUSTOMER_N{tag}", account=f"ICICI-DEMO-{unique_digits(5)}", bank="ICICI Bank",
                 device=f"DEVICE-{tag[1:5]}", ip=unique_ip())
    for p in (victim, mule1, mule2):
        build_history(engine, p["customer"], p["account"], p["bank"], p["device"], p["ip"])
    return victim, mule1, mule2, f"DEVICE-{tag[3:6]}F", unique_ip()


def test_seven_weak_signals_create_one_correlated_case(engine):
    """NEW_DEVICE + NEW_IP + MFA_RESET + KYC_ANOMALY + HIGH_VALUE_TRANSACTION + DEVICE_REUSE + CLOUD_ANOMALY
    must produce exactly ONE fraud case containing every event."""
    v, m1, m2, atk_dev, atk_ip = _setup_parties(engine)
    t0 = utcnow() - timedelta(minutes=12)
    vic = dict(customer_id=v["customer"], account_id=v["account"], bank_name=v["bank"])
    events = [
        EventIn(event_type="login", timestamp=t0, device_id=atk_dev, ip_address=v["ip"],
                metadata={"city": "Mumbai", "subtype": "NEW_DEVICE"}, **vic),
        EventIn(event_type="login", timestamp=t0 + timedelta(minutes=1), device_id=atk_dev, ip_address=atk_ip,
                metadata={"city": "Kolkata", "subtype": "NEW_IP"}, **vic),
        EventIn(event_type="mfa_reset", timestamp=t0 + timedelta(minutes=2), device_id=atk_dev, ip_address=atk_ip,
                metadata={"city": "Kolkata", "password_changed": True}, **vic),
        EventIn(event_type="kyc_verification", timestamp=t0 + timedelta(minutes=4), device_id=atk_dev,
                ip_address=atk_ip, metadata={"demo_manipulation_score": 0.91, "city": "Kolkata"}, **vic),
        EventIn(event_type="transaction", timestamp=t0 + timedelta(minutes=6), device_id=atk_dev, ip_address=atk_ip,
                amount=185_000, metadata={"beneficiary_account": m1["account"], "city": "Kolkata"}, **vic),
        EventIn(event_type="login", timestamp=t0 + timedelta(minutes=7), customer_id=m1["customer"],
                account_id=m1["account"], bank_name=m1["bank"], device_id=atk_dev, ip_address=atk_ip,
                metadata={"subtype": "DEVICE_REUSE"}),
        EventIn(event_type="login", timestamp=t0 + timedelta(minutes=8), customer_id=m2["customer"],
                account_id=m2["account"], bank_name=m2["bank"], device_id=atk_dev, ip_address=atk_ip,
                metadata={"subtype": "CROSS_BANK_LINK"}),
        EventIn(event_type="cloud_event", timestamp=t0 + timedelta(minutes=9), ip_address=atk_ip, channel="cloud",
                metadata={"action": "PRIVILEGED_API_CALL", "region": "eu-central-1", "privileged": True,
                          "new_access_key": True, "principal": "svc-test-principal"}),
    ]
    results = [engine.process_event(e) for e in events]
    case_ids = {r["event"]["case_id"] for r in results if r["event"]["case_id"]}
    assert len(case_ids) == 1, f"expected one correlated case, got {case_ids}"
    case_id = case_ids.pop()
    # every event after correlation began belongs to the case (earlier ones were pulled in on creation)
    with session_scope() as s:
        linked = set(s.scalars(select(CaseEvent.event_id).where(CaseEvent.case_id == case_id)))
        case = s.get(FraudCase, case_id)
        assert {r["event"]["event_id"] for r in results} <= linked
        assert case.risk_score >= 80
        assert case.severity == "CRITICAL"
        assert case.policy_action == "BLOCK_HOLD_INVESTIGATE"
        assert case.status == "HOLD"
        assert set(case.banks) == {"SBI", "HDFC Bank", "ICICI Bank"}
        cs = case.channel_scores
        assert all(cs[c] > 0.5 for c in ("transaction", "takeover", "kyc", "cloud", "graph", "temporal"))
        signals = {e["signal"] for e in case.explanations}
        assert {"amount_deviation", "kyc_manipulation", "device_reuse", "cross_bank_link",
                "privileged_api_call"} <= signals
        assert {"new_device", "new_ip", "mfa_reset"} & signals
        # explanation points per channel never exceed that channel's exact contribution
        for ch, pts in case.contributions.items():
            assert sum(e["contribution"] for e in case.explanations if e["channel"] == ch) <= pts + 0.1
        actions = set(s.scalars(select(AuditLog.action).where(AuditLog.entity_id == case_id)))
        assert {"case.created", "case.score_updated", "policy.triggered"} <= actions
    # risk increased monotonically as evidence arrived
    risks = [r["case"]["risk_score"] for r in results if r["case"]]
    assert risks == sorted(risks)


def test_single_weak_signal_does_not_create_case(engine):
    v, *_ = _setup_parties(engine)
    res = engine.process_event(EventIn(event_type="login", customer_id=v["customer"], account_id=v["account"],
                                       bank_name="SBI", device_id=f"DEVICE-{unique('')[:4]}", ip_address=v["ip"],
                                       metadata={"city": "Mumbai"}))
    assert res["event"]["case_id"] is None and res["case"] is None


def test_unrelated_suspicious_events_are_not_merged(engine):
    a, *_ = _setup_parties(engine)
    b, *_ = _setup_parties(engine)
    now = utcnow()
    r1 = engine.process_event(EventIn(event_type="kyc_verification", timestamp=now, customer_id=a["customer"],
                                      account_id=a["account"], bank_name="SBI",
                                      metadata={"demo_manipulation_score": 0.9}))
    r2 = engine.process_event(EventIn(event_type="kyc_verification", timestamp=now, customer_id=b["customer"],
                                      account_id=b["account"], bank_name="SBI",
                                      metadata={"demo_manipulation_score": 0.9}))
    assert r1["case"] is None and r2["case"] is None  # one weak signal each, no shared entities


def test_events_outside_temporal_window_start_a_new_case(engine):
    v, *_ = _setup_parties(engine)
    base = dict(customer_id=v["customer"], account_id=v["account"], bank_name="SBI")
    old = utcnow() - timedelta(hours=3)
    engine.process_event(EventIn(event_type="kyc_verification", timestamp=old, metadata={"demo_manipulation_score": 0.9},
                                 **base))
    r = engine.process_event(EventIn(event_type="mfa_reset", timestamp=old + timedelta(minutes=40),
                                     device_id=f"DEVICE-{unique('')[:4]}", ip_address=unique_ip(), **base))
    assert r["case"] is None  # 40 min apart > 15 min window → not correlated


def test_analyst_feedback_updates_status_and_learns(engine):
    v, m1, m2, atk_dev, atk_ip = _setup_parties(engine)
    now = utcnow() - timedelta(minutes=5)
    base = dict(customer_id=v["customer"], account_id=v["account"], bank_name="SBI", device_id=atk_dev,
                ip_address=atk_ip)
    engine.process_event(EventIn(event_type="login", timestamp=now, metadata={"city": "Kolkata"}, **base))
    engine.process_event(EventIn(event_type="mfa_reset", timestamp=now + timedelta(minutes=1),
                                 metadata={"city": "Kolkata"}, **base))
    r = engine.process_event(EventIn(event_type="kyc_verification", timestamp=now + timedelta(minutes=2),
                                     metadata={"demo_manipulation_score": 0.9}, **base))
    case_id = r["event"]["case_id"]
    assert case_id
    from app.schemas.cases import FeedbackIn

    out = engine.apply_feedback(case_id, FeedbackIn(action="CONFIRM_FRAUD", analyst="tester", notes="confirmed"))
    assert out["case"]["status"] == "CONFIRMED_FRAUD"
    assert out["learning"]["effect"] == "watchlist"
    from app.privacy.tokenizer import tokenize

    assert engine.graph.g.nodes[tokenize("device", atk_dev)]["watchlist"] is True
