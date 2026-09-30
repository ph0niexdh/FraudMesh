from datetime import timedelta

import numpy as np

from app.detectors.transaction import FEATURES
from app.schemas.events import EventType, NormalizedEvent
from app.services.profiles import CustomerProfile, ProfileStore
from app.utils.timeutil import utcnow

REQUIRED_FIELDS = {"score", "confidence", "signals", "detector", "timestamp"}


def _profile(now):
    prof = CustomerProfile(token="usr_0000000001", home_city="Mumbai", typical_hour=now.hour)
    prof.last_location = ((19.076, 72.8777), now - timedelta(minutes=30))
    prof.amounts.extend([28_000, 31_000, 30_000, 33_000, 29_500, 27_000, 32_000] * 3)
    prof.devices.add("dev_000000000a")
    prof.ips.add("ip_000000000a")
    prof.beneficiaries.add("ben_000000000a")
    prof.merchants.add("SYN-GROCERY-01")
    prof.history_events = 30
    for d in range(1, 15):
        prof.txn_times.append(now - timedelta(days=d))
        prof.login_hours.append(now.hour)
    return prof


def _txn(amount, now, **md):
    return NormalizedEvent(event_id="t1", event_type=EventType.transaction, timestamp=now,
                           customer_token="usr_0000000001", device_token=md.pop("device", "dev_000000000a"),
                           ip_token="ip_000000000a", amount=amount, metadata={"city": "Mumbai", **md})


def test_transaction_detector_scores_anomaly_higher(engine):
    now = utcnow()
    prof = _profile(now)
    normal = engine.txn.detect(_txn(30_000, now, merchant="SYN-GROCERY-01"), prof)
    fraud = engine.txn.detect(_txn(185_000, now, beneficiary_token="ben_ffffffffff", device="dev_ffffffffff",
                                   city="Kolkata"), prof)
    assert REQUIRED_FIELDS <= set(normal.model_dump())
    assert normal.detector == "transaction_xgboost"
    assert fraud.score > 0.8 > normal.score
    assert fraud.score > normal.score + 0.5
    assert {"amount_deviation", "new_beneficiary", "new_device"} <= set(fraud.signals)
    assert 0 <= fraud.confidence <= 1
    assert fraud.details["features"]["amount_ratio"] > 5


def test_transaction_shap_values_are_real_tree_shap(engine):
    """SHAP contributions + base value must reproduce the model's log-odds (no invented values)."""
    now = utcnow()
    res = engine.txn.detect(_txn(150_000, now, beneficiary_token="ben_ffffffffff"), _profile(now))
    shap_vals = res.details["shap_values"]
    assert set(shap_vals) == set(FEATURES)
    base = res.details["shap_base_value"]
    p = res.details["probability"]
    logit = np.log(p / (1 - p))
    assert abs(base + sum(shap_vals.values()) - logit) < 0.05


def test_transaction_model_evaluation_is_measured(engine):
    ev = engine.txn.evaluation
    assert "synthetic" in ev["dataset"]
    for k in ("precision", "recall", "f1", "pr_auc", "false_positive_rate"):
        assert 0 <= ev[k] <= 1


def test_behavior_detector_accumulates_takeover_signals(engine):
    now = utcnow()
    prof = _profile(now)
    store = ProfileStore()
    store.customers[prof.token] = prof
    base = dict(customer_token="usr_0000000001", metadata={"city": "Mumbai"})
    normal = engine.behavior.detect(NormalizedEvent(event_id="l0", event_type=EventType.login, timestamp=now,
                                                    device_token="dev_000000000a", ip_token="ip_000000000a", **base),
                                    prof)
    new_dev = NormalizedEvent(event_id="l1", event_type=EventType.login, timestamp=now + timedelta(minutes=1),
                              device_token="dev_ffffffffff", ip_token="ip_000000000a", **base)
    r1 = engine.behavior.detect(new_dev, prof)
    store.update(new_dev, trusted=False, signals=set(r1.details["current_event_signals"]))
    new_ip = NormalizedEvent(event_id="l2", event_type=EventType.login, timestamp=now + timedelta(minutes=2),
                             device_token="dev_ffffffffff", ip_token="ip_ffffffffff", customer_token="usr_0000000001",
                             metadata={"city": "Kolkata"})
    r2 = engine.behavior.detect(new_ip, prof)
    store.update(new_ip, trusted=False, signals=set(r2.details["current_event_signals"]))
    mfa = NormalizedEvent(event_id="l3", event_type=EventType.mfa_reset, timestamp=now + timedelta(minutes=3),
                          device_token="dev_ffffffffff", ip_token="ip_ffffffffff", customer_token="usr_0000000001",
                          metadata={"city": "Kolkata", "password_changed": True})
    r3 = engine.behavior.detect(mfa, prof)
    assert normal.score < 0.3
    assert "new_device" in r1.signals
    assert {"new_device", "new_ip", "impossible_travel"} <= set(r2.signals)
    assert "mfa_reset" in r3.signals
    assert normal.score < r1.score < r2.score <= r3.score
    assert {"behavior_score", "takeover_score", "top_signals"} <= set(r3.details)


def test_kyc_detector_is_labelled_prototype(engine):
    ev = NormalizedEvent(event_id="k1", event_type=EventType.kyc_verification, timestamp=utcnow(),
                         customer_token="usr_0000000001", metadata={"demo_manipulation_score": 0.91})
    res = engine.kyc.detect(ev)
    assert res.score == 0.91 and "kyc_manipulation" in res.signals
    assert res.details["mode"] == "controlled_scenario_value"
    assert "Prototype" in res.details["display_name"]
    assert "Not a validated deepfake detector" in res.details["disclaimer"]


def test_cloud_detector_flags_privileged_activity(engine):
    from app.services.profiles import PrincipalProfile

    prof = PrincipalProfile(token="prn_0000000001", regions={"ap-south-1"}, actions={"s3:GetObject"}, history_events=50)
    normal = engine.cloud.detect(NormalizedEvent(event_id="c0", event_type=EventType.cloud_event, timestamp=utcnow(),
                                                 metadata={"action": "s3:GetObject", "region": "ap-south-1"}), prof)
    bad = engine.cloud.detect(NormalizedEvent(event_id="c1", event_type=EventType.cloud_event, timestamp=utcnow(),
                                              metadata={"action": "PRIVILEGED_API_CALL", "region": "eu-central-1",
                                                        "new_access_key": True}), prof)
    assert normal.score < 0.3 < 0.7 < bad.score
    assert {"privileged_api_call", "unusual_region", "new_access_key"} <= set(bad.details["cloud_signals"])
