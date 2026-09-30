"""Synthetic demo data generator.

SIMULATED DATA — NO REAL BANK INCIDENT. Generates a synthetic population
(≥100 customers, 150 accounts, 100+ devices, 150 IP tokens) with ~30 days
of normal history (1000 transactions, 500 logins, 100 KYC checks, 200 cloud
events) plus historical fraud scenarios, and runs everything through the
real FraudMesh pipeline so cases, scores and explanations are genuine
outputs of the system.
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.database.db import init_db, session_scope
from app.database.models import Account, Base, Customer, Device, Event, FraudCase, IpAddress
from app.privacy.tokenizer import display_label, tokenize
from app.schemas.cases import AnalystAction, FeedbackIn
from app.schemas.events import EventIn
from app.services import scenarios as sc
from app.services.engine import FraudMeshEngine
from app.utils.logging import get_logger
from app.utils.timeutil import utcnow

log = get_logger(__name__)

BANKS = ["SBI", "HDFC Bank", "ICICI Bank"]
BANK_PREFIX = {"SBI": "SBI", "HDFC Bank": "HDFC", "ICICI Bank": "ICICI"}
CITIES = ["Mumbai", "Delhi", "Bengaluru", "Chennai", "Hyderabad", "Pune", "Ahmedabad", "Jaipur", "Lucknow", "Kochi"]
MERCHANTS = [f"SYN-{m}" for m in ("GROCERY-01", "FUEL-02", "PHARMA-03", "TELECOM-04", "RETAIL-05", "UTILITY-06",
                                  "TRAVEL-07", "DINING-08", "EDU-09", "INSURE-10")]
CLOUD_PRINCIPALS = ["svc-payments-gateway", "svc-ledger", "svc-kyc-pipeline", "ops-admin-01", "ops-admin-02"]
CLOUD_ACTIONS = ["s3:GetObject", "dynamodb:Query", "sqs:SendMessage", "lambda:InvokeFunction", "kms:Encrypt",
                 "logs:PutLogEvents", "rds:DescribeDBInstances"]
RESERVED_DEVICES = {sc.DEMO["attacker_device"], sc.DEMO["victim_device"], sc.DEMO["mule_hdfc_device"],
                    sc.DEMO["mule_icici_device"]}


def _hex_device(rng: random.Random, used: set[str]) -> str:
    while True:
        label = f"DEVICE-{rng.randrange(16 ** 4):04X}"
        if label not in used and label not in RESERVED_DEVICES:
            used.add(label)
            return label


def build_population(rng: random.Random, now: datetime) -> list[dict[str, Any]]:
    used_devices: set[str] = set()
    people: list[dict[str, Any]] = []
    d = sc.DEMO
    fixed = [
        (d["victim_customer"], d["victim_account"], "SBI", d["victim_device"], d["victim_ip"], d["victim_city"],
         32_000.0, 11),
        (d["mule_hdfc_customer"], d["mule_hdfc_account"], "HDFC Bank", d["mule_hdfc_device"], d["mule_hdfc_ip"],
         d["mule_hdfc_city"], 9_000.0, 14),
        (d["mule_icici_customer"], d["mule_icici_account"], "ICICI Bank", d["mule_icici_device"], d["mule_icici_ip"],
         d["mule_icici_city"], 7_500.0, 19),
    ]
    for cust, acct, bank, dev, ip, city, mean, hour in fixed:
        people.append({"customer": cust, "accounts": [(acct, bank)], "device": dev, "ip": ip, "mobile_ip": None,
                       "city": city, "mean": mean, "hour": hour, "demo": True})
    n = 3
    while len(people) < 100:
        n += 1
        bank = BANKS[n % 3]
        mean = round(rng.lognormvariate(9.6, 0.8), -2)  # ~₹15k median
        mean = min(max(mean, 1_500), 120_000)
        people.append({
            "customer": f"CUSTOMER_{10000 + n * 37}",
            "accounts": [(f"{BANK_PREFIX[bank]}-SYN-{10000 + n}", bank)],
            "device": _hex_device(rng, used_devices),
            "ip": f"100.{64 + n % 40}.{rng.randrange(256)}.{rng.randrange(1, 255)}",
            "mobile_ip": None,
            "city": rng.choice(CITIES),
            "mean": mean,
            "hour": rng.randint(8, 21),
            "demo": False,
        })
    # 50 secondary accounts at a different bank (same person, same device — legitimately)
    for p in rng.sample([p for p in people if not p["demo"]], 47) + [people[0], people[1], people[2]]:
        if len(p["accounts"]) > 1:
            continue
        bank = rng.choice([b for b in BANKS if b != p["accounts"][0][1]])
        p["accounts"].append((f"{BANK_PREFIX[bank]}-SYN-{20000 + len(people) + rng.randrange(70000)}", bank))
    # 50 extra mobile-network IPs used by some customers
    for p in rng.sample(people, 50):
        p["mobile_ip"] = f"100.{110 + rng.randrange(10)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
    for p in people:
        p["since"] = now - timedelta(days=30, hours=rng.randint(0, 48))
    return people


def _stamp(base: datetime, day_offset: float, hour: int, rng: random.Random) -> datetime:
    day = (base - timedelta(days=day_offset)).replace(hour=0, minute=0, second=0, microsecond=0)
    h = min(23, max(0, int(rng.gauss(hour, 1.5))))
    return day + timedelta(hours=h, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))


def normal_history(rng: random.Random, people: list[dict[str, Any]], now: datetime) -> list[tuple[datetime, dict]]:
    events: list[tuple[datetime, dict]] = []
    cutoff = now - timedelta(hours=2)
    for p in people:
        acct, bank = p["accounts"][0]
        base = {"customer_id": p["customer"], "device_id": p["device"], "bank_name": bank, "account_id": acct}
        onboard = p["since"]
        events.append((onboard, {**base, "event_type": "kyc_verification", "ip_address": p["ip"],
                                 "metadata": {"city": p["city"], "subtype": "ONBOARDING_KYC",
                                              "liveness_score": round(rng.uniform(0.82, 0.99), 2),
                                              "face_match_score": round(rng.uniform(0.8, 0.98), 2)}}))
        events.append((onboard + timedelta(minutes=5), {**base, "event_type": "login", "ip_address": p["ip"],
                                                         "metadata": {"city": p["city"], "subtype": "FIRST_LOGIN"}}))
        for _ in range(4):
            ts = min(_stamp(now, rng.uniform(0.3, 29), p["hour"], rng), cutoff)
            ip = p["mobile_ip"] if p["mobile_ip"] and rng.random() < 0.3 else p["ip"]
            a, b = rng.choice(p["accounts"])
            events.append((ts, {**base, "account_id": a, "bank_name": b, "event_type": "login", "ip_address": ip,
                                "metadata": {"city": p["city"], "subtype": "NORMAL_LOGIN"}}))
        bens = [f"SYN-BEN-{rng.randint(10000, 99999)}" for _ in range(3)]
        merchants = rng.sample(MERCHANTS, 4)
        for i in range(10):
            ts = min(_stamp(now, rng.uniform(0.3, 29), p["hour"], rng), cutoff)
            if p["demo"] and p["customer"] == sc.DEMO["victim_customer"]:
                amount = round(rng.triangular(sc.DEMO["baseline_low"], sc.DEMO["baseline_high"], 27_000), -2)
            else:
                amount = round(max(100.0, rng.lognormvariate(0, 0.33) * p["mean"]), -1)
            meta: dict[str, Any] = {"city": p["city"], "subtype": "PAYMENT"}
            if rng.random() < 0.5:
                meta["beneficiary_id"] = bens[i % 3]
            else:
                meta["merchant"] = merchants[i % 4]
            a, b = rng.choice(p["accounts"])
            events.append((ts, {**base, "account_id": a, "bank_name": b, "event_type": "transaction",
                                "ip_address": p["ip"], "amount": amount, "metadata": meta}))
    # 200 cloud events from service principals on the corporate network
    for i in range(200):
        prn = CLOUD_PRINCIPALS[i % len(CLOUD_PRINCIPALS)]
        ts = min(_stamp(now, rng.uniform(0.2, 30), 13, rng), cutoff)
        admin = prn.startswith("ops-admin")
        action = rng.choice(["iam:ListRoles", "iam:GetRole"]) if admin and rng.random() < 0.3 else rng.choice(CLOUD_ACTIONS)
        events.append((ts, {"event_type": "cloud_event", "channel": "cloud",
                            "ip_address": f"10.20.{i % 8}.{10 + i % 5}",
                            "metadata": {"principal": prn, "action": action, "region": "ap-south-1",
                                         "resource": f"bucket-{prn.split('-')[1]}", "privileged": False,
                                         "api_calls_per_min": rng.randint(1, 20), "subtype": "API_CALL"}}))
    return events


def _party(p: dict[str, Any]) -> sc.Party:
    acct, bank = p["accounts"][0]
    return sc.Party(p["customer"], acct, bank, p["device"], p["ip"], p["city"], baseline=p["mean"])


def scenario_plan(rng: random.Random, people: list[dict[str, Any]], now: datetime) -> list[dict[str, Any]]:
    """Historical scenarios and the analyst outcome recorded for each resulting case."""
    pool = [p for p in people if not p["demo"]]
    rng.shuffle(pool)
    it = iter(pool)
    plan = [
        ("unusual_transaction", 6.2, AnalystAction.CONFIRM_FRAUD),
        ("account_takeover", 5.1, AnalystAction.CONFIRM_FRAUD),
        ("synthetic_identity", 4.3, AnalystAction.CONFIRM_FRAUD),
        ("kyc_manipulation", 3.4, AnalystAction.INVESTIGATE),
        ("coordinated_cross_channel_fraud", 2.2, AnalystAction.CONFIRM_FRAUD),
        ("account_takeover", 1.1, AnalystAction.HOLD),
        ("unusual_transaction", 0.8, AnalystAction.MARK_LEGITIMATE),
        ("kyc_manipulation", 0.3, None),
        ("account_takeover", 0.15, None),
        ("unusual_transaction", 0.1, None),
        ("normal", 0.5, None),
        ("normal", 0.2, None),
    ]
    out = []
    used_devices: set[str] = {p["device"] for p in people}
    for name, days_ago, outcome in plan:
        victim = next(it)
        ctx = sc.ScenarioContext(
            victim=_party(victim),
            mules=[_party(next(it)), _party(next(it))] if name == "coordinated_cross_channel_fraud" else [],
            attacker_device=_hex_device(rng, used_devices),
            attacker_ip=f"100.99.{rng.randrange(1, 250)}.{rng.randrange(1, 250)}",
            attacker_city=rng.choice(["Kolkata", "Guwahati", "Singapore", "Dubai"]),
            cloud_principal="svc-payments-gateway", cloud_resource=f"iam-role/admin-{rng.randrange(100)}",
            rng=random.Random(rng.random()), tag="seed",
        )
        base = now - timedelta(days=days_ago)
        out.append({"name": name, "base": base, "steps": sc.GENERATORS[name](ctx), "outcome": outcome})
    return out


def write_entities(people: list[dict[str, Any]], extra_devices: set[str], now: datetime) -> None:
    with session_scope() as s:
        for p in people:
            ctok = tokenize("customer", p["customer"])
            s.add(Customer(customer_token=ctok, display_label=display_label("customer", p["customer"]),
                           home_city=p["city"], segment="demo" if p["demo"] else "retail",
                           baseline_amount_mean=p["mean"], baseline_amount_std=round(p["mean"] * 0.33, 2),
                           typical_login_hour=p["hour"], created_at=p["since"]))
            s.flush()  # parent row first (no ORM relationships to order inserts)
            for acct, bank in p["accounts"]:
                s.add(Account(account_token=tokenize("account", acct), customer_token=ctok, bank_name=bank,
                              display_label=display_label("account", acct), opened_at=p["since"]))
            s.add(Device(device_token=tokenize("device", p["device"]), display_label=p["device"],
                         device_type="mobile", os="android" if hash(p["device"]) % 2 else "ios", first_seen=p["since"]))
            for ip, kind in ((p["ip"], "broadband"), (p["mobile_ip"], "mobile")):
                if ip and s.get(IpAddress, tokenize("ip", ip)) is None:
                    s.add(IpAddress(ip_token=tokenize("ip", ip), display_label=display_label("ip", ip),
                                    city=p["city"], network_type=kind, first_seen=p["since"]))
                    s.flush()
        for dev in sorted(extra_devices):
            s.add(Device(device_token=tokenize("device", dev), display_label=dev, device_type="unknown",
                         os="unknown", first_seen=now))


def seed(engine: FraudMeshEngine, *, reset: bool = False, seed_value: int = 2024) -> dict[str, Any]:
    from app.database.db import get_engine as get_db_engine

    t0 = time.perf_counter()
    init_db()
    if reset:
        Base.metadata.drop_all(get_db_engine())
        init_db()
    with session_scope() as s:
        if (s.scalar(select(func.count()).select_from(Event)) or 0) > 0:
            log.info("database already contains events — skipping seed (use --reset to rebuild)")
            return {"skipped": True}
    if engine.txn.model is None:
        engine.train_models()
    with session_scope() as s:
        engine._load_config(s)
    engine.profiles.reset()
    engine.graph.reset()
    engine.recent.clear()
    engine.recent_index.clear()
    engine.open_cases.clear()
    engine.case_index.clear()

    rng = random.Random(seed_value)
    now = utcnow()
    people = build_population(rng, now)
    history = normal_history(rng, people, now)
    plan = scenario_plan(rng, people, now)
    scenario_events: list[tuple[datetime, dict, str]] = []
    extra_devices = {sc.DEMO["attacker_device"]}
    for item in plan:
        for step in item["steps"]:
            ts = item["base"] + timedelta(seconds=step["offset"])
            scenario_events.append((ts, step["event"], item["name"]))
            if step["event"].get("device_id"):
                extra_devices.add(step["event"]["device_id"])
    extra_devices -= {p["device"] for p in people}
    write_entities(people, extra_devices, now)

    for p in people:
        engine.profiles.seed_customer(tokenize("customer", p["customer"]), p["city"], p["mean"], p["mean"] * 0.33,
                                      p["hour"])

    merged = [(ts, ev, None) for ts, ev in history] + scenario_events
    merged.sort(key=lambda x: x[0])
    counts: dict[str, int] = {}
    with session_scope() as s:
        for i, (ts, payload, scenario) in enumerate(merged):
            ev = EventIn.model_validate({**payload, "timestamp": ts, "event_id": f"seed_{i:05d}"})
            engine.process_event(ev, source="seed", session=s, scenario=scenario, received_at=ts)
            counts[ev.event_type.value] = counts.get(ev.event_type.value, 0) + 1

    # analyst outcomes for historical cases (synthetic analyst, synthetic timing)
    decisions: list[tuple[str, AnalystAction, datetime]] = []
    with session_scope() as s:
        for item in plan:
            if item["outcome"] is None:
                continue
            cases = s.scalars(select(FraudCase).where(
                FraudCase.scenario == item["name"],
                FraudCase.first_event_at >= item["base"] - timedelta(minutes=1),
                FraudCase.first_event_at <= item["base"] + timedelta(hours=1))).all()
            for case in cases:
                decisions.append((case.case_id, item["outcome"], case.created_at + timedelta(minutes=rng.randint(25, 140))))
    for case_id, action, at in decisions:
        engine.apply_feedback(case_id, FeedbackIn(action=action, analyst="seed-analyst",
                                                  notes="Synthetic historical analyst decision (seed data)."), at=at)
    with session_scope() as s:
        engine.rebuild_state(s)
        n_cases = s.scalar(select(func.count()).select_from(FraudCase))
    summary = {"customers": len(people), "accounts": sum(len(p["accounts"]) for p in people),
               "devices": len(people) + len(extra_devices), "events": counts, "cases": n_cases,
               "analyst_decisions": len(decisions), "seconds": round(time.perf_counter() - t0, 1)}
    log.info("seed complete: %s", summary)
    return summary
