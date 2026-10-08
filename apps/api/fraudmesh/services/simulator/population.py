"""Deterministic synthetic population (DEMO / SIMULATION data).

Creates customers with behavioural baselines, accounts, known devices and home
networks, a mule ring and a small history of previously confirmed fraud, then
imports 7 days of baseline activity (logins + payments) as historical data.

All people are fictional; IPs come from RFC 6598 (customers) and RFC 5737
(attackers) ranges; account numbers are random and stored encrypted + masked.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.core.crypto import encrypt_str
from fraudmesh.core.ids import new_id
from fraudmesh.core.privacy import mask_account, mask_email, mask_phone
from fraudmesh.db.models import Account, Case, CaseEntity, Customer, Event, Transaction
from fraudmesh.services.auth.security import hash_secret
from fraudmesh.services.graph import store as graph
from fraudmesh.services.graph.store import EdgeSpec, NodeSpec

logger = logging.getLogger(__name__)

FIRST = ["Asha", "Rohan", "Priya", "Vikram", "Meera", "Arjun", "Kavya", "Sanjay", "Ananya", "Rahul", "Divya", "Karan", "Neha", "Aditya",
         "Isha", "Nikhil", "Pooja", "Siddharth", "Tanvi", "Varun", "Lakshmi", "Imran", "Farah", "Joseph", "Grace", "Harpreet", "Gurpreet",
         "Anil", "Sunita", "Deepak", "Ritu", "Manoj", "Swati", "Kiran", "Aisha", "Zoya", "Rajesh", "Shalini", "Vivek", "Nandini"]
LAST = ["Verma", "Sharma", "Iyer", "Nair", "Reddy", "Patel", "Gupta", "Menon", "Rao", "Singh", "Khan", "Das", "Bose", "Joshi", "Kulkarni",
        "Pillai", "Chatterjee", "Mehta", "Agarwal", "Fernandes", "D'Souza", "Kapoor", "Malhotra", "Banerjee", "Shetty", "Hegde"]
CITIES = [("Mumbai", 19.076, 72.877), ("Delhi", 28.614, 77.209), ("Bengaluru", 12.972, 77.594), ("Chennai", 13.083, 80.270),
          ("Kolkata", 22.573, 88.364), ("Hyderabad", 17.385, 78.487), ("Pune", 18.520, 73.856), ("Ahmedabad", 23.023, 72.571),
          ("Jaipur", 26.912, 75.787), ("Kochi", 9.931, 76.267)]
PHONES = [("Pixel 8", "Android 15"), ("Galaxy S23", "Android 14"), ("iPhone 15", "iOS 18"), ("iPhone 13", "iOS 17"),
          ("Redmi Note 13", "Android 14"), ("OnePlus 12", "Android 15"), ("MacBook Air", "macOS 15"), ("ThinkPad", "Windows 11")]
MERCHANTS = ["grocery", "utilities", "dining", "retail", "electronics", "travel"]

DEMO_VICTIM_ID = "cust_asha"
DEMO_PASSWORD = "Demo-Customer-2026!"  # for the identity-verification workflow demo (synthetic customer)
MULE_RING_BENEFICIARY = "ben-rk-0442"


def _ip(rng) -> str:
    return f"100.{int(rng.integers(64, 127))}.{int(rng.integers(0, 255))}.{int(rng.integers(1, 254))}"


async def is_seeded(db: AsyncSession) -> bool:
    return bool(await db.scalar(select(func.count()).select_from(Customer)))


async def seed(db: AsyncSession, n_customers: int = 120, seed_value: int = 1337, history_days: int = 7) -> dict:
    rng = np.random.default_rng(seed_value)
    now = datetime.now(timezone.utc)
    customers: list[Customer] = []
    nodes: list[NodeSpec] = []
    edges: list[EdgeSpec] = []
    accounts: dict[str, Account] = {}

    def make_customer(cid: str, name: str, population: str, city=None, tier="standard", password: str | None = None) -> Customer:
        city = city or CITIES[int(rng.integers(0, len(CITIES)))]
        devices = [f"dev:{cid}-{k}" for k in range(int(rng.integers(1, 3)))]
        ips = [_ip(rng) for _ in range(int(rng.integers(1, 3)))]
        mu = float(rng.normal(7.4, 0.5))
        profile = {
            "typical_hour": round(float(np.clip(rng.normal(14, 3), 7, 22)), 2),
            "log_amount_mean": round(mu, 3),
            "log_amount_std": round(float(rng.uniform(0.6, 1.0)), 3),
            "daily_txn_rate": round(float(rng.uniform(0.8, 3.5)), 2),
            "typical_daily_spend": round(float(math.exp(mu) * rng.uniform(1.2, 3.0)), 0),
            "session_s": round(float(rng.uniform(150, 600)), 0),
            "days_between_logins": round(float(rng.uniform(0.5, 3)), 2),
            "devices": devices,
            "device_models": [PHONES[int(rng.integers(0, len(PHONES)))] for _ in devices],
            "ips": ips,
            "beneficiaries": [f"ben-{cid[5:]}-{k}" for k in range(int(rng.integers(1, 4)))],
        }
        email = f"{name.split()[0].lower()}.{name.split()[-1].lower().replace(chr(39), '')}{int(rng.integers(10, 99))}@mail.example"
        phone = f"+91 9{int(rng.integers(100000000, 999999999))}"
        c = Customer(
            id=cid, display_name=name, email_masked=mask_email(email), phone_masked=mask_phone(phone),
            email_enc=encrypt_str(email), phone_enc=encrypt_str(phone), segment="retail", risk_tier=tier,
            home_city=city[0], home_lat=city[1] + float(rng.normal(0, 0.03)), home_lon=city[2] + float(rng.normal(0, 0.03)),
            population=population, profile=profile, password_hash=hash_secret(password) if password else None,
            created_at=now - timedelta(days=int(rng.integers(200, 3000))),
        )
        customers.append(c)
        return c

    make_customer(DEMO_VICTIM_ID, "Asha Verma", "normal", CITIES[0], password=DEMO_PASSWORD)
    for i in range(n_customers - 1):
        name = f"{FIRST[int(rng.integers(0, len(FIRST)))]} {LAST[int(rng.integers(0, len(LAST)))]}"
        make_customer(f"cust_{i:04d}", name, "normal")
    # mule ring: 5 mule customers sharing one cash-out device; 2 of them previously confirmed
    mules = []
    for k in range(5):
        name = f"{FIRST[int(rng.integers(0, len(FIRST)))]} {LAST[int(rng.integers(0, len(LAST)))]}"
        mules.append(make_customer(f"cust_mule{k}", name, "mule"))
    db.add_all(customers)
    await db.flush()

    for c in customers:
        n_acc = 1 if c.population == "mule" or rng.random() < 0.8 else 2
        for a in range(n_acc):
            number = f"{int(rng.integers(10**11, 10**12 - 1))}"
            acc = Account(id=f"acc_{c.id[5:]}_{a}", customer_id=c.id, number_masked=mask_account(number), number_enc=encrypt_str(number),
                          kind="savings" if a == 0 else "current",
                          balance=float(round(math.exp(c.profile["log_amount_mean"]) * rng.uniform(40, 200), 0)) if c.id != DEMO_VICTIM_ID else 245000.0,
                          opened_at=c.created_at + timedelta(days=1))
            accounts[acc.id] = acc
            db.add(acc)
            nodes.append(NodeSpec(acc.id, "Account", acc.number_masked))
            edges.append(EdgeSpec(c.id, acc.id, "OWNS", 1.0, "core-banking"))
        nodes.append(NodeSpec(c.id, "Customer", c.display_name, risk=0.0))
        for d, (model, os_) in zip(c.profile["devices"], c.profile["device_models"]):
            nodes.append(NodeSpec(d, "Device", f"{model} {os_}"))
            edges.append(EdgeSpec(c.id, d, "USES", 0.9, "baseline-import"))
        for ip in c.profile["ips"]:
            nodes.append(NodeSpec(f"ip:{ip}", "IP", ip, risk=0.02))
            edges.append(EdgeSpec(c.id, f"ip:{ip}", "LOGGED_IN_FROM", 0.5, "baseline-import"))
        for b in c.profile["beneficiaries"]:
            nodes.append(NodeSpec(f"ben:{b}", "Beneficiary", f"Payee {b[-6:]}"))
            edges.append(EdgeSpec(f"acc_{c.id[5:]}_0", f"ben:{b}", "SENT_TO", 1.0, "baseline-import"))

    # mule infrastructure: shared cash-out device + common beneficiary
    ring_dev = "dev:mule-ring-handset"
    nodes.append(NodeSpec(ring_dev, "Device", "Redmi 9A Android 11 (shared)", risk=0.6))
    nodes.append(NodeSpec(f"ben:{MULE_RING_BENEFICIARY}", "Beneficiary", "R. Kumar (A/c XXXX0442)", risk=0.3))
    for m in mules:
        edges.append(EdgeSpec(m.id, ring_dev, "USES", 0.9, "baseline-import"))
        edges.append(EdgeSpec(f"acc_{m.id[5:]}_0", f"ben:{MULE_RING_BENEFICIARY}", "SENT_TO", 1.0, "baseline-import"))
    for a, b in zip(mules, mules[1:]):
        edges.append(EdgeSpec(a.id, b.id, "SHARES_DEVICE", 0.85, "baseline-import"))

    await db.flush()
    await graph.upsert(nodes, edges, now - timedelta(days=history_days))

    # previously confirmed fraud (historical cases) → flagged in the graph
    flagged = [mules[0].id, mules[1].id]
    await graph.flag_entities(flagged + [ring_dev], 0.9, "confirmed fraud (historical case)")
    for i, m in enumerate(mules[:2]):
        hc = Case(id=f"CASE-HIST-{i + 1:03d}", title=f"Money-mule network — {m.display_name}", attack_type="MULE_NETWORK", severity="HIGH",
                  status="RESOLVED", risk_score=82.0, confidence=0.8, recommended_action="BLOCK", action_taken="BLOCK",
                  story="Historical case imported with the demo dataset: account confirmed as a money mule after investigation.",
                  primary_customer_id=m.id, raw_alert_count=6, event_count=6, first_event_at=now - timedelta(days=20 + i),
                  last_event_at=now - timedelta(days=19 + i), is_simulated=True, fusion={"historical": True},
                  created_at=now - timedelta(days=20 + i), updated_at=now - timedelta(days=18 + i))
        db.add(hc)
        await db.flush()
        db.add(CaseEntity(case_id=hc.id, entity_id=m.id, entity_type="Customer", label=m.display_name, risk=0.9))

    # 7 days of baseline history (imported, not live-scored)
    n_events = 0
    pending_txns: list[Transaction] = []
    for c in customers:
        prof = c.profile
        days = history_days
        n_txn = int(rng.poisson(prof["daily_txn_rate"] * days))
        for _ in range(int(rng.poisson(days / max(prof["days_between_logins"], 0.5))) + 1):
            ts = now - timedelta(days=float(rng.uniform(0.2, days)))
            ts = ts.replace(hour=int(np.clip(rng.normal(prof["typical_hour"], 1.5), 0, 23)))
            if ts > now:
                ts -= timedelta(days=1)
            k = int(rng.integers(0, len(prof["devices"])))
            db.add(Event(id=new_id("evt"), event_type="LOGIN", ts=ts, source="historical-import", customer_id=c.id,
                         account_id=f"acc_{c.id[5:]}_0", device_id=prof["devices"][k], ip=prof["ips"][int(rng.integers(0, len(prof["ips"])))],
                         payload={"success": True, "_ctx": {"is_new_device": False}}, entities=[{"id": c.id, "type": "Customer", "role": "subject", "label": c.display_name}],
                         risk_score=float(rng.uniform(1, 12)), confidence=0.8, risk_level="LOW", model="historical", action="ALLOW"))
            n_events += 1
        for _ in range(n_txn):
            ts = now - timedelta(days=float(rng.uniform(0.2, days)))
            ts = ts.replace(hour=int(np.clip(rng.normal(prof["typical_hour"], 2.5), 6, 23)))
            if ts > now:
                ts -= timedelta(days=1)
            amount = float(round(math.exp(rng.normal(prof["log_amount_mean"], prof["log_amount_std"])), 0))
            ben = prof["beneficiaries"][int(rng.integers(0, len(prof["beneficiaries"])))] if rng.random() < 0.4 else None
            eid = new_id("evt")
            db.add(Event(id=eid, event_type="TRANSACTION", ts=ts, source="historical-import", customer_id=c.id, account_id=f"acc_{c.id[5:]}_0",
                         device_id=prof["devices"][0], ip=prof["ips"][0],
                         payload={"amount": amount, "currency": "INR", "channel": "upi", "merchant_category": "p2p_transfer" if ben else MERCHANTS[int(rng.integers(0, len(MERCHANTS)))],
                                  "beneficiary_id": ben, "_ctx": {}},
                         entities=[{"id": c.id, "type": "Customer", "role": "subject", "label": c.display_name}],
                         risk_score=float(rng.uniform(0.5, 8)), confidence=0.8, risk_level="LOW", model="historical", action="ALLOW"))
            pending_txns.append(Transaction(id=new_id("txn"), event_id=eid, customer_id=c.id, account_id=f"acc_{c.id[5:]}_0", amount=amount, channel="upi",
                               merchant_category="p2p_transfer" if ben else "retail", beneficiary_id=ben, fraud_probability=0.01,
                               decision="ALLOW", ts=ts))
            n_events += 1
        if c.population == "mule":
            for _ in range(6):  # mules forward to the ring beneficiary
                ts = now - timedelta(days=float(rng.uniform(0.5, days)))
                eid = new_id("evt")
                amount = float(round(rng.uniform(20000, 90000), 0))
                db.add(Event(id=eid, event_type="TRANSACTION", ts=ts, source="historical-import", customer_id=c.id, account_id=f"acc_{c.id[5:]}_0",
                             device_id=ring_dev, payload={"amount": amount, "channel": "imps", "merchant_category": "p2p_transfer",
                                                          "beneficiary_id": MULE_RING_BENEFICIARY, "_ctx": {}},
                             entities=[{"id": c.id, "type": "Customer", "role": "subject", "label": c.display_name}],
                             risk_score=35.0, confidence=0.7, risk_level="LOW", model="historical", action="ALLOW"))
                pending_txns.append(Transaction(id=new_id("txn"), event_id=eid, customer_id=c.id, account_id=f"acc_{c.id[5:]}_0", amount=amount, channel="imps",
                                   merchant_category="p2p_transfer", beneficiary_id=MULE_RING_BENEFICIARY, fraud_probability=0.4, decision="ALLOW", ts=ts))
                n_events += 1
    await db.flush()  # events first (transactions reference them)
    db.add_all(pending_txns)
    await db.commit()
    logger.info("synthetic population seeded", extra={"fields": {"customers": len(customers), "history_events": n_events}})
    return {"customers": len(customers), "accounts": len(accounts), "history_events": n_events, "seed": seed_value}
