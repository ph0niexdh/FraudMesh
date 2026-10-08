"""Point-in-time context ("feature store") for an event.

Everything is computed *as of the event timestamp* from the system of record
(PostgreSQL), the entity graph (Neo4j) and threat intel, so replayed or simulated
events with historical timestamps get the same features they would have had live.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.db.models import Account, Customer, Detection, Event, Transaction
from fraudmesh.services.graph import store as graph
from fraudmesh.services.ids import intel


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


async def _scalar(db: AsyncSession, stmt):
    return (await db.execute(stmt)).scalar_one_or_none()


async def _latest_domain_risk(db: AsyncSession, customer_id: str, domain: str, since: datetime, until: datetime) -> float:
    stmt = (
        select(func.max(Detection.risk_score))
        .join(Event, Event.id == Detection.event_id)
        .where(Event.customer_id == customer_id, Detection.detector.in_(DOMAIN_DETECTORS[domain]), Event.ts >= since, Event.ts <= until)
    )
    v = await _scalar(db, stmt)
    return float(v or 0.0) / 100


DOMAIN_DETECTORS = {
    "identity": ["identity-risk", "kyc-engine"],
    "deepfake": ["deepfake-detector"],
    "network": ["ids", "cloud-security"],
}


async def build(db: AsyncSession, ev: dict) -> dict:
    ts: datetime = ev["ts"]
    cust_id = ev.get("customer_id")
    ctx: dict = {"device": ev.get("device") or {}}
    rep = intel.ip_reputation(ev.get("ip"))
    ctx["ip_risk"], ctx["ip_category"] = rep["risk"], rep["category"]
    if not cust_id:
        return ctx

    customer = await db.get(Customer, cust_id)
    profile = (customer.profile if customer else None) or {}
    ctx["customer_known"] = customer is not None
    ctx["customer_label"] = customer.display_name if customer else cust_id
    ctx["customer_risk_tier"] = customer.risk_tier if customer else "standard"
    ctx["profile"] = profile
    before = Event.ts < ts
    mine = Event.customer_id == cust_id

    prior_events = await _scalar(db, select(func.count()).select_from(Event).where(mine, before))
    ctx["prior_events"] = int(prior_events or 0)

    dev = ev.get("device_entity")
    if dev:
        first = await _scalar(db, select(func.min(Event.ts)).where(mine, before, Event.device_id == dev))
        known = set(profile.get("devices", []))
        ctx["is_new_device"] = first is None and dev not in known
        ctx["device_age_days"] = (ts - first).total_seconds() / 86400 if first else (400.0 if dev in known else 0.0)
        others = await graph.shared_device_customers(dev, cust_id)
        ctx["device_shared_customers"] = len(others)
        ctx["device_shared_flagged"] = sum(1 for o in others if o.get("flagged"))
    else:
        ctx["is_new_device"] = False
        ctx["device_age_days"] = 365.0
        ctx["device_shared_customers"] = 0
    ctx["devices_24h"] = int(await _scalar(db, select(func.count(func.distinct(Event.device_id))).where(
        mine, before, Event.ts >= ts - timedelta(hours=24), Event.device_id.is_not(None))) or 0) + (1 if dev else 0)

    ip = ev.get("ip")
    if ip:
        seen = await _scalar(db, select(func.count()).select_from(Event).where(mine, before, Event.ip == ip))
        ctx["ip_new"] = not seen and ip not in set(profile.get("ips", []))
    geo = ev.get("geo")
    if geo and customer and customer.home_lat is not None:
        ctx["geo_distance_km"] = haversine_km(customer.home_lat, customer.home_lon, geo["lat"], geo["lon"])
    else:
        ctx["geo_distance_km"] = 0.0

    def window(hours: float):
        return and_(mine, before, Event.ts >= ts - timedelta(hours=hours))

    ctx["failed_logins_24h"] = int(await _scalar(db, select(func.count()).select_from(Event).where(
        window(24), Event.event_type == "LOGIN", Event.payload["success"].as_boolean().is_(False))) or 0)
    ctx["mfa_changes_24h"] = int(await _scalar(db, select(func.count()).select_from(Event).where(
        window(24), Event.event_type == "MFA", Event.payload["action"].as_string().in_(["reset", "disabled", "factor_changed"]))) or 0)

    last_login = (await db.execute(select(Event.ts, Event.payload).where(
        window(24 * 30), Event.event_type == "LOGIN", Event.payload["success"].as_boolean().is_(True)).order_by(Event.ts.desc()).limit(1))).first()
    ctx["secs_since_login"] = (ts - last_login[0]).total_seconds() if last_login else 3600.0
    ctx["days_since_last_login"] = (ts - last_login[0]).total_seconds() / 86400 if last_login else float(profile.get("days_between_logins", 2.0))

    nd_login = await _scalar(db, select(func.max(Event.ts)).where(
        window(2), Event.event_type == "LOGIN", Event.payload["_ctx"]["is_new_device"].as_boolean().is_(True)))
    ctx["mins_since_new_device_login"] = (ts - nd_login).total_seconds() / 60 if nd_login else None
    mfa_change = await _scalar(db, select(func.max(Event.ts)).where(
        window(2), Event.event_type == "MFA", Event.payload["action"].as_string().in_(["reset", "disabled", "factor_changed"])))
    ctx["mins_since_mfa_change"] = (ts - mfa_change).total_seconds() / 60 if mfa_change else None

    # transaction aggregates
    tmine = and_(Transaction.customer_id == cust_id, Transaction.ts < ts)
    ctx["velocity_1h"] = int(await _scalar(db, select(func.count()).select_from(Transaction).where(tmine, Transaction.ts >= ts - timedelta(hours=1))) or 0)
    ctx["velocity_24h"] = int(await _scalar(db, select(func.count()).select_from(Transaction).where(tmine, Transaction.ts >= ts - timedelta(hours=24))) or 0)
    spend_24h = float(await _scalar(db, select(func.coalesce(func.sum(Transaction.amount), 0)).where(tmine, Transaction.ts >= ts - timedelta(hours=24))) or 0)
    typical_daily = float(profile.get("typical_daily_spend", 3000.0))

    p = ev.get("payload", {})
    if ev["event_type"] == "TRANSACTION":
        amount = float(p["amount"])
        mu, sd = float(profile.get("log_amount_mean", 7.3)), float(profile.get("log_amount_std", 0.9))
        ctx["amount_deviation"] = (math.log1p(amount) - mu) / max(sd, 0.2)
        acct = await db.get(Account, ev["account_id"]) if ev.get("account_id") else None
        bal = float(p.get("balance_before") or (acct.balance if acct else 0.0) or 0.0)
        ctx["amount_to_balance"] = amount / bal if bal > 0 else 1.0
        ctx["spend_24h_ratio"] = (spend_24h + amount) / max(typical_daily, 1.0)
        ctx["account_age_days"] = (ts - acct.opened_at).total_seconds() / 86400 if acct else 365.0
        if p.get("beneficiary_id"):
            # only completed payments establish a beneficiary (blocked / held attempts do not)
            paid = await _scalar(db, select(func.count()).select_from(Transaction).where(
                tmine, Transaction.beneficiary_id == p["beneficiary_id"], Transaction.decision.not_in(["BLOCK", "HOLD"])))
            ctx["beneficiary_new"] = not paid and p["beneficiary_id"] not in set(profile.get("beneficiaries", []))
            inbound = await graph.beneficiary_inbound(f"ben:{p['beneficiary_id']}")
            ctx["beneficiary_inbound_senders"] = inbound["senders"]
            ctx["beneficiary_flagged_senders"] = inbound["flagged_senders"]
        else:
            ctx["beneficiary_new"] = False
            ctx["beneficiary_inbound_senders"] = 0
    month = ts - timedelta(days=30)
    ctx["kyc_risk"] = await _latest_domain_risk(db, cust_id, "identity", month, ts)
    ctx["deepfake_risk"] = await _latest_domain_risk(db, cust_id, "deepfake", month, ts)
    if ip:
        v = await _scalar(db, select(func.max(Detection.risk_score)).join(Event, Event.id == Detection.event_id).where(
            Event.ip == ip, Detection.detector.in_(DOMAIN_DETECTORS["network"]), Event.ts >= ts - timedelta(hours=1), Event.ts <= ts))
        ctx["network_risk"] = max(float(v or 0) / 100, ctx["ip_risk"] if ctx["ip_risk"] >= 0.5 else 0.0)
    else:
        ctx["network_risk"] = 0.0
    return ctx


def behavior_features(ev: dict, ctx: dict) -> dict:
    prof = ctx.get("profile", {})
    ts: datetime = ev["local_ts"]
    hour = ts.hour + ts.minute / 60
    typ = float(prof.get("typical_hour", 13.0))
    diff = abs(hour - typ)
    p = ev.get("payload", {})
    return {
        "login_hour_deviation": min(diff, 24 - diff),
        "txn_frequency_ratio": (ctx.get("velocity_24h", 0) + 1) / max(0.3, float(prof.get("daily_txn_rate", 2.0))),
        "amount_deviation": abs(ctx.get("amount_deviation", 0.0)),
        "location_deviation_km": math.log1p(ctx.get("geo_distance_km", 0.0)),
        "device_change": 1.0 if ctx.get("is_new_device") else 0.0,
        "ip_change": 1.0 if ctx.get("ip_new") else 0.0,
        "session_duration_ratio": float(p.get("session_duration_s") or prof.get("session_s", 300)) / max(30.0, float(prof.get("session_s", 300))),
        "navigation_speed_ratio": float(p.get("navigation_speed_ratio") or 1.0),
        "failed_logins": float(min(12, ctx.get("failed_logins_24h", 0))),
        "days_since_last_login": float(ctx.get("days_since_last_login", 1.0)),
    }


def transaction_raw(ev: dict, ctx: dict, graph_risk: float, behavior_anomaly: float) -> dict:
    p = ev["payload"]
    ts: datetime = ev["local_ts"]
    return {
        "amount": p["amount"],
        "amount_deviation": ctx.get("amount_deviation", 0.0),
        "amount_to_balance": ctx.get("amount_to_balance", 0.0),
        "velocity_1h": ctx.get("velocity_1h", 0),
        "velocity_24h": ctx.get("velocity_24h", 0),
        "spend_24h_ratio": ctx.get("spend_24h_ratio", 0.0),
        "merchant_category": p.get("merchant_category"),
        "channel": p.get("channel"),
        "hour": ts.hour + ts.minute / 60,
        "device_age_days": ctx.get("device_age_days", 365.0),
        "is_new_device": ctx.get("is_new_device", False),
        "device_shared_customers": ctx.get("device_shared_customers", 0),
        "ip_risk": ctx.get("ip_risk", 0.0),
        "geo_distance_km": ctx.get("geo_distance_km", 0.0),
        "beneficiary_new": ctx.get("beneficiary_new", False),
        "beneficiary_inbound_senders": ctx.get("beneficiary_inbound_senders", 0),
        "account_age_days": ctx.get("account_age_days", 365.0),
        "secs_since_login": ctx.get("secs_since_login", 600.0),
        "failed_logins_24h": ctx.get("failed_logins_24h", 0),
        "mfa_changes_24h": ctx.get("mfa_changes_24h", 0),
        "kyc_risk": ctx.get("kyc_risk", 0.0),
        "deepfake_risk": ctx.get("deepfake_risk", 0.0),
        "network_risk": ctx.get("network_risk", 0.0),
        "behavior_anomaly": behavior_anomaly,
        "graph_risk": graph_risk,
    }
