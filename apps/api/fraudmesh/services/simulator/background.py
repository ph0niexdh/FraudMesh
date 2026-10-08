"""Background benign traffic (DEMO / SIMULATION).

Emits ordinary customer activity and benign network flows through the real ingest
stream at a steady rate, so live views show realistic flow and the false-positive
behaviour of every detector is continuously exercised on normal behaviour.
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
from datetime import datetime, timezone

from sqlalchemy import select

from fraudmesh.config import get_settings
from fraudmesh.core import bus
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import Customer
from fraudmesh.db.session import sessionmaker

logger = logging.getLogger(__name__)

_state = {"enabled": False, "per_minute": 10, "emitted": 0, "last_at": None}
MERCHANTS = [("grocery", "m-freshmart"), ("utilities", "m-power-co"), ("dining", "m-cafe"), ("retail", "m-bazaar"), ("travel", "m-rail")]


def status() -> dict:
    return dict(_state)


def set_enabled(on: bool) -> None:
    _state["enabled"] = on


async def _customers() -> list[Customer]:
    async with sessionmaker()() as db:
        return list((await db.execute(select(Customer).where(Customer.population == "normal").limit(200))).scalars().all())


async def loop() -> None:
    _state["enabled"] = get_settings().demo_mode and _state["enabled"]
    rng = random.Random(get_settings().seed)
    customers: list[Customer] = []
    while True:
        await asyncio.sleep(60 / max(1, _state["per_minute"]))
        if not _state["enabled"]:
            continue
        try:
            if not customers:
                customers = await _customers()
                if not customers:
                    continue
            c = rng.choice(customers)
            prof = c.profile or {}
            dev_i = rng.randrange(len(prof.get("devices", ["dev:x"])))
            device = {"id": prof["devices"][dev_i].removeprefix("dev:"), "model": prof["device_models"][dev_i][0], "os": prof["device_models"][dev_i][1]}
            ip = rng.choice(prof.get("ips", ["100.64.0.1"]))
            base = {"event_id": new_id("evt"), "source": "background-traffic", "customer_id": c.id, "account_id": f"acc_{c.id[5:]}_0",
                    "ip": ip, "device": device, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "geo": {"lat": c.home_lat, "lon": c.home_lon}}
            r = rng.random()
            if r < 0.35:
                ev = {**base, "event_type": "LOGIN", "payload": {"success": rng.random() > 0.05, "session_duration_s": prof.get("session_s", 300) * rng.uniform(0.6, 1.4)}}
            elif r < 0.85:
                cat, mid = rng.choice(MERCHANTS)
                amount = round(math.exp(rng.gauss(prof.get("log_amount_mean", 7.3), prof.get("log_amount_std", 0.8))), 0)
                ben = rng.choice(prof.get("beneficiaries", [None])) if rng.random() < 0.3 else None
                payload = {"amount": max(10.0, amount), "channel": rng.choice(["upi", "upi", "card", "imps"]),
                           "merchant_category": "p2p_transfer" if ben else cat}
                if ben:
                    payload["beneficiary_id"] = ben
                else:
                    payload["merchant_id"] = mid
                ev = {**base, "event_type": "TRANSACTION", "payload": payload}
            else:
                ev = {"event_id": new_id("evt"), "source": "zeek-sensor", "event_type": "NETWORK", "payload": {"sensor": "zeek", "log_type": "conn", "record": {
                    "ts": datetime.now(timezone.utc).timestamp(), "uid": f"B{rng.randrange(10**8)}", "id.orig_h": ip, "id.orig_p": rng.randrange(30000, 60000),
                    "id.resp_h": "10.20.0.15", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "duration": rng.uniform(0.2, 8),
                    "orig_bytes": rng.randrange(800, 9000), "resp_bytes": rng.randrange(4000, 90000), "orig_pkts": rng.randrange(8, 40),
                    "resp_pkts": rng.randrange(10, 80), "conn_state": "SF"}}}
            await bus.enqueue_ingest(ev)
            _state["emitted"] += 1
            _state["last_at"] = datetime.now(timezone.utc).isoformat()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("background traffic error")
            await asyncio.sleep(5)
