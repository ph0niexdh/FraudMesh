"""Scenario runner: emits scenario steps into the real ingestion stream.

Media steps run the real deepfake / KYC pipelines on the controlled fixtures; the
stored results are referenced by the emitted KYC / BIOMETRIC events — the same
path an external verification vendor integration would use.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select

from fraudmesh.config import get_settings
from fraudmesh.core import bus
from fraudmesh.core.crypto import encrypt_str
from fraudmesh.core.ids import new_id
from fraudmesh.core.privacy import mask_account
from fraudmesh.db.models import Account, Customer, SimulationRun
from fraudmesh.db.session import sessionmaker
from fraudmesh.services.events.worker import await_result
from fraudmesh.services.identity import media as media_svc
from fraudmesh.services.simulator import scenarios
from fraudmesh.services.simulator.population import DEMO_VICTIM_ID

logger = logging.getLogger(__name__)
_running: dict[str, asyncio.Task] = {}


def _anchor(kind: str, steps: list[scenarios.Step]) -> datetime:
    now = datetime.now(timezone.utc)
    if kind == "midnight":
        tz = ZoneInfo(get_settings().timezone)
        local = now.astimezone(tz)
        anchor = local.replace(hour=2, minute=14, second=0, microsecond=0)
        last = max(s.at for s in steps)
        if anchor + timedelta(minutes=last + 5) > local:
            anchor -= timedelta(days=1)
        return anchor.astimezone(timezone.utc)
    return now - timedelta(minutes=max(s.at for s in steps) + 0.5)


async def _victim(db, scenario_id: str, run: str) -> dict:
    if scenario_id == "DEEPFAKE_KYC":  # brand-new applicant
        cid = f"cust_new{run}"
        c = Customer(id=cid, display_name=f"Applicant {run.upper()}", segment="retail", risk_tier="standard", kyc_status="PENDING",
                     population="fraudster", home_city="Mumbai", home_lat=19.076, home_lon=72.877,
                     profile={"typical_hour": 14, "log_amount_mean": 7.0, "log_amount_std": 0.8, "daily_txn_rate": 1, "session_s": 300,
                              "typical_daily_spend": 2000, "devices": [], "ips": [], "beneficiaries": []},
                     created_at=datetime.now(timezone.utc) - timedelta(days=1))
        db.add(c)
        await db.flush()
        number = f"{int.from_bytes(os.urandom(5), 'big') % 10**12:012d}"
        db.add(Account(id=f"acc_new{run}", customer_id=cid, number_masked=mask_account(number), number_enc=encrypt_str(number), balance=50000.0,
                       opened_at=datetime.now(timezone.utc) - timedelta(days=1)))
        await db.commit()
        return {"customer_id": cid, "account_id": f"acc_new{run}", "device_id": f"dev:new-{run}", "ip": "100.64.200.1"}
    # The takeover always targets the demo victim; the normal journey uses a clean customer
    # with no attack history (a victim's recent deepfake/KYC risk legitimately carries over).
    cid = DEMO_VICTIM_ID if scenario_id == "ACCOUNT_TAKEOVER" else ("cust_0007" if scenario_id == "NORMAL" else "cust_0001")
    c = await db.get(Customer, cid)
    if c is None:
        raise RuntimeError("demo population not seeded (POST /api/simulator/seed)")
    acct = (await db.execute(select(Account.id).where(Account.customer_id == cid).limit(1))).scalar_one()
    prof = c.profile or {}
    return {"customer_id": cid, "account_id": acct, "device_id": prof.get("devices", ["dev:unknown"])[0], "ip": prof.get("ips", ["100.64.0.1"])[0],
            "device_model": " ".join(prof.get("device_models", [["Galaxy S23", ""]])[0]).strip(), "home": (c.home_lat, c.home_lon)}


def _stamp(event: dict, ts: datetime, idx: int) -> dict:
    e = copy.deepcopy(event)
    e["timestamp"] = ts.isoformat()
    if e["event_type"] in ("NETWORK", "IDS"):
        rec = e["payload"]["record"]
        if "ts" in rec:
            rec["ts"] = ts.timestamp()
            if idx:
                rec["uid"] = f"{rec.get('uid', 'C')}{idx}"
                rec["id.orig_p"] = int(rec.get("id.orig_p", 40000)) + idx
        else:
            rec["timestamp"] = ts.isoformat()
    return e


async def _run(run_id: str, scenario_id: str) -> None:
    run_suffix = run_id[-6:]
    case_ids: list[str] = []
    try:
        async with sessionmaker()() as db:
            victim = await _victim(db, scenario_id, run_suffix)
        sc = scenarios.build(scenario_id, run_suffix, victim)
        anchor = _anchor(sc.anchor, sc.steps)
        total = sum(s.repeat for s in sc.steps)
        async with sessionmaker()() as db:
            run = await db.get(SimulationRun, run_id)
            run.total_steps = total
            await db.commit()
        emitted = 0
        for step in sc.steps:
            for i in range(step.repeat):
                await asyncio.sleep(step.pause if i == 0 else min(step.pause, 0.3))
                ts = anchor + timedelta(minutes=step.at + i * 0.04)
                ev = _stamp(step.event, ts, i)
                ev["event_id"] = new_id("evt")
                ev["source"] = "attack-simulator"
                if step.media:
                    await bus.publish("simulation.progress", {"run_id": run_id, "scenario": scenario_id, "step": emitted, "total": total,
                                                              "label": f"{step.label} — running deepfake/KYC inference", "phase": "inference"})
                    d = get_settings().fixture_dir
                    async with sessionmaker()() as db:
                        if step.media["kind"] == "kyc":
                            out = await media_svc.verify_kyc(db, (d / step.media["document"]).read_bytes(), (d / step.media["selfie"]).read_bytes(),
                                                             customer_id=ev.get("customer_id"))
                            ev["payload"]["kyc_record_id"] = out["kyc_record_id"]
                            if out["result"].get("selfie_analysis_id"):
                                ev["payload"]["media_analysis_id"] = out["result"]["selfie_analysis_id"]
                        else:
                            out = await media_svc.analyze_media(db, (d / step.media["selfie"]).read_bytes(), customer_id=ev.get("customer_id"))
                            ev["payload"]["media_analysis_id"] = out["analysis_id"]
                            ev["payload"]["liveness"] = out["result"]["liveness"]["status"]
                        await db.commit()
                ev["_meta"] = {"simulation_run_id": run_id}
                await bus.enqueue_ingest(ev)
                res = await await_result(ev["event_id"], 90)
                emitted += 1
                if res and res.get("case_id") and res["case_id"] not in case_ids:
                    case_ids.append(res["case_id"])
                await bus.publish("simulation.progress", {"run_id": run_id, "scenario": scenario_id, "step": emitted, "total": total,
                                                          "label": step.label, "event_id": ev["event_id"], "event_type": ev["event_type"],
                                                          "result": res, "phase": "emitted"})
                async with sessionmaker()() as db:
                    run = await db.get(SimulationRun, run_id)
                    run.emitted = emitted
                    run.case_ids = case_ids
                    await db.commit()
        status, error = "COMPLETED", None
    except asyncio.CancelledError:
        status, error = "CANCELLED", None
    except Exception as exc:
        logger.exception("simulation failed")
        status, error = "FAILED", f"{type(exc).__name__}: {exc}"[:500]
    async with sessionmaker()() as db:
        run = await db.get(SimulationRun, run_id)
        run.status, run.error, run.finished_at, run.case_ids = status, error, datetime.now(timezone.utc), case_ids
        await db.commit()
    await bus.publish("simulation.progress", {"run_id": run_id, "scenario": scenario_id, "phase": "finished", "status": status,
                                              "case_ids": case_ids, "error": error})
    _running.pop(run_id, None)


async def start(scenario_id: str, started_by: str) -> SimulationRun:
    if scenario_id not in {s["id"] for s in scenarios.CATALOG}:
        raise KeyError(scenario_id)
    if len(_running) >= 3:
        raise RuntimeError("too many simulations running")
    run = SimulationRun(id=new_id("sim"), scenario=scenario_id, status="RUNNING", started_by=started_by, seed=get_settings().seed)
    async with sessionmaker()() as db:
        db.add(run)
        await db.commit()
    _running[run.id] = asyncio.create_task(_run(run.id, scenario_id), name=f"sim-{run.id}")
    return run


async def cancel(run_id: str) -> bool:
    task = _running.get(run_id)
    if task is None:
        return False
    task.cancel()
    return True
