"""Attack simulator + demo data management (DEMO / SIMULATION)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.config import get_settings
from fraudmesh.db.models import SimulationRun
from fraudmesh.db.session import get_db
from fraudmesh.services.audit import service as audit
from fraudmesh.services.graph import store as graph
from fraudmesh.services.simulator import background, population, runner, scenarios

router = APIRouter(prefix="/simulator", tags=["simulator"])


def _demo_only():
    if not get_settings().demo_mode:
        raise HTTPException(403, "simulator is disabled outside demo mode")


@router.get("/scenarios")
async def list_scenarios(cu: CurrentUser = Depends(require("dashboard:read"))):
    out = []
    for s in scenarios.CATALOG:
        sc = scenarios.build(s["id"], "000000", {"customer_id": "cust_x", "account_id": "acc_x", "device_id": "dev:x", "ip": "100.64.0.1"})
        out.append({**s, "description": sc.description, "expected": sc.expected, "anchor": sc.anchor,
                    "steps": [{"label": st.label, "at_min": st.at, "event_type": (st.event or {}).get("event_type"), "repeat": st.repeat,
                               "media": bool(st.media)} for st in sc.steps]})
    return out


class RunRequest(BaseModel):
    scenario: str


@router.post("/run")
async def run(body: RunRequest, cu: CurrentUser = Depends(require("simulator:run")), db: AsyncSession = Depends(get_db)):
    _demo_only()
    if not await population.is_seeded(db):
        raise HTTPException(409, "demo population not seeded")
    try:
        r = await runner.start(body.scenario, cu.user.email)
    except KeyError:
        raise HTTPException(404, "unknown scenario")
    except RuntimeError as exc:
        raise HTTPException(429, str(exc))
    await audit.record(db, cu.actor, "simulation.start", "simulation", r.id, new_state={"scenario": body.scenario})
    return {"run_id": r.id, "scenario": r.scenario, "status": r.status}


@router.get("/runs")
async def runs(cu: CurrentUser = Depends(require("dashboard:read")), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(SimulationRun).order_by(SimulationRun.started_at.desc()).limit(30))).scalars().all()
    return [{"id": r.id, "scenario": r.scenario, "status": r.status, "started_by": r.started_by, "total_steps": r.total_steps, "emitted": r.emitted,
             "case_ids": r.case_ids, "error": r.error, "started_at": r.started_at, "finished_at": r.finished_at} for r in rows]


@router.post("/runs/{run_id}/cancel")
async def cancel(run_id: str, cu: CurrentUser = Depends(require("simulator:run"))):
    return {"cancelled": await runner.cancel(run_id)}


@router.get("/background")
async def bg_status(cu: CurrentUser = Depends(require("dashboard:read"))):
    return background.status()


class BackgroundRequest(BaseModel):
    enabled: bool


@router.post("/background")
async def bg_toggle(body: BackgroundRequest, cu: CurrentUser = Depends(require("simulator:run")), db: AsyncSession = Depends(get_db)):
    _demo_only()
    background.set_enabled(body.enabled)
    await audit.record(db, cu.actor, "simulation.background", "simulation", None, new_state={"enabled": body.enabled})
    return background.status()


@router.post("/seed")
async def seed(cu: CurrentUser = Depends(require("demo:reset")), db: AsyncSession = Depends(get_db)):
    _demo_only()
    if await population.is_seeded(db):
        return {"status": "already seeded"}
    res = await population.seed(db, seed_value=get_settings().seed)
    await audit.record(db, cu.actor, "demo.seed", "demo", None, new_state=res)
    return res


@router.post("/reset")
async def reset(cu: CurrentUser = Depends(require("demo:reset")), db: AsyncSession = Depends(get_db)):
    """Wipe operational demo data (cases, events, graph) and reseed. Users, policies,
    model registry and the audit trail are preserved."""
    _demo_only()
    await db.execute(text("TRUNCATE case_actions, case_entities, case_events, feedback, alerts, transactions, detections, "
                          "media_analyses, kyc_records, verification_sessions, face_templates, otp_challenges, simulation_runs, "
                          "cases, events, accounts, customers RESTART IDENTITY CASCADE"))
    await db.commit()
    await graph.clear_all()
    await graph.ensure_schema()
    res = await population.seed(db, seed_value=get_settings().seed)
    await audit.record(db, cu.actor, "demo.reset", "demo", None, new_state=res)
    return res
