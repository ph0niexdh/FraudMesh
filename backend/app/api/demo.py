from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from app.api.deps import broadcaster_dep, engine_dep, require_admin
from app.services import scenarios as sc
from app.services.broadcaster import Broadcaster
from app.services.demo import DemoRunner
from app.services.engine import FraudMeshEngine

router = APIRouter(tags=["demo"])


class SimulateIn(BaseModel):
    scenario: str = Field("coordinated_cross_channel_fraud", pattern="^[a-z_]{3,48}$")
    step_seconds: float = Field(2.5, ge=0.0, le=30.0)
    reset: bool = True


def runner_dep(request: Request) -> DemoRunner:
    return request.app.state.demo_runner


@router.get("/api/demo/scenarios")
def scenarios() -> dict:
    return {"banner": sc.SIMULATION_BANNER,
            "scenarios": [{"name": n, "description": sc.SCENARIO_INFO[n]} for n in sc.SCENARIOS],
            "flagship": [{k: st[k] for k in ("offset", "title", "narrative")} for st in sc.flagship_attack()]}


@router.post("/api/demo/simulate", status_code=202)
async def simulate(body: SimulateIn, runner: DemoRunner = Depends(runner_dep),
                   _: FraudMeshEngine = Depends(engine_dep)) -> dict:
    if body.scenario not in sc.GENERATORS:
        raise HTTPException(422, f"unknown scenario; choose one of {list(sc.GENERATORS)}")
    try:
        return await runner.start(body.scenario, body.step_seconds, body.reset, actor="dashboard")
    except RuntimeError as err:
        raise HTTPException(409, str(err)) from err


@router.get("/api/demo/status")
def status(runner: DemoRunner = Depends(runner_dep)) -> dict:
    return {**runner.state, "running": runner.running}


@router.post("/api/demo/reset")
async def reset(actor: str = Depends(require_admin), runner: DemoRunner = Depends(runner_dep),
                bc: Broadcaster = Depends(broadcaster_dep), _: FraudMeshEngine = Depends(engine_dep)) -> dict:
    if runner.running:
        raise HTTPException(409, "cannot reset while a simulation is running")
    result = await run_in_threadpool(runner.reset_live_data, actor)
    await bc.publish([{"type": "demo.reset", "data": result}])
    return result


@router.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    bc: Broadcaster = ws.app.state.broadcaster
    await bc.connect(ws)
    try:
        await ws.send_json({"type": "hello", "data": {"banner": sc.SIMULATION_BANNER}})
        while True:
            msg = await ws.receive_text()  # keep-alive pings from the client
            if msg == "ping":
                await ws.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        pass
    finally:
        await bc.disconnect(ws)
