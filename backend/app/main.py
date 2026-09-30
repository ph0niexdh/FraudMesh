"""FraudMesh — Cross-Channel Fraud Detection & Intelligence (hackathon prototype).

Connect the signals. Expose the attack. Explain the risk.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from starlette.concurrency import run_in_threadpool

from app.api import admin, cases, demo, events, kyc
from app.config import get_settings
from app.database.db import init_db, session_scope
from app.database.models import Event
from app.services.broadcaster import Broadcaster
from app.services.demo import DemoRunner
from app.services.engine import get_engine
from app.utils.logging import configure_logging, get_logger
from app.utils.ratelimit import RateLimitMiddleware

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger("fraudmesh")


def _initialise() -> None:
    init_db()
    engine = get_engine()
    engine.train_models()
    with session_scope() as s:
        empty = (s.scalar(select(func.count()).select_from(Event)) or 0) == 0
    if empty and settings.auto_seed:
        from app.services.seeder import seed

        log.info("empty database — generating SYNTHETIC demo data (FRAUDMESH_AUTO_SEED=true)")
        seed(engine)
    engine.startup()
    log.info("FraudMesh ready")


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    if not settings.admin_auth_enabled:
        log.warning("FRAUDMESH_ADMIN_TOKEN not set — configuration endpoints run in OPEN DEMO MODE")
    task = asyncio.create_task(run_in_threadpool(_initialise))
    app.state.init_task = task
    yield
    runner: DemoRunner = app.state.demo_runner
    if runner.task and not runner.task.done():
        runner.task.cancel()


app = FastAPI(
    title="FraudMesh API",
    description="Cross-Channel Fraud Detection & Intelligence — hackathon prototype. "
                "SIMULATED DATA — NO REAL BANK INCIDENT.",
    version="0.1.0",
    lifespan=lifespan,
)
app.state.broadcaster = Broadcaster()
app.state.demo_runner = DemoRunner(get_engine(), app.state.broadcaster)

app.add_middleware(RateLimitMiddleware, general_limit=settings.rate_limit_per_minute,
                   kyc_limit=settings.kyc_rate_limit_per_minute)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type", "X-Admin-Token"])


@app.middleware("http")
async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    # never echo submitted values back (they may contain sensitive input)
    errors = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


for router in (events.router, cases.router, admin.router, kyc.router, demo.router):
    app.include_router(router)


@app.get("/", include_in_schema=False)
def root() -> dict:
    return {"name": "FraudMesh", "tagline": "Connect the signals. Expose the attack. Explain the risk.",
            "docs": "/docs", "health": "/api/health", "banner": "SIMULATED DATA — NO REAL BANK INCIDENT"}
