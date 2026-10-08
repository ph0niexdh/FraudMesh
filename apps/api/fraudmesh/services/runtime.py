"""Process lifecycle: dependency checks, bootstrap and background workers."""

from __future__ import annotations

import asyncio
import logging
import os
import time

from sqlalchemy import text

from fraudmesh.config import get_settings
from fraudmesh.core import bus
from fraudmesh.core.redis import redis
from fraudmesh.db.session import sessionmaker
from fraudmesh.services.graph import store as graph

logger = logging.getLogger(__name__)

_tasks: list[asyncio.Task] = []


async def dependency_status() -> dict:
    out: dict = {}
    t = time.perf_counter()
    try:
        async with sessionmaker()() as db:
            await db.execute(text("SELECT 1"))
        out["postgres"] = {"status": "ONLINE", "latency_ms": round((time.perf_counter() - t) * 1000, 1)}
    except Exception as exc:
        out["postgres"] = {"status": "OFFLINE", "error": type(exc).__name__}
    t = time.perf_counter()
    try:
        await redis().ping()
        out["redis"] = {"status": "ONLINE", "latency_ms": round((time.perf_counter() - t) * 1000, 1)}
    except Exception as exc:
        out["redis"] = {"status": "OFFLINE", "error": type(exc).__name__}
    try:
        out["neo4j"] = {"status": "ONLINE", "latency_ms": round(await graph.ping(), 1)}
    except Exception as exc:
        out["neo4j"] = {"status": "OFFLINE", "error": type(exc).__name__}
    out["ready"] = all(v.get("status") == "ONLINE" for v in out.values() if isinstance(v, dict))
    out["demo_mode"] = get_settings().demo_mode
    return out


def _warm_models() -> None:
    """Load models once at startup (worker thread) so the first request is not slow."""
    from fraudmesh.services.behavior.detector import behavior_detector
    from fraudmesh.services.deepfake import pipeline as deepfake
    from fraudmesh.services.ids.detector import network_detector
    from fraudmesh.services.kyc import ocr
    from fraudmesh.services.transaction.detector import transaction_detector

    t = time.perf_counter()
    transaction_detector.score({"amount": 1000.0})
    behavior_detector.status()
    network_detector.status()
    deepfake.engine()
    ocr.status()
    logger.info("models warm", extra={"fields": {"seconds": round(time.perf_counter() - t, 1)}})


async def startup() -> None:
    from fraudmesh.services.bootstrap import ensure_operators
    from fraudmesh.services.events import worker
    from fraudmesh.services.events.gateway import gateway
    from fraudmesh.services.metrics import registry
    from fraudmesh.services.policy import engine as policy
    from fraudmesh.services.simulator import background, population

    s = get_settings()
    try:
        await graph.ensure_schema()
    except Exception:
        logger.exception("neo4j schema setup failed; graph engine will report OFFLINE")
    await bus.ensure_groups()
    async with sessionmaker()() as db:
        await ensure_operators(db)
        await policy.ensure_defaults(db)
        await registry.sync(db)
        if s.demo_mode and os.environ.get("FM_SEED_ON_START", "true").lower() == "true" and not await population.is_seeded(db):
            await population.seed(db, seed_value=s.seed)
    if os.environ.get("FM_WARM_MODELS", "true").lower() == "true":
        spawn(asyncio.to_thread(_warm_models), "warm-models")
    if os.environ.get("FM_RUN_WORKER", "true").lower() == "true":
        spawn(worker.run_forever(), "ingest-worker")
    spawn(gateway.tail(), "ws-gateway")
    spawn(gateway.metrics_ticker(), "metrics-ticker")
    if s.demo_mode:
        background.set_enabled(os.environ.get("FM_BACKGROUND_TRAFFIC", "true").lower() == "true")
        spawn(background.loop(), "background-traffic")


async def shutdown() -> None:
    for task in _tasks:
        task.cancel()
    for task in _tasks:
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    _tasks.clear()


def spawn(coro, name: str) -> None:
    _tasks.append(asyncio.ensure_future(coro))
