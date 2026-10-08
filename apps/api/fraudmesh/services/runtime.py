"""Process lifecycle: dependency checks, bootstrap and background workers."""

from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import text

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
    return out


async def startup() -> None:
    from fraudmesh.services.bootstrap import ensure_operators

    try:
        await graph.ensure_schema()
    except Exception:
        logger.exception("neo4j schema setup failed; graph engine will report OFFLINE")
    await bus.ensure_groups()
    async with sessionmaker()() as db:
        await ensure_operators(db)


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
    _tasks.append(asyncio.create_task(coro, name=name))
