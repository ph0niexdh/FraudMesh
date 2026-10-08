"""Ingest worker: consumes ``fm:ingest`` (Redis Streams consumer group) and runs the
pipeline. At-least-once: messages are acked only after processing; messages left
pending by a crashed consumer are reclaimed after 60 s. Results are written to a
short-lived ``fm:result:{event_id}`` key so producers (e.g. the simulator) can
await the outcome.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket

from pydantic import ValidationError

from fraudmesh.core import bus
from fraudmesh.core.redis import redis, redis_blocking
from fraudmesh.db.session import sessionmaker
from fraudmesh.schemas.events import EventIn
from fraudmesh.services.events import pipeline

logger = logging.getLogger(__name__)
CONSUMER = f"{socket.gethostname()}-{os.getpid()}"
RESULT_TTL = 600


async def _handle(msg_id: str, fields: dict) -> None:
    raw = json.loads(fields["event"])
    meta = raw.pop("_meta", {})
    try:
        ev = EventIn.model_validate(raw)
    except ValidationError as exc:
        logger.warning("rejected invalid event from stream", extra={"fields": {"errors": exc.error_count()}})
        if raw.get("event_id"):
            await redis().set(f"fm:result:{raw['event_id']}", json.dumps({"error": "validation", "detail": exc.errors()[:3]}, default=str), ex=RESULT_TTL)
        return
    async with sessionmaker()() as db:
        try:
            result = await pipeline.process(db, ev, simulation_run_id=meta.get("simulation_run_id"))
        except Exception as exc:
            await db.rollback()
            logger.exception("pipeline failed for stream event")
            result = {"error": type(exc).__name__}
    if ev.event_id:
        slim = {k: result.get(k) for k in ("event_id", "event_type", "risk_score", "risk_level", "action", "case_id", "case_attack_score",
                                           "case_severity", "alert_id", "model", "latency_ms", "error")}
        await redis().set(f"fm:result:{ev.event_id}", json.dumps(slim, default=str), ex=RESULT_TTL)


async def run_forever(stop: asyncio.Event | None = None) -> None:
    await bus.ensure_groups()
    r = redis()
    # reclaim messages abandoned by dead consumers
    try:
        claimed = await r.xautoclaim(bus.INGEST_STREAM, bus.INGEST_GROUP, CONSUMER, min_idle_time=60_000, start_id="0-0", count=100)
        for msg_id, fields in (claimed[1] if claimed else []):
            if fields:
                await _handle(msg_id, fields)
            await r.xack(bus.INGEST_STREAM, bus.INGEST_GROUP, msg_id)
    except Exception:
        logger.exception("xautoclaim failed")
    while stop is None or not stop.is_set():
        try:
            resp = await redis_blocking().xreadgroup(bus.INGEST_GROUP, CONSUMER, {bus.INGEST_STREAM: ">"}, count=10, block=2000)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("xreadgroup failed; retrying")
            await asyncio.sleep(2)
            continue
        for _, messages in resp or []:
            for msg_id, fields in messages:
                try:
                    await _handle(msg_id, fields)
                finally:
                    await r.xack(bus.INGEST_STREAM, bus.INGEST_GROUP, msg_id)


async def await_result(event_id: str, timeout_s: float = 60.0) -> dict | None:
    deadline = asyncio.get_event_loop().time() + timeout_s
    while asyncio.get_event_loop().time() < deadline:
        v = await redis().get(f"fm:result:{event_id}")
        if v:
            return json.loads(v)
        await asyncio.sleep(0.15)
    return None
