"""Event bus on Redis Streams.

Two streams:

* ``fm:ingest`` – raw inbound events awaiting pipeline processing (consumer group
  ``pipeline``; at-least-once delivery, acked after processing).
* ``fm:bus``    – lifecycle notifications (``event.created``, ``event.normalized``,
  ``risk.detected``, ``alert.created``, ``case.correlated``, ``case.updated``,
  ``action.executed``, ``simulation.progress``). The WebSocket gateway tails it.

The topic names and payloads are transport-agnostic so Kafka/Redpanda can replace
Redis Streams by swapping this module.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fraudmesh.core.redis import redis

logger = logging.getLogger(__name__)

INGEST_STREAM = "fm:ingest"
BUS_STREAM = "fm:bus"
INGEST_GROUP = "pipeline"
BUS_MAXLEN = 20_000

TOPICS = {
    "event.created",
    "event.normalized",
    "risk.detected",
    "alert.created",
    "case.correlated",
    "case.updated",
    "action.executed",
    "simulation.progress",
    "metrics.tick",
}


async def publish(topic: str, data: dict[str, Any]) -> str | None:
    if topic not in TOPICS:
        raise ValueError(f"unknown topic {topic}")
    try:
        return await redis().xadd(
            BUS_STREAM, {"topic": topic, "data": json.dumps(data, default=str)}, maxlen=BUS_MAXLEN, approximate=True
        )
    except Exception:  # the bus must never break the scoring path
        logger.exception("bus publish failed", extra={"fields": {"topic": topic}})
        return None


async def enqueue_ingest(event: dict[str, Any]) -> str:
    return await redis().xadd(INGEST_STREAM, {"event": json.dumps(event, default=str)}, maxlen=100_000, approximate=True)


async def ensure_groups() -> None:
    try:
        await redis().xgroup_create(INGEST_STREAM, INGEST_GROUP, id="0", mkstream=True)
    except Exception as exc:  # BUSYGROUP = already exists
        if "BUSYGROUP" not in str(exc):
            raise
