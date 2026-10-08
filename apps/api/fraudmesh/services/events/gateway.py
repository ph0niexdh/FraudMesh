"""WebSocket fan-out of the Redis Streams bus.

One background task per process tails ``fm:bus`` (XREAD from '$') and pushes each
message to every connected, authenticated client through a bounded queue (slow
clients drop their oldest messages instead of blocking everyone). Because the
source is Redis, any number of API processes can serve WebSockets.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fraudmesh.core import bus
from fraudmesh.core.redis import redis_blocking
from fraudmesh.services.metrics.telemetry import snapshot, telemetry

logger = logging.getLogger(__name__)


class Gateway:
    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self.clients.add(q)
        telemetry.ws_clients = len(self.clients)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.clients.discard(q)
        telemetry.ws_clients = len(self.clients)

    def broadcast(self, msg: dict) -> None:
        for q in list(self.clients):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(msg)
            telemetry.ws_messages += 1

    async def tail(self) -> None:
        last = "$"
        r = redis_blocking()
        while True:
            try:
                resp = await r.xread({bus.BUS_STREAM: last}, block=5000, count=200)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("bus tail failed; retrying")
                await asyncio.sleep(2)
                continue
            for _, messages in resp or []:
                for msg_id, fields in messages:
                    last = msg_id
                    try:
                        data = json.loads(fields.get("data", "{}"))
                    except ValueError:
                        continue
                    self.broadcast({"id": msg_id, "topic": fields.get("topic"), "data": data})

    async def metrics_ticker(self, every_s: float = 5.0) -> None:
        while True:
            await asyncio.sleep(every_s)
            snap = snapshot()
            await bus.publish("metrics.tick", {
                "events_per_sec_1m": snap["events_per_sec_1m"],
                "api_p95_ms": snap["api"]["p95_ms"],
                "ws_clients": snap["websocket"]["clients"],
                "pipeline_p95_ms": snap["pipeline_stages"].get("pipeline_total", {}).get("p95_ms"),
                "correlation_p95_ms": snap["pipeline_stages"].get("correlation", {}).get("p95_ms"),
            })


gateway = Gateway()
