"""WebSocket fan-out for real-time dashboard updates."""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket

from app.utils.logging import get_logger
from app.utils.timeutil import iso, utcnow

log = get_logger(__name__)


class Broadcaster:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def publish(self, messages: list[dict[str, Any]]) -> None:
        if not messages or not self._clients:
            return
        async with self._lock:
            clients = list(self._clients)
        for msg in messages:
            msg.setdefault("server_ts", iso(utcnow()))
            payload = json.dumps(msg, default=str)
            dead = []
            for ws in clients:
                try:
                    await ws.send_text(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                await self.disconnect(ws)
                clients.remove(ws)
