"""WebSocket: live bus updates. Authentication is the first message
(``{"type": "auth", "token": "<access token>"}``) so tokens never appear in URLs/logs."""

from __future__ import annotations

import asyncio
import json

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from fraudmesh.config import get_settings
from fraudmesh.services.auth import security as sec
from fraudmesh.services.auth.service import is_revoked
from fraudmesh.services.events.gateway import gateway

router = APIRouter()


@router.websocket("/ws")
async def ws(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin and origin not in get_settings().cors_origins and get_settings().env == "production":
        await websocket.close(code=4403)
        return
    await websocket.accept()
    try:
        first = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        msg = json.loads(first)
        claims = sec.decode_token(msg.get("token", ""), "access")
        if msg.get("type") != "auth" or await is_revoked(claims.get("sid"), claims.get("fam")):
            raise PermissionError
    except (asyncio.TimeoutError, ValueError, PermissionError, jwt.PyJWTError, WebSocketDisconnect):
        try:
            await websocket.close(code=4401)
        except RuntimeError:
            pass
        return
    q = gateway.subscribe()
    await websocket.send_json({"topic": "ws.ready", "data": {"user": claims["sub"], "role": claims.get("role")}})

    async def pump():
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=20)
                await websocket.send_text(json.dumps(item, default=str))
            except asyncio.TimeoutError:
                await websocket.send_json({"topic": "ping", "data": {}})

    sender = asyncio.create_task(pump())
    try:
        while True:  # drain client messages (pongs); disconnect ends the loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        sender.cancel()
        gateway.unsubscribe(q)
