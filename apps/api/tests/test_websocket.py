"""WebSocket live updates against a real uvicorn server process."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time

import httpx
import pytest
import websockets

from .conftest import PASSWORD

pytestmark = pytest.mark.slow


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server(app):  # `app` ensures migrations + bootstrap already ran on the test databases
    port = _free_port()
    env = {**os.environ, "FM_SEED_ON_START": "false", "FM_BACKGROUND_TRAFFIC": "false", "FM_WARM_MODELS": "false"}
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "fraudmesh.main:app", "--port", str(port), "--log-level", "warning"],
                            cwd=os.path.dirname(os.path.dirname(__file__)), env=env)
    base = f"http://127.0.0.1:{port}"
    for _ in range(120):
        try:
            if httpx.get(f"{base}/api/health", timeout=1).status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.5)
    yield base, port
    proc.terminate()
    proc.wait(timeout=20)


async def test_websocket_requires_auth(server):
    _, port = server
    async with websockets.connect(f"ws://127.0.0.1:{port}/ws") as ws:
        await ws.send(json.dumps({"type": "auth", "token": "not-a-jwt"}))
        with pytest.raises(websockets.ConnectionClosed) as exc:
            await asyncio.wait_for(ws.recv(), 5)
        assert exc.value.rcvd.code == 4401


async def test_websocket_streams_pipeline_events(server):
    base, port = server
    async with httpx.AsyncClient(base_url=base) as c:
        tok = (await c.post("/api/auth/login", json={"email": "secops@fraudmesh.local", "password": PASSWORD})).json()["access_token"]
        async with websockets.connect(f"ws://127.0.0.1:{port}/ws") as ws:
            await ws.send(json.dumps({"type": "auth", "token": tok}))
            ready = json.loads(await asyncio.wait_for(ws.recv(), 5))
            assert ready["topic"] == "ws.ready"
            rec = {"ts": time.time(), "uid": "Cws1", "id.orig_h": "192.0.2.77", "id.orig_p": 4000, "id.resp_h": "10.0.0.5", "id.resp_p": 443,
                   "proto": "tcp", "method": "POST", "host": "x", "uri": "/api/login", "status_code": 401, "user_agent": "Hydra"}
            r = await c.post("/api/events", headers={"Authorization": f"Bearer {tok}"},
                             json={"event_type": "NETWORK", "payload": {"sensor": "zeek", "log_type": "http", "record": rec}})
            assert r.status_code == 200
            topics = set()
            deadline = time.time() + 15
            while time.time() < deadline and not {"event.created", "risk.detected"} <= topics:
                msg = json.loads(await asyncio.wait_for(ws.recv(), 10))
                topics.add(msg["topic"])
            assert {"event.created", "risk.detected"} <= topics
