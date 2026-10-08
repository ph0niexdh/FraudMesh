"""Test harness.

Integration tests run against real PostgreSQL, Redis and Neo4j instances (the
same engines as production) using isolated test databases:

  FM_TEST_DATABASE_URL  (default postgresql+asyncpg://fraudmesh:fraudmesh@127.0.0.1:5432/fraudmesh_test)
  FM_TEST_REDIS_URL     (default redis://127.0.0.1:6379/15)
  FM_TEST_NEO4J_URI     (default bolt://127.0.0.1:7688, password fraudmesh-test)
"""

from __future__ import annotations

import os

os.environ["FM_ENV"] = "test"
os.environ["FM_DATABASE_URL"] = os.environ.get(
    "FM_TEST_DATABASE_URL", "postgresql+asyncpg://fraudmesh:fraudmesh@127.0.0.1:5432/fraudmesh_test"
)
os.environ["FM_REDIS_URL"] = os.environ.get("FM_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")
os.environ["FM_NEO4J_URI"] = os.environ.get("FM_TEST_NEO4J_URI", "bolt://127.0.0.1:7688")
os.environ["FM_NEO4J_PASSWORD"] = os.environ.get("FM_TEST_NEO4J_PASSWORD", "fraudmesh-test")
os.environ.setdefault("FM_SEED_ON_START", "false")

import pytest  # noqa: E402
from asgi_lifespan import LifespanManager  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

PASSWORD = "FraudMesh-Demo-2026!"


async def _reset_postgres() -> None:
    from alembic import command
    from alembic.config import Config

    eng = create_async_engine(os.environ["FM_DATABASE_URL"])
    async with eng.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await eng.dispose()
    here = os.path.dirname(os.path.dirname(__file__))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "migrations"))
    import asyncio

    await asyncio.to_thread(command.upgrade, cfg, "head")


@pytest.fixture(scope="session")
async def app():
    await _reset_postgres()
    from fraudmesh.core.redis import redis
    from fraudmesh.services.graph import store as graph

    await redis().flushdb()
    await graph.ensure_schema()
    await graph.clear_all()
    from fraudmesh.main import app as fastapi_app

    async with LifespanManager(fastapi_app, startup_timeout=120, shutdown_timeout=30):
        yield fastapi_app


@pytest.fixture(scope="session")
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def login_as(client: AsyncClient, email: str) -> dict:
    r = await client.post("/api/auth/login", json={"email": email, "password": PASSWORD, "device": {"fingerprint": f"fp-{email}", "label": "pytest"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "OK", body
    return {"Authorization": f"Bearer {body['access_token']}"}


@pytest.fixture(scope="session")
async def admin_headers(client):
    return await login_as(client, "admin@fraudmesh.local")


@pytest.fixture(scope="session")
async def analyst_headers(client):
    return await login_as(client, "analyst@fraudmesh.local")


@pytest.fixture(scope="session")
async def auditor_headers(client):
    return await login_as(client, "auditor@fraudmesh.local")
