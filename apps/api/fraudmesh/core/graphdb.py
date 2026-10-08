"""Neo4j async driver (official ``neo4j`` package)."""

from __future__ import annotations

from neo4j import AsyncDriver, AsyncGraphDatabase

from fraudmesh.config import get_settings

_driver: AsyncDriver | None = None


def driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        s = get_settings()
        _driver = AsyncGraphDatabase.driver(
            s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password), max_connection_pool_size=30, connection_timeout=5
        )
    return _driver


async def close() -> None:
    global _driver
    if _driver is not None:
        await _driver.close()
    _driver = None
