"""Redis client: cache, rate limiting, event streams (Redis Streams) and fan-out."""

from __future__ import annotations

import redis.asyncio as aioredis

from fraudmesh.config import get_settings

_client: aioredis.Redis | None = None
_blocking: aioredis.Redis | None = None


def redis() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(get_settings().redis_url, decode_responses=True, health_check_interval=30)
    return _client


def redis_blocking() -> aioredis.Redis:
    """Separate pool for long blocking reads (XREAD/XREADGROUP BLOCK): its socket
    timeout must exceed the block window so a busy event loop is not mistaken for
    a dead connection, and blocking reads never starve the request pool."""
    global _blocking
    if _blocking is None:
        _blocking = aioredis.from_url(get_settings().redis_url, decode_responses=True, socket_timeout=60, health_check_interval=30)
    return _blocking


async def close() -> None:
    global _client, _blocking
    for c in (_client, _blocking):
        if c is not None:
            await c.aclose()
    _client = None
    _blocking = None
