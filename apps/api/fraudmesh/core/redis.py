"""Redis client: cache, rate limiting, event streams (Redis Streams) and fan-out."""

from __future__ import annotations

import redis.asyncio as aioredis

from fraudmesh.config import get_settings

_client: aioredis.Redis | None = None


def redis() -> aioredis.Redis:
    global _client
    if _client is None:
        _client = aioredis.from_url(get_settings().redis_url, decode_responses=True, health_check_interval=30)
    return _client


async def close() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
    _client = None
