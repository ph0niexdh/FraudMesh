"""Redis fixed-window rate limiting + progressive login delay."""

from __future__ import annotations

import time

from fastapi import HTTPException, Request, status

from fraudmesh.config import get_settings
from fraudmesh.core.redis import redis


def client_ip(request: Request) -> str:
    # Only trust X-Forwarded-For when the direct peer is a configured reverse proxy.
    fwd = request.headers.get("x-forwarded-for")
    if fwd and request.client and request.client.host in get_settings().trusted_proxies:
        return fwd.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


async def hit(key: str, limit: int, window_s: int = 60) -> tuple[bool, int]:
    bucket = int(time.time() // window_s)
    rkey = f"rl:{key}:{bucket}"
    pipe = redis().pipeline()
    pipe.incr(rkey)
    pipe.expire(rkey, window_s + 1)
    count, _ = await pipe.execute()
    return count <= limit, max(0, limit - count)


async def enforce(request: Request, scope: str, limit: int | None = None) -> None:
    limit = limit or get_settings().rate_limit_per_minute
    ok, _ = await hit(f"{scope}:{client_ip(request)}", limit)
    if not ok:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded", headers={"Retry-After": "60"})


def progressive_delay_s(failures: int) -> float:
    """0, 0, 0.5, 1, 2, 4 ... capped at 8s — slows online guessing without locking users out instantly."""
    if failures < 2:
        return 0.0
    return min(8.0, 0.5 * (2 ** (failures - 2)))
