"""Small in-memory sliding-window rate limiter (per client IP, per bucket).

Adequate for a single-process prototype; a production deployment would use
Redis or the API gateway instead.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] > window:
                hits.popleft()
            if len(hits) >= limit:
                return False
            hits.append(now)
            return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, general_limit: int, kyc_limit: int) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.limiter = SlidingWindowLimiter()
        self.general_limit = general_limit
        self.kyc_limit = kyc_limit

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        path = request.url.path
        if path.startswith("/api/"):
            client = request.client.host if request.client else "unknown"
            if path.startswith("/api/kyc"):
                bucket, limit = "kyc", self.kyc_limit
            else:
                bucket, limit = "api", self.general_limit
            if not self.limiter.allow(f"{bucket}:{client}", limit):
                return JSONResponse({"detail": "Rate limit exceeded. Slow down."}, status_code=429)
        return await call_next(request)
