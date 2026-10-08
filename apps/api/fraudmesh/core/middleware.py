"""Request context (request ids, latency metrics) and security headers."""

from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from fraudmesh.core.logging import request_id_var

logger = logging.getLogger("fraudmesh.http")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(self), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
}


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get("x-request-id")
        if not rid or len(rid) > 64 or not all(c.isalnum() or c in "-_" for c in rid):
            rid = uuid.uuid4().hex[:16]
        token = request_id_var.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            logger.exception("unhandled error", extra={"fields": {"path": request.url.path}})
            raise
        finally:
            request_id_var.reset(token)
        elapsed = (time.perf_counter() - start) * 1000
        response.headers["X-Request-ID"] = rid
        response.headers["Server-Timing"] = f"app;dur={elapsed:.1f}"
        for k, v in SECURITY_HEADERS.items():
            # docs pages need scripts; everything else is a JSON API
            if k == "Content-Security-Policy" and request.url.path.startswith(("/docs", "/redoc")):
                continue
            response.headers.setdefault(k, v)
        from fraudmesh.services.metrics.telemetry import telemetry

        route = request.scope.get("route")
        telemetry.observe_api(getattr(route, "path", request.url.path), elapsed, response.status_code)
        if elapsed > 1000:
            logger.warning("slow request", extra={"fields": {"path": request.url.path, "ms": round(elapsed, 1)}})
        return response
