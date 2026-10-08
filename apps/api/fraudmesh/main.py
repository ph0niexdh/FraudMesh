"""FraudMesh API application."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from fraudmesh.config import get_settings
from fraudmesh.core import bus
from fraudmesh.core import graphdb as graphdb_mod
from fraudmesh.core import redis as redis_mod
from fraudmesh.core.logging import configure_logging, request_id_var
from fraudmesh.core.middleware import RequestContextMiddleware
from fraudmesh.db import session as db_session

logger = logging.getLogger("fraudmesh")


@asynccontextmanager
async def lifespan(app: FastAPI):
    from fraudmesh.services import runtime

    configure_logging(get_settings().log_level)
    await runtime.startup()
    try:
        yield
    finally:
        await runtime.shutdown()
        await graphdb_mod.close()
        await redis_mod.close()
        await db_session.dispose()


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(
        title="FraudMesh API",
        version="2.0.0",
        description="One attack. Multiple signals. One explainable case.",
        lifespan=lifespan,
        docs_url="/docs" if s.env != "production" else None,
        redoc_url=None,
    )
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"],
    )

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError):
        errors = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        return JSONResponse({"detail": errors, "request_id": request_id_var.get()}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        if isinstance(exc, HTTPException):
            raise exc
        logger.exception("unhandled", extra={"fields": {"path": request.url.path}})
        return JSONResponse({"detail": "internal error", "request_id": request_id_var.get()}, status_code=500)

    from fraudmesh.api.routes import register

    register(app)
    return app


app = create_app()
