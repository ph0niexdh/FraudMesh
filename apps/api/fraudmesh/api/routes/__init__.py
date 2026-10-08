"""Route registration. All REST endpoints are served under /api."""

from fastapi import APIRouter, FastAPI


def register(app: FastAPI) -> None:
    from fraudmesh.api.routes import auth, system

    api = APIRouter(prefix="/api")
    for module in (auth, system):
        api.include_router(module.router)
    app.include_router(api)
