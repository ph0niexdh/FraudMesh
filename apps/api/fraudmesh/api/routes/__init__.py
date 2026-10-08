"""Route registration. All REST endpoints are served under /api; the WebSocket at /ws."""

from fastapi import APIRouter, FastAPI


def register(app: FastAPI) -> None:
    from fraudmesh.api.routes import audit, auth, cases, dashboard, entities, events, identity, media, policies, security, simulator, system, ws

    api = APIRouter(prefix="/api")
    for module in (auth, system, events, media, dashboard, cases, entities, simulator, policies, audit, security, identity):
        api.include_router(module.router)
    app.include_router(api)
    app.include_router(ws.router)
