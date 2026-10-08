"""Liveness / readiness."""

from __future__ import annotations

from fastapi import APIRouter

from fraudmesh.services import runtime

router = APIRouter(tags=["system"])


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/ready")
async def ready():
    return await runtime.dependency_status()
