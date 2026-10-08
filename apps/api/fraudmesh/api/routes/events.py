"""Event ingestion and query endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.core import bus, ratelimit
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import Detection, Event
from fraudmesh.db.session import get_db
from fraudmesh.domain import EventType
from fraudmesh.schemas.events import EventIn, TypedEventIn
from fraudmesh.services.auth.security import has_permission
from fraudmesh.services.events import pipeline
from fraudmesh.services.ids.telemetry import TelemetryError

router = APIRouter(prefix="/events", tags=["events"])

TYPED = {
    "login": EventType.LOGIN, "transaction": EventType.TRANSACTION, "device": EventType.DEVICE, "mfa": EventType.MFA,
    "kyc": EventType.KYC, "biometric": EventType.BIOMETRIC, "network": EventType.NETWORK, "beneficiary": EventType.BENEFICIARY,
    "cloud": EventType.CLOUD,
}


async def _ingest(db: AsyncSession, ev: EventIn, mode: str) -> dict:
    if mode == "async":
        ev.event_id = ev.event_id or new_id("evt")
        await bus.enqueue_ingest(ev.model_dump(mode="json"))
        return {"event_id": ev.event_id, "status": "QUEUED"}
    try:
        return await pipeline.process(db, ev)
    except TelemetryError as exc:
        raise HTTPException(422, str(exc))


@router.post("")
async def ingest(ev: EventIn, request: Request, mode: Literal["sync", "async"] = "sync",
                 cu: CurrentUser = Depends(require("events:ingest")), db: AsyncSession = Depends(get_db)):
    await ratelimit.enforce(request, "ingest", 600)
    return await _ingest(db, ev, mode)


@router.post("/{kind}")
async def ingest_typed(kind: str, body: TypedEventIn, request: Request, mode: Literal["sync", "async"] = "sync",
                       cu: CurrentUser = Depends(require("events:ingest")), db: AsyncSession = Depends(get_db)):
    et = TYPED.get(kind)
    if et is None:
        raise HTTPException(404, f"unknown event kind {kind!r}")
    if et == EventType.NETWORK and not has_permission(cu.user.role, "network:ingest"):
        raise HTTPException(403, "network telemetry requires network:ingest")
    await ratelimit.enforce(request, "ingest", 600)
    try:
        ev = EventIn.model_validate({**body.model_dump(exclude_none=True), "event_type": et.value})
    except ValidationError as exc:
        raise HTTPException(422, [{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()])
    return await _ingest(db, ev, mode)


class TelemetryBatch(BaseModel):
    sensor: Literal["zeek", "suricata"]
    log_type: str | None = Field(default=None, max_length=16)
    records: list[dict[str, Any]] = Field(min_length=1, max_length=500)


@router.post("/telemetry/batch")
async def ingest_telemetry(batch: TelemetryBatch, request: Request, cu: CurrentUser = Depends(require("network:ingest"))):
    """Bulk Zeek / Suricata JSON (e.g. shipped by a log forwarder). Queued for async processing."""
    await ratelimit.enforce(request, "ingest-batch", 60)
    ids = []
    for rec in batch.records:
        ev = EventIn(event_type=EventType.IDS if batch.sensor == "suricata" else EventType.NETWORK, source=f"{batch.sensor}-sensor",
                     event_id=new_id("evt"), payload={"sensor": batch.sensor, "log_type": batch.log_type, "record": rec})
        await bus.enqueue_ingest(ev.model_dump(mode="json"))
        ids.append(ev.event_id)
    return {"queued": len(ids), "event_ids": ids[:20]}


def event_dict(e: Event) -> dict:
    p = {k: v for k, v in (e.payload or {}).items() if not k.startswith("_")}
    if e.event_type in ("NETWORK", "IDS"):
        rec = p.get("record", {})
        p = {"sensor": p.get("sensor"), "log_type": p.get("log_type") or rec.get("event_type"),
             "summary": {k: rec.get(k) for k in ("id.resp_h", "dest_ip", "id.resp_p", "dest_port", "uri", "query", "server_name", "status_code") if rec.get(k) is not None}}
    return {
        "id": e.id, "event_type": e.event_type, "ts": e.ts, "received_at": e.received_at, "source": e.source,
        "customer_id": e.customer_id, "account_id": e.account_id, "device_id": e.device_id, "ip": e.ip,
        "risk_score": e.risk_score, "risk_level": e.risk_level, "confidence": e.confidence, "model": e.model, "action": e.action,
        "reason_codes": (e.reason_codes or [])[:4], "case_id": e.case_id, "simulated": e.is_simulated, "payload": p,
        "entities": e.entities or [], "context": (e.payload or {}).get("_ctx", {}),
    }


@router.get("")
async def list_events(
    event_type: str | None = None, min_risk: float = Query(0, ge=0, le=100), case_id: str | None = None,
    customer_id: str | None = None, since_minutes: int = Query(24 * 60, ge=1, le=60 * 24 * 30), limit: int = Query(100, ge=1, le=500),
    include_history: bool = False,
    cu: CurrentUser = Depends(require("dashboard:read")), db: AsyncSession = Depends(get_db),
):
    q = select(Event).where(Event.received_at >= datetime.now(timezone.utc) - timedelta(minutes=since_minutes))
    if not include_history:
        q = q.where(Event.source != "historical-import")
    if event_type:
        q = q.where(Event.event_type == event_type.upper())
    if min_risk:
        q = q.where(Event.risk_score >= min_risk)
    if case_id:
        q = q.where(Event.case_id == case_id)
    if customer_id:
        q = q.where(Event.customer_id == customer_id)
    rows = (await db.execute(q.order_by(Event.received_at.desc()).limit(limit))).scalars().all()
    return [event_dict(e) for e in rows]


@router.get("/{event_id}")
async def get_event(event_id: str, cu: CurrentUser = Depends(require("dashboard:read")), db: AsyncSession = Depends(get_db)):
    e = await db.get(Event, event_id)
    if e is None:
        raise HTTPException(404, "event not found")
    dets = (await db.execute(select(Detection).where(Detection.event_id == event_id))).scalars().all()
    return {**event_dict(e), "detections": [
        {"detector": d.detector, "domain": d.details.get("domain"), "risk_score": d.risk_score, "confidence": d.confidence,
         "reason_codes": d.reason_codes, "model_version": d.model_version, "latency_ms": d.latency_ms, "metadata": d.details.get("metadata", {})}
        for d in dets]}
