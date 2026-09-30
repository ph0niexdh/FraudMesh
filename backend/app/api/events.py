from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from starlette.concurrency import run_in_threadpool

from app.api.deps import broadcaster_dep, engine_dep
from app.config import get_settings
from app.database.db import session_scope
from app.database.models import Event
from app.privacy.tokenizer import tokenize
from app.schemas.events import EventBatchIn, EventIn
from app.services.broadcaster import Broadcaster
from app.services.engine import FraudMeshEngine
from app.services.serializers import event_to_dict

router = APIRouter(prefix="/api/events", tags=["events"])


def _public(result: dict) -> dict:
    return {k: v for k, v in result.items() if k != "messages"}


@router.post("", status_code=201)
async def submit_event(event: EventIn, engine: FraudMeshEngine = Depends(engine_dep),
                       bc: Broadcaster = Depends(broadcaster_dep)) -> dict:
    try:
        result = await run_in_threadpool(engine.process_event, event)
    except ValueError as err:
        raise HTTPException(409, str(err)) from err
    await bc.publish(result["messages"])
    return _public(result)


@router.post("/batch", status_code=201)
async def submit_batch(batch: EventBatchIn, engine: FraudMeshEngine = Depends(engine_dep),
                       bc: Broadcaster = Depends(broadcaster_dep)) -> dict:
    if len(batch.events) > get_settings().max_batch_size:
        raise HTTPException(413, f"batch larger than {get_settings().max_batch_size} events")
    results, errors = [], []
    for i, ev in enumerate(sorted(batch.events, key=lambda e: e.timestamp.timestamp() if e.timestamp else float("inf"))):
        try:
            res = await run_in_threadpool(engine.process_event, ev)
            await bc.publish(res["messages"])
            results.append(_public(res))
        except ValueError as err:
            errors.append({"index": i, "error": str(err)})
    cases = sorted({r["case"]["case_id"] for r in results if r["case"]})
    return {"processed": len(results), "errors": errors, "cases": cases,
            "results": [{"event_id": r["event"]["event_id"], "signal_score": r["signal_score"],
                         "case_id": r["event"]["case_id"]} for r in results]}


def _match(column, raw_column, kind: str, value: str):  # type: ignore[no-untyped-def]
    """Filter by token, by synthetic display label, or by raw id (tokenized first)."""
    return or_(column == value, raw_column == value, column == tokenize(kind, value))


@router.get("")
def list_events(
    customer: str | None = Query(None, max_length=64),
    account: str | None = Query(None, max_length=64),
    bank: str | None = Query(None, max_length=32),
    device: str | None = Query(None, max_length=64),
    ip: str | None = Query(None, max_length=64),
    event_type: str | None = Query(None, max_length=32),
    channel: str | None = Query(None, max_length=32),
    case_id: str | None = Query(None, max_length=32),
    since: datetime | None = None,
    until: datetime | None = None,
    min_risk: float | None = Query(None, ge=0, le=100),
    max_risk: float | None = Query(None, ge=0, le=100),
    suspicious: bool | None = None,
    source: str | None = Query(None, pattern="^(seed|live)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: FraudMeshEngine = Depends(engine_dep),
) -> dict:
    q = select(Event)
    if customer:
        q = q.where(_match(Event.customer_token, Event.customer_label, "customer", customer))
    if account:
        q = q.where(_match(Event.account_token, Event.account_label, "account", account))
    if device:
        q = q.where(_match(Event.device_token, Event.device_label, "device", device))
    if ip:
        q = q.where(_match(Event.ip_token, Event.ip_label, "ip", ip))
    if bank:
        q = q.where(Event.bank_name == bank)
    if event_type:
        q = q.where(Event.event_type == event_type)
    if channel:
        q = q.where(Event.channel == channel)
    if case_id:
        q = q.where(Event.case_id == case_id)
    if since:
        q = q.where(Event.timestamp >= since)
    if until:
        q = q.where(Event.timestamp <= until)
    if min_risk is not None:
        q = q.where(Event.signal_score >= min_risk / 100)
    if max_risk is not None:
        q = q.where(Event.signal_score <= max_risk / 100)
    if suspicious is not None:
        q = q.where(Event.suspicious.is_(suspicious))
    if source:
        q = q.where(Event.source == source)
    with session_scope() as s:
        total = s.scalar(select(func.count()).select_from(q.subquery()))
        rows = s.scalars(q.order_by(Event.timestamp.desc(), Event.received_at.desc()).offset(offset).limit(limit)).all()
        return {"total": total, "limit": limit, "offset": offset, "events": [event_to_dict(r) for r in rows]}


@router.get("/{event_id}")
def get_event(event_id: str, _: FraudMeshEngine = Depends(engine_dep)) -> dict:
    with session_scope() as s:
        row = s.get(Event, event_id)
        if row is None:
            raise HTTPException(404, "event not found")
        return event_to_dict(row)
