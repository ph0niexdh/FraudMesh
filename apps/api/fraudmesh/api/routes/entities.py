"""Entity and graph intelligence endpoints (bounded queries only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.api.deps import CurrentUser, require
from fraudmesh.api.routes.events import event_dict
from fraudmesh.db.models import Account, Case, CaseEntity, Customer, Event
from fraudmesh.db.session import get_db
from fraudmesh.services.graph import risk as graph_risk
from fraudmesh.services.graph import store as graph

router = APIRouter(tags=["entities & graph"])
_ID = r"^[A-Za-z0-9_.:\- ]{1,80}$"


@router.get("/entities/search")
async def search(q: str = Query(min_length=2, max_length=60), cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    like = f"%{q}%"
    custs = (await db.execute(select(Customer).where(or_(Customer.display_name.ilike(like), Customer.id.ilike(like))).limit(10))).scalars().all()
    cases = (await db.execute(select(Case).where(or_(Case.id.ilike(like), Case.title.ilike(like))).order_by(Case.updated_at.desc()).limit(8))).scalars().all()
    events = (await db.execute(select(Event).where(or_(Event.id == q, Event.ip == q, Event.device_id.ilike(like))).order_by(Event.received_at.desc()).limit(8))).scalars().all()
    return {
        "customers": [{"id": c.id, "label": c.display_name, "city": c.home_city, "tier": c.risk_tier} for c in custs],
        "cases": [{"id": c.id, "label": c.title, "severity": c.severity, "status": c.status} for c in cases],
        "events": [{"id": e.id, "label": f"{e.event_type} · {e.ip or e.device_id or ''}", "risk": e.risk_score} for e in events],
    }


@router.get("/entities/{entity_id}")
async def get_entity(entity_id: str = ..., cu: CurrentUser = Depends(require("cases:read")), db: AsyncSession = Depends(get_db)):
    try:
        node = await graph.entity(entity_id)
    except Exception:
        node = None
    customer = await db.get(Customer, entity_id) if entity_id.startswith("cust") else None
    if node is None and customer is None:
        raise HTTPException(404, "entity not found")
    if entity_id.startswith("cust"):
        evq = select(Event).where(Event.customer_id == entity_id)
    elif entity_id.startswith("acc"):
        evq = select(Event).where(Event.account_id == entity_id)
    elif entity_id.startswith("dev:"):
        evq = select(Event).where(Event.device_id == entity_id)
    elif entity_id.startswith("ip:"):
        evq = select(Event).where(Event.ip == entity_id[3:])
    else:
        evq = select(Event).where(Event.entities.contains([{"id": entity_id}]))
    events = (await db.execute(evq.order_by(Event.ts.desc()).limit(50))).scalars().all()
    case_rows = (await db.execute(select(Case).join(CaseEntity, CaseEntity.case_id == Case.id).where(CaseEntity.entity_id == entity_id)
                                  .order_by(Case.updated_at.desc()).limit(20))).scalars().all()
    path = None
    try:
        path = await graph.shortest_suspicious_path(entity_id)
    except Exception:
        pass
    out = {"entity": node, "events": [event_dict(e) for e in events],
           "cases": [{"id": c.id, "title": c.title, "severity": c.severity, "status": c.status, "risk_score": c.risk_score} for c in case_rows],
           "path_to_flagged": path}
    if customer:
        accts = (await db.execute(select(Account).where(Account.customer_id == customer.id))).scalars().all()
        out["customer"] = {"id": customer.id, "name": customer.display_name, "email": customer.email_masked, "phone": customer.phone_masked,
                           "city": customer.home_city, "segment": customer.segment, "risk_tier": customer.risk_tier, "kyc_status": customer.kyc_status,
                           "since": customer.created_at, "synthetic": customer.is_synthetic,
                           "accounts": [{"id": a.id, "number": a.number_masked, "kind": a.kind, "status": a.status} for a in accts],
                           "baseline": {k: v for k, v in (customer.profile or {}).items() if k in ("typical_hour", "daily_txn_rate", "typical_daily_spend", "session_s")}}
    return out


@router.get("/graph/neighborhood")
async def neighborhood(ids: str = Query(max_length=2000), depth: int = Query(2, ge=1, le=3), limit: int = Query(120, ge=10, le=150),
                       cu: CurrentUser = Depends(require("cases:read"))):
    seeds = [s for s in ids.split(",") if s][:40]
    sub = await graph.neighborhood(seeds, depth=depth, limit=limit)
    prop = graph_risk.propagate(sub["nodes"], sub["edges"])
    for n in sub["nodes"]:
        p = prop.get(n["id"])
        n["propagated_risk"] = round(p["risk"], 3) if p else 0.0
        n["in_case"] = n["id"] in seeds
    return sub


@router.get("/graph/rings")
async def rings(cu: CurrentUser = Depends(require("cases:read"))):
    return {"rings": await graph.fraud_rings(min_size=2), "mule_beneficiaries": await graph.mule_beneficiaries(min_senders=3)}


@router.get("/graph/stats")
async def gstats(cu: CurrentUser = Depends(require("dashboard:read"))):
    return await graph.stats()
