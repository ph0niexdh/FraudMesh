"""Alert correlation and case management.

Correlation windows (relative to event time):

* strong identifiers (customer, account, device, session, face, KYC document,
  beneficiary, cloud identity): 60 minutes
* network identifiers (non-residential IPs, network indicators): 15 minutes
* residential / CGNAT IPs are never used on their own (thousands of households share them)

A case is opened only by an *alert* (event risk ≥ MEDIUM); lower-risk events that
share entities with an open case are attached as context, and on creation the
engine looks back 60 minutes for the earlier, quieter steps of the same attack.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.core import bus
from fraudmesh.core.ids import case_id as new_case_id
from fraudmesh.core.ids import new_id
from fraudmesh.db.models import Alert, Case, CaseAction, CaseEntity, CaseEvent, Detection, Event
from fraudmesh.domain import CaseStatus, risk_level
from fraudmesh.services.cases import story as story_mod
from fraudmesh.services.correlation import temporal
from fraudmesh.services.fusion import engine as fusion
from fraudmesh.services.graph import risk as graph_risk
from fraudmesh.services.graph import store as graph
from fraudmesh.services.ids import intel
from fraudmesh.services.policy import engine as policy

logger = logging.getLogger(__name__)

STRONG_TYPES = {"Customer", "Account", "Device", "Session", "Face", "KYCDocument", "Beneficiary", "CloudIdentity", "Transaction"}
NETWORK_TYPES = {"IP", "NetworkIndicator"}
STRONG_WINDOW = timedelta(minutes=60)
NETWORK_WINDOW = timedelta(minutes=15)
OPEN = [CaseStatus.NEW.value, CaseStatus.INVESTIGATING.value, CaseStatus.CONTAINED.value]

ATTACK_TITLES = {
    "ACCOUNT_TAKEOVER_DEEPFAKE": "Account takeover + deepfake KYC",
    "ACCOUNT_TAKEOVER": "Account takeover",
    "DEEPFAKE_KYC": "Deepfake identity verification",
    "CREDENTIAL_STUFFING": "Credential stuffing",
    "CLOUD_COMPROMISE": "Cloud identity compromise",
    "MULE_NETWORK": "Money-mule network",
    "INSIDER_THREAT": "Insider-assisted takeover",
    "NETWORK_INTRUSION": "Network intrusion",
    "TRANSACTION_FRAUD": "Suspicious transaction",
    "IDENTITY_FRAUD": "Identity fraud",
}


def correlation_keys(entities: list[dict]) -> tuple[list[str], list[str]]:
    strong = [e["id"] for e in entities if e["type"] in STRONG_TYPES]
    net = []
    for e in entities:
        if e.get("role") == "destination":
            continue  # our own servers / popular services would glue unrelated traffic together
        if e["type"] == "NetworkIndicator":
            net.append(e["id"])
        elif e["type"] == "IP" and intel.ip_reputation(e["id"].removeprefix("ip:"))["category"] != "residential_isp":
            net.append(e["id"])  # residential CGNAT pools are shared by thousands of households
    return strong, net


async def _candidate_case(db: AsyncSession, ev: Event) -> tuple[Case | None, str | None]:
    strong, net = correlation_keys(ev.entities or [])
    for ids, window, why in ((strong, STRONG_WINDOW, "shared identifier"), (net, NETWORK_WINDOW, "shared network indicator")):
        if not ids:
            continue
        row = (
            await db.execute(
                select(Case, CaseEntity.entity_id)
                .join(CaseEntity, CaseEntity.case_id == Case.id)
                .where(CaseEntity.entity_id.in_(ids), Case.status.in_(OPEN), Case.last_event_at >= ev.ts - window,
                       Case.first_event_at <= ev.ts + window)
                .order_by(Case.last_event_at.desc())
                .limit(1)
            )
        ).first()
        if row:
            label = next((e["label"] for e in ev.entities if e["id"] == row[1]), row[1])
            return row[0], f"{why}: {label} (within {int(window.total_seconds() // 60)} min)"
    return None, None


async def _attach(db: AsyncSession, case: Case, ev: Event, reason: str) -> None:
    exists = await db.get(CaseEvent, (case.id, ev.id))
    if exists:
        return
    db.add(CaseEvent(case_id=case.id, event_id=ev.id, reason=reason[:200]))
    ev.case_id = case.id
    for e in ev.entities or []:
        if not await db.get(CaseEntity, (case.id, e["id"])):
            db.add(CaseEntity(case_id=case.id, entity_id=e["id"], entity_type=e["type"], label=e.get("label", e["id"])[:120]))
    case.first_event_at = min(case.first_event_at, ev.ts)
    case.last_event_at = max(case.last_event_at, ev.ts)
    await db.execute(update(Alert).where(Alert.event_id == ev.id).values(case_id=case.id))
    await db.flush()


async def correlate(db: AsyncSession, ev: Event, is_alert: bool) -> tuple[Case | None, bool]:
    """Attach the event to an existing case, open a new one (alerts only), or do nothing."""
    case, reason = await _candidate_case(db, ev)
    if case is not None:
        await _attach(db, case, ev, reason or "correlated")
        return case, False
    if not is_alert:
        return None, False

    case = Case(
        id=new_case_id(), title="Correlating…", attack_type="UNDETERMINED", severity=ev.risk_level, status=CaseStatus.NEW.value,
        risk_score=ev.risk_score, confidence=ev.confidence, recommended_action="MONITOR", first_event_at=ev.ts, last_event_at=ev.ts,
        primary_customer_id=ev.customer_id, is_simulated=ev.is_simulated, correlation_window_s=int(STRONG_WINDOW.total_seconds()),
    )
    db.add(case)
    await db.flush()
    await _attach(db, case, ev, "alert opened case")
    # look back for the quieter earlier steps of the same attack
    strong, net = correlation_keys(ev.entities or [])
    look = []
    for ids, window in ((strong, STRONG_WINDOW), (net, NETWORK_WINDOW)):
        if not ids:
            continue
        look += (await db.execute(select(Event).where(
            Event.case_id.is_(None), Event.id != ev.id, Event.ts >= ev.ts - window, Event.ts <= ev.ts,
            or_(*[Event.entities.contains([{"id": i}]) for i in ids[:25]]),  # JSONB containment, parameterised
        ))).scalars().all()
    for prior in {e.id: e for e in look}.values():
        await _attach(db, case, prior, "lookback: earlier step sharing an identifier")
    return case, True


def _det_dict(d: Detection) -> dict:
    return {"detector": d.detector, "domain": d.details.get("domain"), "risk_score": d.risk_score, "confidence": d.confidence,
            "reason_codes": d.reason_codes, "model_version": d.model_version, "metadata": d.details.get("metadata", {}), "event_id": d.event_id}


def _attack_type(best_seq: dict | None, domains: dict, event_types: set[str]) -> str:
    if best_seq and best_seq["score"] >= 0.45:
        return best_seq["attack_type"]
    if "CLOUD" in event_types and not event_types & {"TRANSACTION", "BENEFICIARY", "KYC", "BIOMETRIC"}:
        return "CLOUD_COMPROMISE"
    hot = {d for d, v in domains.items() if v.risk >= 60}
    if "deepfake" in hot:
        return "DEEPFAKE_KYC"
    if "graph" in hot and "transaction" in hot:
        return "MULE_NETWORK"
    if hot == {"network"} or hot <= {"network", "temporal"} and hot:
        return "NETWORK_INTRUSION"
    if "identity" in hot:
        return "IDENTITY_FRAUD"
    return "TRANSACTION_FRAUD"


async def recompute(db: AsyncSession, case: Case, policies: list[dict], is_new: bool) -> dict:
    events = (await db.execute(select(Event).join(CaseEvent, CaseEvent.event_id == Event.id).where(CaseEvent.case_id == case.id))).scalars().all()
    ev_ids = [e.id for e in events]
    dets = (await db.execute(select(Detection).where(Detection.event_id.in_(ev_ids)))).scalars().all()
    det_by_event: dict[str, list[dict]] = {}
    for d in dets:
        det_by_event.setdefault(d.event_id, []).append(_det_dict(d))
    ev_dicts = [{"id": e.id, "ts": e.ts, "event_type": e.event_type, "payload": e.payload, "risk_score": e.risk_score,
                 "reason_codes": e.reason_codes or [], "ctx": (e.payload or {}).get("_ctx", {}), "ip": e.ip,
                 "device": (e.payload or {}).get("_device"), "entities": e.entities or []} for e in events]

    # case-level graph and temporal analysis
    entity_ids = list({x["id"] for e in events for x in (e.entities or [])})
    subjects = [x for x in entity_ids if x.startswith(("cust", "acc"))] or entity_ids[:5]
    g = await graph_risk.score(entity_ids[:60], subjects, ignore_case_id=case.id)
    seq_result, best_seq = temporal.analyze(ev_dicts)
    all_results = [d for v in det_by_event.values() for d in v if d["domain"] not in ("graph", "temporal")]
    all_results += [g.to_dict(), seq_result.to_dict()]
    domains = fusion.collapse(all_results)
    fused = fusion.fuse(domains)

    attack_type = _attack_type(best_seq, domains, {e.event_type for e in events})
    alerts = int(await db.scalar(select(func.count()).select_from(Alert).where(Alert.event_id.in_(ev_ids))) or 0)
    txn_amounts = [float(e.payload.get("amount", 0)) for e in events if e.event_type == "TRANSACTION"]
    pending_amount = sum(txn_amounts)
    max_amount = max(txn_amounts, default=0.0)
    if case.primary_customer_id is None:  # case opened by a network event: adopt the first customer seen
        case.primary_customer_id = next((e.customer_id for e in sorted(events, key=lambda e: e.ts) if e.customer_id), None)

    dom = {d: v.risk for d, v in domains.items()}
    pctx = {
        "attack_score": fused["attack_score"], "risk_level": fused["risk_level"], "confidence": fused["confidence"],
        "event_type": "CASE", "amount": max_amount, "customer_risk_tier": None, "attack_type": attack_type,
        **{f"{d}_risk": dom.get(d, 0.0) for d in ("transaction", "deepfake", "identity", "graph", "network", "behavior", "device", "temporal")},
    }
    decision = policy.evaluate(policies, pctx)

    subject_label = None
    if case.primary_customer_id:
        subject_label = next((x.get("label") for e in events for x in (e.entities or []) if x["id"] == case.primary_customer_id), None)
    narrative = story_mod.build({"subject_label": subject_label}, ev_dicts, det_by_event, fused, decision, g.to_dict(), alerts)

    old = {"risk_score": case.risk_score, "severity": case.severity, "attack_type": case.attack_type}
    case.attack_type = attack_type
    customers = {e.customer_id for e in events if e.customer_id}
    if len(customers) > 1:
        who = f"{len(customers)} customers"
    elif subject_label:
        who = subject_label
    else:
        ents = [x for e in events for x in (e.entities or []) if x.get("role") != "destination"]
        pick = next((x for x in ents if x["type"] == "CloudIdentity"), None) or next((x for x in ents if x["type"] == "IP"), None)
        who = pick["label"] if pick else "unattributed"
    case.title = f"{ATTACK_TITLES.get(attack_type, attack_type.title())} — {who}"[:200]
    case.risk_score = fused["attack_score"]
    case.severity = fused["risk_level"]
    case.confidence = fused["confidence"]
    case.recommended_action = decision["action"]
    case.raw_alert_count = alerts
    case.event_count = len(events)
    case.amount_at_risk = pending_amount
    case.fusion = {**fused, "graph": g.to_dict(), "temporal": seq_result.to_dict(), "decision": decision,
                   "domains_present": sorted(domains)}
    case.story = "\n".join(s["text"] for s in narrative)
    case.updated_at = datetime.now(timezone.utc)
    await db.flush()

    # Attacker-controlled infrastructure of critical cases becomes a graph risk seed
    # (the victim customer/account is NOT flagged — they are the target, not the source).
    if fused["risk_level"] == "CRITICAL":
        attacker = [x for x in entity_ids if x.startswith(("dev:", "ip:", "ben:", "ni:")) and _is_case_new_entity(x, ev_dicts)]
        if attacker:
            await graph.flag_entities(attacker, 0.8, f"linked to critical case {case.id}")
        await graph.upsert([graph.NodeSpec(id=f"case:{case.id}", type="Case", label=case.id, risk=fused["attack_score"] / 100)],
                           [graph.EdgeSpec(src=f"case:{case.id}", dst=x, rel="ASSOCIATED_WITH", confidence=0.9, source="case-engine",
                                           risk=fused["attack_score"] / 100) for x in entity_ids[:40]])

    payload = {"case_id": case.id, "title": case.title, "severity": case.severity, "risk_score": case.risk_score,
               "attack_type": case.attack_type, "event_count": case.event_count, "raw_alert_count": alerts,
               "recommended_action": case.recommended_action, "status": case.status, "old": old}
    await bus.publish("case.correlated" if is_new else "case.updated", payload)
    return {"fusion": fused, "decision": decision, "story": narrative, "graph": g.to_dict(), "temporal": seq_result.to_dict()}


def _is_case_new_entity(entity_id: str, events: list[dict]) -> bool:
    """Only flag devices/IPs that were *new* for the victim during the attack (attacker infrastructure)."""
    for e in events:
        ctx = e.get("ctx", {})
        if entity_id.startswith("dev:") and ctx.get("is_new_device") and ctx.get("_device_entity") == entity_id:
            return True
        if entity_id.startswith("ip:") and ctx.get("ip_new") and f"ip:{e.get('ip')}" == entity_id and ctx.get("ip_risk", 0) >= 0.5:
            return True
        if entity_id.startswith("ben:") and ctx.get("beneficiary_new"):
            return True
        if entity_id.startswith("ni:"):
            return True
    return False


async def record_action(db: AsyncSession, case: Case, action: str, actor: str, note: str | None = None, details: dict | None = None) -> CaseAction:
    row = CaseAction(id=new_id("act"), case_id=case.id, action=action, actor=actor, note=note, details=details or {})
    db.add(row)
    await db.flush()
    await bus.publish("action.executed", {"case_id": case.id, "action": action, "actor": actor, "note": note})
    return row


def level(score: float) -> str:
    return risk_level(score).value
