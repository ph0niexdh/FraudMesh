"""The FraudMesh event pipeline.

    EVENT → normalise → persist → resolve entities (Neo4j) → point-in-time context
          → DETECT (per-type detectors) → event-level fusion → alert?
          → CORRELATE (case) → FUSE (case-level, incl. graph + temporal) → EXPLAIN (story)
          → ACT (policy) → graph risk update → publish lifecycle events (Redis Streams)

Transactions are decided on the *case-level* attack score, so a transfer that looks
ordinary in isolation is still stopped when it is the last step of a correlated attack.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.config import get_settings
from fraudmesh.core import bus
from fraudmesh.core.ids import new_id
from fraudmesh.core.logging import case_id_var, event_id_var
from fraudmesh.db.models import Account, Alert, Detection, Event, KycRecord, MediaAnalysis, Transaction
from fraudmesh.detection import scorecards
from fraudmesh.detection.base import DetectorResult, Reason
from fraudmesh.domain import EventType, risk_level
from fraudmesh.schemas.events import EventIn
from fraudmesh.services.behavior.detector import behavior_detector
from fraudmesh.services.cases import engine as cases
from fraudmesh.services.events import context as context_mod
from fraudmesh.services.fusion import engine as fusion
from fraudmesh.services.graph import resolution
from fraudmesh.services.graph import risk as graph_risk
from fraudmesh.services.graph import store as graph
from fraudmesh.services.ids import telemetry as net_telemetry
from fraudmesh.services.ids.detector import network_detector
from fraudmesh.services.metrics.telemetry import telemetry
from fraudmesh.services.policy import engine as policy
from fraudmesh.services.transaction.detector import transaction_detector

logger = logging.getLogger(__name__)

ALERT_THRESHOLD = 40.0  # MEDIUM and above become alerts


class Stage:
    def __init__(self, name: str):
        self.name = name

    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, *exc):
        telemetry.observe_stage(self.name, (time.perf_counter() - self.t) * 1000)


def deepfake_result_to_detector(res: dict) -> DetectorResult:
    return DetectorResult(
        detector="deepfake-detector", domain="deepfake", risk_score=float(res.get("risk_score") or 0.0),
        confidence=float(res.get("confidence") or 0.0),
        reason_codes=[Reason(r["code"], r["message"], float(r.get("weight", 0))) for r in res.get("reason_codes", [])],
        model_version=res.get("model", {}).get("version", "unknown"), latency_ms=float(res.get("latency_ms") or 0.0),
        metadata={"deepfake_probability": res.get("deepfake_probability"), "verdict": res.get("verdict"),
                  "liveness": (res.get("liveness") or {}).get("status"), "analysis_id": res.get("analysis_id"),
                  "suspicious_frames": res.get("suspicious_frames", [])},
    )


def kyc_result_to_detector(res: dict) -> DetectorResult:
    failed = [c for c in res.get("checks", []) if c["status"] == "FAIL"]
    return DetectorResult(
        detector="kyc-engine", domain="identity", risk_score=float(res["scores"]["kyc_risk"]),
        confidence=float(res["scores"]["document_confidence"]),
        reason_codes=[Reason(f"KYC_{c['id'].upper()}", f"{c['name']}: {c['detail']}", 0.0) for c in failed][:6],
        model_version="kyc-pipeline-v1 (PP-OCR + ICAO 9303 + SFace)", latency_ms=float(res.get("latency_ms") or 0.0),
        metadata={"decision": res.get("decision"), "scores": res.get("scores"), "kyc_record_id": res.get("kyc_record_id"),
                  "face_match": res.get("face_match"), "document_type": res.get("document_type")},
    )


async def _load_media_extras(db: AsyncSession, ev: dict, extra: dict) -> None:
    p = ev["payload"]
    if p.get("media_analysis_id") and "deepfake" not in extra:
        row = await db.get(MediaAnalysis, p["media_analysis_id"])
        if row:
            extra["deepfake"] = {**row.result, "analysis_id": row.id}
    if p.get("kyc_record_id") and "kyc" not in extra:
        row = await db.get(KycRecord, p["kyc_record_id"])
        if row:
            extra["kyc"] = {"scores": row.scores, "checks": row.checks, "decision": row.decision, "kyc_record_id": row.id,
                            "document_type": row.doc_type}
            extra.setdefault("doc_hmac", row.doc_number_hmac)


async def process(db: AsyncSession, ev_in: EventIn, *, simulation_run_id: str | None = None, extra: dict | None = None) -> dict:
    t0 = time.perf_counter()
    extra = dict(extra or {})
    s = get_settings()

    # ---------------------------------------------------------------- normalise
    with Stage("normalize"):
        if ev_in.event_id:
            existing = await db.get(Event, ev_in.event_id)
            if existing is not None:  # idempotent replay
                return {"event_id": existing.id, "duplicate": True, "risk_score": existing.risk_score, "action": existing.action,
                        "case_id": existing.case_id}
        eid = ev_in.event_id or new_id("evt")
        event_id_var.set(eid)
        ts = ev_in.timestamp or datetime.now(timezone.utc)
        customer_id, account_id = ev_in.customer_id, ev_in.account_id
        if account_id and not customer_id:
            acct = await db.get(Account, account_id)
            customer_id = acct.customer_id if acct else None
        device = ev_in.device.model_dump() if ev_in.device else None
        dev_entity = resolution.device_entity_id(device)
        ev = {
            "id": eid, "event_type": ev_in.event_type.value, "ts": ts, "local_ts": ts.astimezone(ZoneInfo(s.timezone)),
            "source": ev_in.source, "customer_id": customer_id, "account_id": account_id, "session_id": ev_in.session_id,
            "ip": ev_in.ip, "device": device, "device_entity": dev_entity, "geo": ev_in.geo.model_dump() if ev_in.geo else None,
            "payload": dict(ev_in.payload),
        }
        et = ev_in.event_type
        if et in (EventType.NETWORK, EventType.IDS):
            obs = net_telemetry.parse(ev["payload"]["record"], ev["payload"]["sensor"], ev["payload"].get("log_type"))
            ev["ip"] = ev["ip"] or obs.src_ip
            ev["ts"] = ev_in.timestamp or obs.ts
            ev["local_ts"] = ev["ts"].astimezone(ZoneInfo(s.timezone))
            extra["observation"] = obs

    row = Event(id=eid, event_type=et.value, ts=ev["ts"], source=ev["source"], customer_id=customer_id, account_id=account_id,
                device_id=dev_entity, ip=ev["ip"], session_id=ev["session_id"], payload=ev["payload"], entities=[],
                is_simulated=simulation_run_id is not None, simulation_run_id=simulation_run_id)
    db.add(row)
    await db.flush()
    telemetry.count_event(et.value)
    await bus.publish("event.created", {"event_id": eid, "event_type": et.value, "ts": ev["ts"], "source": ev["source"],
                                        "customer_id": customer_id, "simulated": row.is_simulated})

    # ---------------------------------------------------------------- context + entities
    with Stage("context"):
        await _load_media_extras(db, ev, extra)
        ctx = await context_mod.build(db, ev)
    res_extra = {"customer_label": ctx.get("customer_label"), "doc_hmac": extra.get("doc_hmac"), "face_id": extra.get("face_id")}
    if "observation" in extra:
        res_extra["dst_ip"] = extra["observation"].dst_ip
    with Stage("entity_resolution"):
        resolved = resolution.resolve(ev, 0.0, res_extra)
        try:
            await graph.upsert(resolved.nodes, resolved.edges, ev["ts"])
            graph_ok = True
        except Exception:
            logger.exception("graph upsert failed")
            graph_ok = False

    # ---------------------------------------------------------------- detect
    results: list[DetectorResult] = []
    with Stage("detection"):
        entity_ids = [e["id"] for e in resolved.entities]
        subjects = [x for x in (customer_id, account_id) if x]
        g_res = None
        if graph_ok and customer_id and et in (EventType.TRANSACTION, EventType.BENEFICIARY, EventType.DEVICE, EventType.LOGIN, EventType.KYC):
            g_res = await graph_risk.score(entity_ids, subjects or entity_ids[:3])
            results.append(g_res)
        beh_res = None
        if customer_id and et in (EventType.LOGIN, EventType.TRANSACTION):
            beh_res = behavior_detector.score(context_mod.behavior_features(ev, ctx))
            results.append(beh_res)
        if customer_id and et in (EventType.LOGIN, EventType.DEVICE, EventType.TRANSACTION, EventType.BENEFICIARY):
            results.append(scorecards.device({**ctx, "device": ev["device"]}))
        idr = scorecards.identity(et.value, {**ev["payload"], **({"kyc_risk": extra["kyc"]["scores"]["kyc_risk"]} if "kyc" in extra else {})},
                                  {**ctx, "kyc_failed_checks": [c for c in extra.get("kyc", {}).get("checks", []) if c["status"] == "FAIL"]})
        if idr is not None and et != EventType.KYC:
            results.append(idr)
        if "kyc" in extra:
            results.append(kyc_result_to_detector(extra["kyc"]))
        elif et == EventType.KYC and idr is not None:
            results.append(idr)
        if "deepfake" in extra:
            results.append(deepfake_result_to_detector(extra["deepfake"]))
        elif et in (EventType.BIOMETRIC, EventType.DEEPFAKE, EventType.KYC) and ev["payload"].get("deepfake_risk") is not None:
            results.append(DetectorResult("deepfake-detector", "deepfake", float(ev["payload"]["deepfake_risk"]), 0.6,
                                          [Reason("DF_EXTERNAL", "Deepfake risk reported by upstream verification vendor", 0.0)],
                                          "external", 0.0, {"deepfake_probability": ev["payload"]["deepfake_risk"] / 100}))
        if et in (EventType.NETWORK, EventType.IDS):
            results.append(await network_detector.analyze(extra["observation"]))
        elif ev["ip"] and ctx.get("ip_risk", 0) >= 0.5:
            results.append(scorecards.ip_reputation(ev["ip"], ctx))
        if et == EventType.CLOUD:
            seen = await db.scalar(select(Event.id).where(Event.event_type == "CLOUD", Event.ip == ev["ip"], Event.ts < ev["ts"],
                                                          Event.payload["principal"].as_string() == ev["payload"]["principal"]).limit(1))
            results.append(scorecards.cloud(ev["payload"], {**ctx, "principal_new_ip": seen is None}))
        if et == EventType.TRANSACTION:
            raw = context_mod.transaction_raw(ev, ctx, (g_res.risk_score / 100) if g_res else 0.0, (beh_res.risk_score / 100) if beh_res else 0.0)
            txn_res = transaction_detector.score(raw)
            txn_res.metadata["features"] = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in raw.items()}
            results.append(txn_res)

    # ---------------------------------------------------------------- event-level fusion
    dicts = [r.to_dict() for r in results]
    domains = fusion.collapse(dicts)
    event_fused = fusion.fuse(domains) if domains else {"attack_score": 0.0, "risk_level": "LOW", "confidence": 0.3, "contributions": []}
    strongest = max(dicts, key=lambda d: d["risk_score"] * d["confidence"], default=None)
    ev_risk = event_fused["attack_score"]
    primary = strongest["detector"] if strongest else None
    reasons = sorted([rc for d in dicts for rc in d["reason_codes"]], key=lambda r: -abs(r.get("weight", 0)))[:8]

    ctx_flags = {k: ctx.get(k) for k in ("is_new_device", "ip_new", "beneficiary_new", "ip_risk", "ip_category", "device_age_days",
                                          "deepfake_risk", "geo_distance_km") if ctx.get(k) is not None}
    ctx_flags["_device_entity"] = dev_entity
    if "deepfake" in extra:
        ctx_flags["deepfake_risk"] = (extra["deepfake"].get("risk_score") or 0) / 100
    row.payload = {**ev["payload"], "_ctx": ctx_flags, **({"_device": device} if device else {})}
    row.entities = resolved.entities
    row.risk_score = round(ev_risk, 2)
    row.risk_level = risk_level(ev_risk).value
    row.confidence = event_fused["confidence"] if domains else 0.3
    row.model = primary
    row.reason_codes = reasons
    for d in dicts:
        db.add(Detection(id=new_id("det"), event_id=eid, detector=d["detector"], model_version=d["model_version"],
                         risk_score=d["risk_score"], confidence=d["confidence"], reason_codes=d["reason_codes"],
                         details={"domain": d["domain"], "metadata": d["metadata"]}, latency_ms=d["latency_ms"]))
    await db.flush()
    await bus.publish("event.normalized", {"event_id": eid, "entities": resolved.entities})
    await bus.publish("risk.detected", {"event_id": eid, "event_type": et.value, "risk_score": row.risk_score, "risk_level": row.risk_level,
                                        "detectors": [{"detector": d["detector"], "risk_score": d["risk_score"]} for d in dicts]})

    # ---------------------------------------------------------------- alert + correlate + case fusion
    alert = None
    if ev_risk >= ALERT_THRESHOLD:
        top_domain = max(domains.values(), key=lambda v: v.risk).domain if domains else "transaction"
        title = reasons[0]["message"][:200] if reasons else f"{et.value} risk {ev_risk:.0f}"
        alert = Alert(id=new_id("alr"), event_id=eid, detector=primary or "fusion", domain=top_domain,
                      severity=row.risk_level, title=title, risk_score=row.risk_score)
        db.add(alert)
        await db.flush()
    with Stage("correlation"):
        case, is_new = await cases.correlate(db, row, alert is not None)
    case_view = None
    policies = await policy.load(db)
    if case is not None:
        case_id_var.set(case.id)
        with Stage("case_fusion"):
            case_view = await cases.recompute(db, case, policies, is_new)
    if alert is not None:
        await bus.publish("alert.created", {"alert_id": alert.id, "event_id": eid, "case_id": case.id if case else None, "severity": alert.severity,
                                            "title": alert.title, "risk_score": alert.risk_score, "domain": alert.domain, "event_type": et.value})

    # ---------------------------------------------------------------- act
    # Decide on the attack (case) when there is one, otherwise on the event itself.
    dom_risk = {d: v.risk for d, v in domains.items()}
    if case is not None:
        dom_risk = {**dom_risk, **{c["domain"]: c["risk"] for c in case.fusion.get("contributions", [])}}
    decision_score = case.risk_score if case is not None else ev_risk
    pctx = {
        "attack_score": decision_score, "risk_level": risk_level(decision_score).value,
        "confidence": case.confidence if case is not None else row.confidence, "event_type": et.value,
        "amount": ev["payload"].get("amount", 0.0), "channel": ev["payload"].get("channel"),
        "customer_risk_tier": ctx.get("customer_risk_tier"),
        **{f"{d}_risk": dom_risk.get(d, 0.0) for d in ("transaction", "deepfake", "identity", "graph", "network", "behavior", "device", "temporal")},
    }
    decision = policy.evaluate(policies, pctx)
    if et in (EventType.NETWORK, EventType.IDS, EventType.CLOUD) and decision["action"] in ("STEP_UP", "HOLD"):
        # telemetry has no customer session to step up or payment to hold: watch the source instead
        decision = {**decision, "action": "MONITOR"}
    row.action = decision["action"]

    if et == EventType.TRANSACTION:
        p = ev["payload"]
        txn_det = next((d for d in dicts if d["detector"] == "transaction-model"), None)
        db.add(Transaction(id=new_id("txn"), event_id=eid, customer_id=customer_id, account_id=account_id, amount=p["amount"],
                           currency=p.get("currency", "INR"), channel=p.get("channel", "upi"), merchant_category=p.get("merchant_category"),
                           beneficiary_id=p.get("beneficiary_id"), beneficiary_new=bool(ctx.get("beneficiary_new")),
                           fraud_probability=(txn_det["metadata"]["fraud_probability"] if txn_det else 0.0), decision=decision["action"], ts=ev["ts"]))
    if case is not None and decision["action"] in ("BLOCK", "HOLD") and et in (EventType.TRANSACTION, EventType.BENEFICIARY, EventType.KYC, EventType.BIOMETRIC, EventType.DEEPFAKE):
        verb = {"TRANSACTION": "transaction", "BENEFICIARY": "beneficiary change", "KYC": "verification", "BIOMETRIC": "verification", "DEEPFAKE": "verification"}[et.value]
        await cases.record_action(db, case, f"{decision['action']}_{verb.upper().replace(' ', '_')}", "policy-engine",
                                  f"{decision['reason']} — {verb} {eid}", {"event_id": eid, "policy": decision.get("policy"), "attack_score": decision_score})
        if case.status == "NEW" and decision["action"] == "BLOCK":
            case.status = "CONTAINED"
    await db.flush()

    # edge risk now that the event is scored
    if graph_ok and ev_risk >= 20:
        try:
            scored = resolution.resolve(ev, ev_risk / 100, res_extra)
            await graph.upsert(scored.nodes, scored.edges, ev["ts"])
        except Exception:
            logger.exception("graph risk update failed")

    await db.commit()
    total_ms = (time.perf_counter() - t0) * 1000
    telemetry.observe_stage("pipeline_total", total_ms)
    result = {
        "event_id": eid,
        "event_type": et.value,
        "ts": ev["ts"],
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "confidence": row.confidence,
        "model": primary,
        "action": decision["action"],
        "policy": decision.get("policy"),
        "matched_policies": decision.get("matched"),
        "detectors": dicts,
        "event_fusion": event_fused,
        "alert_id": alert.id if alert else None,
        "case_id": case.id if case else None,
        "case_attack_score": case.risk_score if case else None,
        "case_severity": case.severity if case else None,
        "entities": resolved.entities,
        "latency_ms": round(total_ms, 1),
    }
    await bus.publish("event.normalized", {"event_id": eid, "stage": "decided", "action": decision["action"], "risk_score": row.risk_score,
                                           "risk_level": row.risk_level, "case_id": result["case_id"], "event_type": et.value,
                                           "customer_id": customer_id, "ts": ev["ts"], "model": primary, "confidence": row.confidence,
                                           "source": ev["source"], "simulated": row.is_simulated, "latency_ms": result["latency_ms"]})
    return result
