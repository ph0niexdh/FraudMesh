"""Counterfactual defence analysis and earliest-intervention replay.

Counterfactuals rebuild the case's evidence with one factor changed and push it
back through the *same* models and policy:

* the transaction model is re-scored on modified features (stored at decision time),
* the behaviour model is re-scored on modified session features,
* identity / device scorecard reasons that depended on the factor are dropped,
* temporal sequences are re-matched on the modified event list,
* fusion + policy are re-evaluated.

So "what if the deepfake signal were absent?" answers with what FraudMesh would
actually have done, not with a subtraction.
"""

from __future__ import annotations

import copy
import math
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.db.models import Case, CaseEvent, Customer, Detection, Event
from fraudmesh.domain import risk_level
from fraudmesh.services.behavior.detector import behavior_detector
from fraudmesh.services.correlation import temporal
from fraudmesh.services.fusion import engine as fusion
from fraudmesh.services.policy import engine as policy
from fraudmesh.services.transaction.detector import transaction_detector

KYC_CRITICAL_WEIGHT = 45.0  # weight of a failed critical KYC check (kyc.pipeline._SEVERITY_WEIGHT)

SCENARIOS = {
    "no_deepfake": "What if the deepfake signal had not existed?",
    "trusted_device": "What if the device had been a trusted, known device?",
    "no_mfa_reset": "What if the MFA reset had not occurred?",
    "normal_amount": "What if the transaction amount had been normal for this customer?",
    "no_network": "What if network / IDS telemetry had been unavailable?",
    "siloed": "What if each detector had acted alone (no correlation)?",
}


async def _load(db: AsyncSession, case: Case) -> tuple[list[dict], list[dict], dict]:
    events = (await db.execute(select(Event).join(CaseEvent, CaseEvent.event_id == Event.id).where(CaseEvent.case_id == case.id).order_by(Event.ts))).scalars().all()
    dets = (await db.execute(select(Detection).where(Detection.event_id.in_([e.id for e in events])))).scalars().all()
    evs = [{"id": e.id, "ts": e.ts, "event_type": e.event_type, "payload": copy.deepcopy(e.payload), "risk_score": e.risk_score,
            "reason_codes": copy.deepcopy(e.reason_codes or []), "ctx": copy.deepcopy((e.payload or {}).get("_ctx", {})), "ip": e.ip,
            "customer_id": e.customer_id} for e in events]
    ds = [{"event_id": d.event_id, "detector": d.detector, "domain": d.details.get("domain"), "risk_score": d.risk_score,
           "confidence": d.confidence, "reason_codes": copy.deepcopy(d.reason_codes), "model_version": d.model_version,
           "metadata": copy.deepcopy(d.details.get("metadata", {}))} for d in dets]
    profile = {}
    if case.primary_customer_id:
        c = await db.get(Customer, case.primary_customer_id)
        profile = (c.profile or {}) if c else {}
    return evs, ds, profile


def _noisy_or(ws: list[float]) -> float:
    p = 1.0
    for w in ws:
        p *= 1 - max(0.0, min(1.0, w))
    return 1 - p


def _rescore_identity(d: dict, drop_prefixes: tuple[str, ...]) -> None:
    keep = [r for r in d["reason_codes"] if not r["code"].startswith(drop_prefixes)]
    if len(keep) != len(d["reason_codes"]):
        d["reason_codes"] = keep
        d["risk_score"] = round(100 * _noisy_or([r.get("weight", 0) for r in keep]), 2)


def _rescore_txn(d: dict, changes: dict) -> None:
    feats = d["metadata"].get("features")
    if not feats:
        return
    raw = {**feats, **changes}
    _, p, _ = transaction_detector.predict_raw(raw)
    d["risk_score"] = round(100 * p, 2)
    d["metadata"]["fraud_probability"] = round(p, 4)


def _rescore_behavior(d: dict, changes: dict) -> None:
    feats = d["metadata"].get("features")
    if not feats:
        return
    d["risk_score"] = behavior_detector.score({**feats, **changes}).risk_score


def apply(name: str, evs: list[dict], ds: list[dict], profile: dict) -> tuple[list[dict], list[dict], list[str]]:
    evs, ds = copy.deepcopy(evs), copy.deepcopy(ds)
    notes: list[str] = []
    if name == "no_deepfake":
        ds = [d for d in ds if d["domain"] != "deepfake"]
        for e in evs:
            e["ctx"]["deepfake_risk"] = 0.0
            e["reason_codes"] = [r for r in e["reason_codes"] if not r["code"].startswith(("DF_", "ARTIFACT_", "LIVENESS", "IDENTITY_FLICKER"))]
        for d in ds:
            if d["detector"] == "transaction-model":
                _rescore_txn(d, {"deepfake_risk": 0.0})
            if d["detector"] == "kyc-engine":
                # drop the media-manipulation checks; document checks (MRZ, dates, re-use) stay
                media_codes = ("KYC_SELFIE_DEEPFAKE", "KYC_PORTRAIT_MANIPULATION", "KYC_SELFIE_LIVENESS")
                removed = [r for r in d["reason_codes"] if r["code"] in media_codes]
                d["reason_codes"] = [r for r in d["reason_codes"] if r["code"] not in media_codes]
                d["risk_score"] = max(0.0, d["risk_score"] - KYC_CRITICAL_WEIGHT * len(removed))
        notes.append("Deepfake detector outputs removed; transaction model re-scored with deepfake_risk = 0.")
    elif name == "trusted_device":
        ds = [d for d in ds if d["domain"] != "device"]
        for e in evs:
            e["ctx"].update(is_new_device=False, device_age_days=400.0)
        for d in ds:
            if d["detector"] == "transaction-model":
                _rescore_txn(d, {"is_new_device": False, "device_age_days": 400.0, "device_shared_customers": 0})
            elif d["detector"] == "behavior-model":
                _rescore_behavior(d, {"device_change": 0.0})
            elif d["detector"] == "identity-risk":
                _rescore_identity(d, ("ID_NEW_DEVICE", "ID_MFA_RESET_AFTER_NEW_DEVICE", "ID_BENEF_NEW_DEVICE"))
        notes.append("Device treated as known/trusted: device scorecard removed, models re-scored.")
    elif name == "no_mfa_reset":
        removed = {e["id"] for e in evs if e["event_type"] == "MFA" and e["payload"].get("action") in ("reset", "disabled", "factor_changed")}
        evs = [e for e in evs if e["id"] not in removed]
        ds = [d for d in ds if d["event_id"] not in removed]
        for d in ds:
            if d["detector"] == "transaction-model":
                _rescore_txn(d, {"mfa_changes_24h": 0})
            elif d["detector"] == "identity-risk":
                _rescore_identity(d, ("ID_BENEF_AFTER_MFA",))
        notes.append(f"{len(removed)} MFA change event(s) removed from the case.")
    elif name == "normal_amount":
        typical = math.exp(float(profile.get("log_amount_mean", 7.3)))
        for e in evs:
            if e["event_type"] == "TRANSACTION":
                e["payload"]["amount"] = round(typical, 0)
        for d in ds:
            if d["detector"] == "transaction-model":
                feats = d["metadata"].get("features", {})
                bal = feats.get("amount", 1) / max(feats.get("amount_to_balance", 1e-6), 1e-6)
                _rescore_txn(d, {"amount": typical, "amount_deviation": 0.0, "amount_to_balance": typical / max(bal, 1.0), "spend_24h_ratio": 1.0})
            elif d["detector"] == "behavior-model":
                _rescore_behavior(d, {"amount_deviation": 0.0})
        notes.append(f"Transfer amounts set to the customer's typical ₹{typical:,.0f}; models re-scored.")
    elif name == "no_network":
        ds = [d for d in ds if d["domain"] != "network"]
        evs = [e for e in evs if e["event_type"] not in ("NETWORK", "IDS")]
        for d in ds:
            if d["detector"] == "transaction-model":
                _rescore_txn(d, {"network_risk": 0.0, "ip_risk": 0.0})
        notes.append("Network / IDS events and IP reputation removed.")
    elif name == "siloed":
        notes.append("Each detector evaluated alone; the highest single-detector decision is shown.")
    else:
        raise KeyError(name)
    return evs, ds, notes


def evaluate(evs: list[dict], ds: list[dict], graph_result: dict | None, policies: list[dict], max_amount: float) -> dict:
    seq, _ = temporal.analyze(evs)
    results = [d for d in ds if d["domain"] not in ("graph", "temporal")]
    if graph_result:
        results.append(graph_result)
    results.append(seq.to_dict())
    fused = fusion.fuse(fusion.collapse(results))
    dom = {c["domain"]: c["risk"] for c in fused["contributions"]}
    decision = policy.evaluate(policies, {
        "attack_score": fused["attack_score"], "risk_level": fused["risk_level"], "confidence": fused["confidence"], "event_type": "CASE",
        "amount": max_amount, **{f"{d}_risk": dom.get(d, 0.0) for d in ("transaction", "deepfake", "identity", "graph", "network", "behavior", "device", "temporal")},
    })
    return {"attack_score": fused["attack_score"], "logit": fused["logit"], "risk_level": fused["risk_level"], "action": decision["action"],
            "policy": decision.get("policy"), "contributions": fused["contributions"],
            "temporal_pattern": (seq.metadata.get("best") or {}).get("name") if seq.metadata else None}


def replay(evs: list[dict], ds: list[dict], graph_result: dict | None, policies: list[dict]) -> dict:
    """Fused score and policy decision after each event, in time order."""
    trajectory, earliest = [], None
    first_txn = next((e for e in evs if e["event_type"] == "TRANSACTION" and e["payload"].get("amount", 0) >= 50_000), None)
    for i in range(len(evs)):
        prefix = evs[: i + 1]
        ids = {e["id"] for e in prefix}
        pds = [d for d in ds if d["event_id"] in ids]
        g = graph_result if any(d["domain"] == "graph" for d in pds) else None
        amount = max((e["payload"].get("amount", 0) for e in prefix if e["event_type"] == "TRANSACTION"), default=0.0)
        r = evaluate(prefix, pds, g, policies, amount)
        ev = prefix[-1]
        point = {"index": i, "event_id": ev["id"], "event_type": ev["event_type"], "ts": ev["ts"].isoformat(),
                 "attack_score": r["attack_score"], "logit": r["logit"], "risk_level": r["risk_level"], "action": r["action"]}
        trajectory.append(point)
        if earliest is None and r["action"] in ("HOLD", "BLOCK"):
            earliest = point
    lead = None
    if earliest and first_txn:
        lead = round((first_txn["ts"] - datetime.fromisoformat(earliest["ts"])).total_seconds() / 60, 1)
    return {"trajectory": trajectory, "earliest": earliest, "minutes_before_transfer": lead}


async def counterfactual(db: AsyncSession, case: Case, name: str) -> dict:
    evs, ds, profile = await _load(db, case)
    policies = await policy.load(db)
    graph_result = (case.fusion or {}).get("graph")
    max_amount = max((e["payload"].get("amount", 0) for e in evs if e["event_type"] == "TRANSACTION"), default=0.0)
    original = evaluate(evs, ds, graph_result, policies, max_amount)
    if name == "siloed":
        singles = []
        for d in ds:
            alone = fusion.fuse(fusion.collapse([d]))
            dec = policy.evaluate(policies, {"attack_score": alone["attack_score"], "risk_level": alone["risk_level"], "confidence": d["confidence"],
                                             "event_type": "CASE", "amount": max_amount, f"{d['domain']}_risk": d["risk_score"]})
            singles.append({"detector": d["detector"], "domain": d["domain"], "risk": d["risk_score"], "score_alone": alone["attack_score"],
                            "action_alone": dec["action"]})
        best = max(singles, key=lambda s: s["score_alone"], default={"score_alone": 0.0, "action_alone": "ALLOW"})
        cf = {"attack_score": best["score_alone"], "risk_level": risk_level(best["score_alone"]).value,
              "action": best["action_alone"], "detectors": sorted(singles, key=lambda s: -s["score_alone"])[:12]}
        notes = ["Siloed view: every detector's output is fused on its own, as if no correlation existed."]
        timing = None
    else:
        m_evs, m_ds, notes = apply(name, evs, ds, profile)
        cf = evaluate(m_evs, m_ds, graph_result, policies, max_amount)
        before, after = replay(evs, ds, graph_result, policies), replay(m_evs, m_ds, graph_result, policies)
        timing = {
            "original_earliest": before["earliest"], "counterfactual_earliest": after["earliest"],
            "original_minutes_before_transfer": before["minutes_before_transfer"],
            "counterfactual_minutes_before_transfer": after["minutes_before_transfer"],
        }
        if before["earliest"] and after["earliest"]:
            shift = (datetime.fromisoformat(after["earliest"]["ts"]) - datetime.fromisoformat(before["earliest"]["ts"])).total_seconds() / 60
            timing["intervention_delay_min"] = round(shift, 1)
        elif before["earliest"] and not after["earliest"]:
            timing["intervention_delay_min"] = None
            notes.append("Without this signal FraudMesh would never have reached HOLD/BLOCK on this case.")
    orig_c = {c["domain"]: c["logit_contribution"] for c in original.get("contributions", [])}
    cf_c = {c["domain"]: c["logit_contribution"] for c in cf.get("contributions", [])}
    return {
        "scenario": name,
        "question": SCENARIOS[name],
        "original": original,
        "counterfactual": cf,
        "delta": round(cf["attack_score"] - original["attack_score"], 1),
        # attack scores saturate near 100; the logit is the un-squashed weight of evidence
        "evidence_delta_logit": round(cf.get("logit", 0.0) - original.get("logit", 0.0), 2) if "logit" in cf else None,
        "attack_odds_ratio": round(math.exp(cf["logit"] - original["logit"]), 4) if "logit" in cf else None,
        "contribution_changes": [{"domain": d, "before": round(orig_c.get(d, 0.0), 2), "after": round(cf_c.get(d, 0.0), 2)}
                                 for d in sorted(set(orig_c) | set(cf_c)) if round(orig_c.get(d, 0.0), 2) != round(cf_c.get(d, 0.0), 2)],
        "timing": timing,
        "decision_changed": cf["action"] != original["action"],
        "notes": notes,
        "method": "evidence rebuilt and re-scored through the same models, fusion and policy",
    }


async def intervention(db: AsyncSession, case: Case) -> dict:
    """Replay the case event-by-event: fused score and policy decision after each step."""
    evs, ds, _ = await _load(db, case)
    policies = await policy.load(db)
    r = replay(evs, ds, (case.fusion or {}).get("graph"), policies)
    earliest, lead = r["earliest"], r["minutes_before_transfer"]
    step_up = next((p for p in r["trajectory"] if p["action"] in ("STEP_UP", "HOLD", "BLOCK")), None)
    return {
        "trajectory": r["trajectory"],
        "earliest_hold_or_block": earliest,
        "earliest_step_up": step_up,
        "minutes_before_transfer": lead,
        "recommendation": (
            f"Intervene at step {earliest['index'] + 1} ({earliest['event_type']}) with {earliest['action']}"
            + (f" — {lead:.0f} min before the high-value transfer." if lead and lead > 0 else ".")
        ) if earliest else "No point in the timeline reached a HOLD/BLOCK decision.",
    }


def siloed_timeline(evs: list[dict], ds: list[dict], policies: list[dict]) -> list[dict]:
    """What each event would have triggered if every detector were a separate tool that
    only sees its own output (no correlation, not even within the same event)."""
    from fraudmesh.domain import ACTION_SEVERITY, Action

    out = []
    for e in evs:
        own = [d for d in ds if d["event_id"] == e["id"]]
        if not own:
            continue
        best = None
        for d in own:
            alone = fusion.fuse(fusion.collapse([d]))
            dec = policy.evaluate(policies, {"attack_score": alone["attack_score"], "risk_level": alone["risk_level"], "confidence": d["confidence"],
                                             "event_type": e["event_type"], "amount": e["payload"].get("amount", 0.0), f"{d['domain']}_risk": d["risk_score"]})
            action = dec["action"]
            if e["event_type"] in ("NETWORK", "IDS", "CLOUD") and action in ("STEP_UP", "HOLD"):
                action = "MONITOR"
            cand = {"detector": d["detector"], "score_alone": alone["attack_score"], "action_alone": action}
            if best is None or (ACTION_SEVERITY[Action(action)], alone["attack_score"]) > (ACTION_SEVERITY[Action(best["action_alone"])], best["score_alone"]):
                best = cand
        out.append({"event_id": e["id"], "event_type": e["event_type"], "ts": e["ts"].isoformat(), **best})
    return out


async def siloed_vs_fraudmesh(db: AsyncSession, case: Case) -> dict:
    evs, ds, _ = await _load(db, case)
    policies = await policy.load(db)
    silo = siloed_timeline(evs, ds, policies)
    mesh = replay(evs, ds, (case.fusion or {}).get("graph"), policies)
    first_silo_block = next((s for s in silo if s["action_alone"] in ("HOLD", "BLOCK") and s["event_type"] not in ("NETWORK", "IDS", "CLOUD")), None)
    gain = None
    if first_silo_block and mesh["earliest"]:
        gain = round((datetime.fromisoformat(first_silo_block["ts"]) - datetime.fromisoformat(mesh["earliest"]["ts"])).total_seconds() / 60, 1)
    return {"siloed_timeline": silo, "siloed_first_customer_block": first_silo_block, "fraudmesh_first_block": mesh["earliest"],
            "minutes_earlier": gain}
