"""Attack reconstruction narrative.

The story is assembled *only* from stored evidence: every sentence is produced by
a template that fires when a specific event / detector result exists, and each
sentence carries the ids of the events that support it. Nothing is generated
free-form, so there is nothing to hallucinate.
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from fraudmesh.config import get_settings


def _t(ts: datetime) -> str:
    return ts.astimezone(ZoneInfo(get_settings().timezone)).strftime("%H:%M")


def _gap(a: datetime, b: datetime) -> str:
    m = (b - a).total_seconds() / 60
    if m < 1:
        return "Seconds later"
    if m < 90:
        return f"{m:.0f} minute{'s' if round(m) != 1 else ''} later"
    return f"{m / 60:.1f} hours later"


def _inr(v: float) -> str:
    s = f"{v:,.0f}"
    # Indian digit grouping (₹1,85,000)
    n = f"{int(round(v))}"
    if len(n) > 3:
        head, tail = n[:-3], n[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        s = ",".join(groups + [tail])
    return f"₹{s}"


def build(case: dict, events: list[dict], detections: dict[str, list[dict]], fusion: dict, decision: dict | None,
          graph_result: dict | None, alerts: int) -> list[dict]:
    evs = sorted(events, key=lambda e: e["ts"])
    if not evs:
        return []
    out: list[dict] = []
    prev_ts: datetime | None = None
    subject = case.get("subject_label") or "The customer"

    def add(text: str, ev_ids: list[str]) -> None:
        out.append({"text": text, "evidence": ev_ids})

    skip: set[str] = set()
    for idx, ev in enumerate(evs):
        if ev["id"] in skip:
            continue
        et, p, ctx = ev["event_type"], ev["payload"], ev["payload"].get("_ctx", {})
        lead = (_gap(prev_ts, ev["ts"]) + ",") if prev_ts else f"At {_t(ev['ts'])},"
        dets = {d["detector"]: d for d in detections.get(ev["id"], [])}
        sentence = None
        if et == "LOGIN":
            if not p.get("success"):
                continue  # failed-login bursts are summarised below
            if any(r.get("code") == "ID_SUCCESS_AFTER_FAILURES" for r in ev.get("reason_codes", [])):
                who = next((x.get("label") for x in ev.get("entities", []) if x.get("type") == "Customer"), None) or subject
                add(f"{lead} a login for {who} succeeded after repeated failures from {ev.get('ip')} — a likely credential-stuffing hit.", [ev["id"]])
                prev_ts = ev["ts"]
                continue
            bits = []
            if ctx.get("is_new_device"):
                bits.append("a device never seen before")
            if ctx.get("ip_new"):
                cat = ctx.get("ip_category", "unclassified")
                net = f"a network flagged as {cat.replace('_', ' ')}" if ctx.get("ip_risk", 0) >= 0.5 else "an unfamiliar network"
                bits.append(f"{net} ({ev.get('ip')})")
            if bits:
                who = next((x.get("label") for x in ev.get("entities", []) if x.get("type") == "Customer"), None) or subject
                sentence = f"{lead} {who} signed in from {' and '.join(bits)}."
        elif et == "DEVICE" and ctx.get("is_new_device"):
            d = ev.get("device") or {}
            sentence = f"{lead} a new device ({' '.join(x for x in (d.get('model'), d.get('os')) if x) or 'unknown model'}) was registered to the account."
        elif et == "MFA" and p.get("action") in ("reset", "disabled", "factor_changed"):
            verb = {"reset": "reset", "disabled": "disabled", "factor_changed": "changed"}[p["action"]]
            dest = f" (OTP channel moved to {p['channel_changed_to']})" if p.get("channel_changed_to") else ""
            src = f" from {ev.get('ip')}" if ctx.get("ip_category") == "internal" else ""
            sentence = f"{lead} the {p.get('factor', 'MFA').upper()} factor was {verb}{dest}{src}."
        elif et in ("KYC", "BIOMETRIC", "DEEPFAKE"):
            df = dets.get("deepfake-detector")
            kyc = dets.get("kyc-engine") or dets.get("identity-risk")
            if df and df["metadata"].get("deepfake_probability") is not None:
                prob = df["metadata"]["deepfake_probability"]
                verdict = (df["metadata"].get("verdict") or "").replace("_", " ").lower()
                detail = "; ".join(x for x in (verdict, df["model_version"]) if x)
                sentence = (f"{lead} a {'KYC verification' if et == 'KYC' else 'biometric verification'} attempt produced a "
                            f"{prob:.2f} deepfake probability ({detail}).")
                if kyc and kyc["risk_score"] >= 40:
                    fails = [r["message"] for r in kyc["reason_codes"] if r["code"].startswith("KYC_")][:2]
                    if fails:
                        sentence += f" KYC checks failed: {'; '.join(fails)}."
            elif kyc and kyc["risk_score"] >= 40:
                sentence = f"{lead} identity verification scored {kyc['risk_score']:.0f}/100 risk."
        elif et == "BENEFICIARY" and p.get("action") == "added":
            sentence = f"{lead} a new beneficiary “{p.get('beneficiary_name') or p.get('beneficiary_id')}” was added."
        elif et == "TRANSACTION":
            t = dets.get("transaction-model")
            prob = t["metadata"]["fraud_probability"] if t else None
            new_b = " to a first-time beneficiary" if ctx.get("beneficiary_new") else ""
            if p["amount"] >= 50_000 or (prob or 0) >= 0.5:
                sentence = (f"{lead} a {_inr(p['amount'])} {p.get('channel', '').upper()} transfer{new_b} was initiated"
                            f"{f' (transaction model fraud probability {prob:.2f})' if prob is not None else ''}.")
        elif et in ("NETWORK", "IDS"):
            ids = dets.get("ids")
            if ids and ids["risk_score"] >= 50:
                # collapse the consecutive burst of network events into one sentence
                burst = [ev]
                for nxt in evs[idx + 1:]:
                    if nxt["event_type"] not in ("NETWORK", "IDS") or (nxt["ts"] - burst[-1]["ts"]).total_seconds() > 180:
                        break
                    burst.append(nxt)
                titles: list[str] = []
                for b in burst:
                    for d in detections.get(b["id"], []):
                        if d["detector"] == "ids":
                            for rc in d["reason_codes"][:3]:
                                t = rc["message"].split(" — ")[0]
                                if t not in titles:
                                    titles.append(t)
                skip.update(b["id"] for b in burst)
                src = ev.get("ip") or "an external host"
                if len(burst) > 1:
                    sentence = f"{lead} network monitoring raised {len(burst)} alerts for {src}: {'; '.join(titles[:4])}."
                else:
                    sentence = f"{lead} network monitoring reported for {src}: {'; '.join(titles[:3]) or 'suspicious traffic'}."
                add(sentence, [b["id"] for b in burst])
                prev_ts = burst[-1]["ts"]
                continue
        elif et == "CLOUD":
            c = dets.get("cloud-security")
            if c and c["risk_score"] >= 40:
                sentence = f"{lead} cloud principal {p.get('principal')} called {p.get('action')} from {ev.get('ip') or 'an unknown IP'}."
        if sentence:
            add(sentence, [ev["id"]])
            prev_ts = ev["ts"]

    failed = [e for e in evs if e["event_type"] == "LOGIN" and not e["payload"].get("success")]
    if len(failed) >= 3:
        add(f"{len(failed)} failed login attempts preceded the compromise.", [e["id"] for e in failed[:10]])

    if graph_result:
        for r in graph_result.get("reason_codes", [])[:2]:
            if r["code"] in ("MULE_BENEFICIARY", "SHARED_DEVICE", "GRAPH_PROPAGATED"):
                add(f"Entity graph: {r['message']}.", [])

    contrib = ", ".join(f"{c['domain']} {c['risk']:.0f}" for c in fusion["contributions"][:4])
    add(f"FraudMesh correlated {len(evs)} events ({alerts} raw alert{'s' if alerts != 1 else ''}) into this single case. "
        f"Fused attack score {fusion['attack_score']:.0f}/100 ({fusion['risk_level']}), driven by {contrib}.", [])
    if decision and decision.get("policy"):
        add(f"Policy {decision['policy']['id']} → {decision['action']}.", [])
    return out
