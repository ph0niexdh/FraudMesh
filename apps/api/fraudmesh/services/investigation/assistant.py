"""Grounded case assistant ("InvestigationChat").

Design choices (security):
* No LLM and no tools: a question is classified into an intent by keyword rules and
  answered from stored case evidence only. Every answer lists its citations.
* The question is treated as data — it is never executed, interpolated into a
  query or used as an instruction, so prompt injection has nothing to act on.
* Unknown intents get a short list of what can be asked, not a guess.
"""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fraudmesh.db.models import Case, CaseEntity, CaseEvent, Detection, Event

INTENTS = [
    ("decision", r"\b(why|block|blocked|hold|decision|action|policy|stopp?ed)\b"),
    ("deepfake", r"\b(deepfake|fake|face|selfie|liveness|kyc|document|biometric|spoof)\b"),
    ("graph", r"\b(graph|link|linked|connected|mule|ring|beneficiary|shared|relationship)\b"),
    ("network", r"\b(network|ids|ip|zeek|suricata|traffic|dns|tls|botnet)\b"),
    ("transaction", r"\b(transaction|transfer|amount|payment|shap|feature)\b"),
    ("timeline", r"\b(timeline|happen|happened|sequence|story|order|when|first)\b"),
    ("next", r"\b(next|recommend|should|todo|do now|steps?)\b"),
    ("devices", r"\b(device|phone|emulator|handset)\b"),
    ("risk", r"\b(risk|score|contribut|confidence|severity)\b"),
]


def classify(q: str) -> str | None:
    ql = q.lower()
    for name, pat in INTENTS:
        if re.search(pat, ql):
            return name
    return None


async def answer(db: AsyncSession, case: Case, question: str) -> dict:
    intent = classify(question)
    f = case.fusion or {}
    cites: list[str] = []
    lines: list[str] = []
    if intent is None:
        return {"intent": None, "grounded": True, "citations": [],
                "answer": "I can only answer from this case's evidence. Try: why was it blocked, what happened first, "
                          "what did the deepfake detector find, how is the beneficiary linked, what network activity was seen, "
                          "what drove the transaction score, or what should I do next."}

    evs = (await db.execute(select(Event).join(CaseEvent, CaseEvent.event_id == Event.id).where(CaseEvent.case_id == case.id).order_by(Event.ts))).scalars().all()
    dets = (await db.execute(select(Detection).where(Detection.event_id.in_([e.id for e in evs])))).scalars().all()

    if intent in ("decision", "risk"):
        dec = f.get("decision") or {}
        lines.append(f"Attack score {case.risk_score:.0f}/100 ({case.severity}), confidence {case.confidence:.2f}.")
        if dec.get("policy"):
            lines.append(f"Policy {dec['policy']['id']} ({dec['policy']['name']}) selected {dec['action']}; "
                         f"{len(dec.get('matched', []))} polic{'y' if len(dec.get('matched', [])) == 1 else 'ies'} matched in total.")
        top = f.get("contributions", [])[:4]
        if top:
            lines.append("Largest contributions: " + ", ".join(f"{c['domain']} (risk {c['risk']:.0f}, {c['share'] * 100:.0f}% of evidence)" for c in top) + ".")
        if f.get("corroborating_domains"):
            lines.append(f"{len(f['corroborating_domains'])} independent domains corroborate each other: {', '.join(f['corroborating_domains'])}.")
    elif intent == "timeline":
        lines += case.story.split("\n")[:8] if case.story else ["No narrative available yet."]
        cites += [e.id for e in evs[:10]]
    elif intent == "deepfake":
        found = [d for d in dets if d.detector in ("deepfake-detector", "kyc-engine")]
        if not found:
            lines.append("No deepfake or KYC analysis is attached to this case.")
        for d in found:
            md = d.details.get("metadata", {})
            if d.detector == "deepfake-detector":
                lines.append(f"Deepfake detector ({d.model_version}): probability {md.get('deepfake_probability')}, verdict {md.get('verdict')}, "
                             f"liveness {md.get('liveness')}, confidence {d.confidence:.2f}.")
            else:
                fails = [r["message"] for r in d.reason_codes][:4]
                lines.append(f"KYC engine: risk {d.risk_score:.0f}, decision {md.get('decision')}" + (f"; failed: {'; '.join(fails)}" if fails else "") + ".")
            cites.append(d.event_id)
        lines.append("Note: deepfake scores are probabilistic evidence, not proof; review the frame-level evidence in the Deepfake tab.")
    elif intent == "graph":
        g = f.get("graph") or {}
        for r in g.get("reason_codes", []):
            lines.append(r["message"] + ".")
        ents = (await db.execute(select(CaseEntity).where(CaseEntity.case_id == case.id))).scalars().all()
        bens = [e.label for e in ents if e.entity_type == "Beneficiary"]
        if bens:
            lines.append(f"Beneficiaries in this case: {', '.join(bens)}.")
        if not lines:
            lines.append("The graph engine found no links from this case to flagged entities.")
    elif intent == "network":
        net = [d for d in dets if d.details.get("domain") == "network"]
        for d in sorted(net, key=lambda d: -d.risk_score)[:5]:
            for r in d.reason_codes[:2]:
                lines.append(f"[{d.detector}] {r['message']}")
            cites.append(d.event_id)
        if not net:
            lines.append("No network / IDS evidence is attached to this case.")
    elif intent == "transaction":
        t = next((d for d in sorted(dets, key=lambda d: -d.risk_score) if d.detector == "transaction-model"), None)
        if t is None:
            lines.append("No transaction was scored in this case.")
        else:
            md = t.details.get("metadata", {})
            lines.append(f"Transaction model ({t.model_version}): fraud probability {md.get('fraud_probability')}.")
            for s in (md.get("shap") or [])[1:6]:
                lines.append(f"• {s['label']}: SHAP {s['shap']:+.2f} ({s['direction']})")
            cites.append(t.event_id)
    elif intent == "devices":
        ents = (await db.execute(select(CaseEntity).where(CaseEntity.case_id == case.id, CaseEntity.entity_type == "Device"))).scalars().all()
        for e in ents:
            lines.append(f"Device {e.label} ({e.entity_id}).")
        dev = [d for d in dets if d.detector == "device-intel" and d.risk_score > 0]
        for d in dev[:3]:
            lines += [r["message"] for r in d.reason_codes[:3]]
        if not lines:
            lines.append("No device evidence in this case.")
    elif intent == "next":
        steps = {
            "BLOCK": ["Confirm the transfer stayed blocked and notify the customer through a verified channel.",
                      "Revoke all sessions and reset credentials; re-enrol MFA in branch or via verified video KYC.",
                      "Freeze the receiving beneficiary and file a mule report.",
                      "Record CONFIRMED_FRAUD feedback so attacker infrastructure seeds graph risk."],
            "HOLD": ["Contact the customer out-of-band before releasing anything.", "Review the deepfake and KYC evidence; request a fresh live verification.",
                     "Release the hold or block based on the outcome and record feedback."],
            "STEP_UP": ["Require step-up authentication and monitor the session.", "Escalate if further risky events correlate."],
        }.get(case.recommended_action, ["Monitor; no immediate action required by policy."])
        lines += [f"{i + 1}. {s}" for i, s in enumerate(steps)]
    return {"intent": intent, "grounded": True, "citations": sorted(set(cites)), "answer": "\n".join(lines)}
