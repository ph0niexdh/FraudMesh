"""Case explanations.

Because fusion is linear, each channel's contribution to the final risk is
exact: ``100 * weight * channel_score``. Within a channel, points are shared
between the fired signals in proportion to their detector-reported weights:

* transaction → positive TreeSHAP values from the XGBoost model
* takeover / cloud → the transparent rule points
* kyc → the heuristic indicator weights (or the controlled scenario value)
* graph → the noisy-OR component weights

These allocations are labelled "approximate share" in the UI; only the
transaction SHAP values themselves come from an explainer.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

CHANNEL_NAMES = {
    "transaction": "Transaction",
    "takeover": "Account takeover",
    "kyc": "KYC / media",
    "cloud": "Cloud security",
    "graph": "Entity graph",
    "temporal": "Temporal correlation",
}


def format_inr(amount: float) -> str:
    """Indian digit grouping: 185000 -> ₹1,85,000."""
    n = int(round(amount))
    s = str(abs(n))
    if len(s) > 3:
        head, tail = s[:-3], s[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        s = ",".join(groups + [tail])
    return f"{'-' if n < 0 else ''}₹{s}"


def describe_signal(name: str, detail: dict[str, Any], event: dict[str, Any], result: dict[str, Any]) -> str:
    md = event.get("metadata", {})
    d = result.get("details", {})
    if name == "amount_deviation":
        ratio = d.get("features", {}).get("amount_ratio", detail.get("value", 0))
        base = d.get("baseline_mean") or 0
        return f"{format_inr(event.get('amount', 0))} transfer is {ratio:.1f}× customer baseline (avg {format_inr(base)})"
    if name == "new_beneficiary":
        return f"Payment of {format_inr(event.get('amount', 0))} to a NEW beneficiary"
    if name == "velocity_spike":
        return f"Transaction velocity spike ({int(detail.get('value', 0))} in the last hour)"
    if name == "new_device":
        return f"New device login ({event.get('device_label') or 'unknown device'})"
    if name == "new_ip":
        city = md.get("city")
        return f"New IP / network ({event.get('ip_label') or 'unknown'}{', ' + city if city else ''})"
    if name == "mfa_reset":
        return "MFA reset during an active suspicious session"
    if name == "impossible_travel":
        return f"Impossible-travel-like login from {md.get('city', 'a distant location')}"
    if name == "kyc_manipulation":
        return f"KYC manipulation score = {float(detail.get('value', 0)):.2f} (prototype media detector)"
    if name == "privileged_api_call":
        return f"Unusual privileged cloud activity ({md.get('action', 'privileged API call')})"
    if name == "unusual_region":
        return f"Cloud API call from unusual region {md.get('region', '')}".strip()
    return detail.get("label") or name.replace("_", " ").capitalize()


def build_explanations(
    events: list[dict[str, Any]],
    contributions: dict[str, float],
    graph_result: dict[str, Any],
    temporal: dict[str, Any],
    suspicious_threshold: float,
) -> list[dict[str, Any]]:
    """Return ranked explanation items for a case."""
    candidates: dict[str, dict[str, Any]] = {}
    ordered = sorted(events, key=lambda e: e["timestamp"])

    # For each detector channel, the case score is the max over events, so the
    # channel's exact contribution is allocated across the signals of that peak event.
    peak: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    for ev in ordered:
        for res in ev.get("detector_results", []):
            ch = res.get("channel")
            if ch in contributions and ch not in ("graph", "temporal"):
                if ch not in peak or res.get("score", 0) > peak[ch][1].get("score", 0):
                    peak[ch] = (ev, res)

    def first_fired(ch: str, name: str) -> dict[str, Any] | None:
        """Earliest event where a (possibly accumulated) signal actually fired."""
        for ev in ordered:
            for res in ev.get("detector_results", []):
                if res.get("channel") != ch:
                    continue
                for sd in res.get("signal_details", []):
                    if sd["name"] == name and sd.get("current_event", True):
                        return ev
        return None

    for ch, (ev, res) in peak.items():
        if res.get("score", 0) < suspicious_threshold * 0.5:
            continue
        details = res.get("signal_details", [])
        total_w = sum(max(float(s.get("weight", 0)), 0.0) for s in details) or 1.0
        for s in details:
            name = s["name"]
            src = first_fired(ch, name) or ev
            item = {
                "signal": name,
                "text": describe_signal(name, s, src if ch == "takeover" else ev, res),
                "channel": ch,
                "channel_name": CHANNEL_NAMES.get(ch, ch),
                "detector": res.get("detector"),
                "contribution": round(contributions[ch] * max(float(s.get("weight", 0)), 0.0) / total_w, 2),
                "detector_score": res.get("score"),
                "event_id": src["event_id"],
                "event_type": src["event_type"],
                "timestamp": src["timestamp"],
                "value": s.get("value"),
            }
            key = f"{ch}:{name}"
            if key not in candidates or item["contribution"] > candidates[key]["contribution"]:
                candidates[key] = item

    g_signals = graph_result.get("signals", [])
    g_total = sum(s["weight"] for s in g_signals) or 1.0
    for s in g_signals:
        candidates[f"graph:{s['name']}"] = {
            "signal": s["name"], "text": s["label"], "channel": "graph", "channel_name": CHANNEL_NAMES["graph"],
            "detector": "entity_graph", "contribution": round(contributions.get("graph", 0) * s["weight"] / g_total, 2),
            "detector_score": graph_result.get("score"), "event_id": None, "event_type": None,
            "timestamp": None, "value": s.get("value"),
        }

    if temporal.get("suspicious_events", 0) >= 2:
        candidates["temporal_cluster"] = {
            "signal": "temporal_cluster",
            "text": (f"{temporal['suspicious_events']} correlated suspicious events across "
                     f"{temporal['channels']} channels within {temporal['span_minutes']:.0f} min"),
            "channel": "temporal", "channel_name": CHANNEL_NAMES["temporal"], "detector": "correlation_engine",
            "contribution": contributions.get("temporal", 0), "detector_score": temporal.get("score"),
            "event_id": None, "event_type": None, "timestamp": None, "value": temporal["suspicious_events"],
        }

    ranked = sorted(candidates.values(), key=lambda c: -c["contribution"])
    for i, item in enumerate(ranked, 1):
        item["rank"] = i
    return ranked


def summarize(explanations: list[dict[str, Any]], channel_scores: dict[str, float], threshold: float) -> str:
    active = [CHANNEL_NAMES[c].lower() for c, s in channel_scores.items() if s >= threshold and c in CHANNEL_NAMES]
    if not active:
        return "Low-risk correlated activity."
    top = "; ".join(e["text"] for e in explanations[:3])
    kind = "Cross-channel" if len(active) >= 3 else "Correlated"
    return f"{kind} pattern across {', '.join(active)}. Top evidence: {top}."


def as_iso(ts: datetime | str | None) -> str | None:
    if ts is None or isinstance(ts, str):
        return ts
    return ts.isoformat()
