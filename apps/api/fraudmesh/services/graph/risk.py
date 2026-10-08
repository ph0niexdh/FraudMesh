"""Graph risk: controlled propagation + structural signals.

Propagation is *max-product* over bounded paths (≤ 3 hops) from seed entities
(flagged or intrinsically risky):

    risk(v) = max over paths s→v of  risk(s) · Π_e [confidence(e) · transfer(type(e)) · decay(e)] · DAMPING^(hops-1)

* ``transfer`` encodes how much suspicion a relationship type carries
  (sharing a device is strong evidence; sharing a CGNAT IP is weak),
* ``decay`` halves an edge's weight every 30 days since it was last seen,
* ``DAMPING`` makes every additional hop count for less.

Max-product (rather than sum) guarantees a single malicious node cannot turn a
whole neighbourhood "fraudulent": risk only flows along the single strongest
chain of evidence, and never exceeds the seed's own risk.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fraudmesh.detection.base import DetectorResult, Reason
from fraudmesh.services.graph import store
from fraudmesh.services.metrics.telemetry import telemetry

TRANSFER = {
    "OWNS": 0.95,
    "USES": 0.85,
    "SHARES_DEVICE": 0.8,
    "SENT_TO": 0.7,
    "CREATED": 0.8,
    "VERIFIED_BY": 0.9,
    "AUTHENTICATED_WITH": 0.5,
    "LOGGED_IN_FROM": 0.55,
    "LINKED_TO": 0.5,
    "ACCESSED": 0.5,
    "ASSOCIATED_WITH": 0.6,
    "SHARES_IP": 0.35,
    "RECEIVED_FROM": 0.7,
}
DAMPING = 0.75
HALF_LIFE_DAYS = 30.0
MAX_HOPS = 3
SEED_MIN = 0.5
INTEL_SEEDED = {"IP", "NetworkIndicator"}


def _decay(last_seen: str | None, now: datetime) -> float:
    if not last_seen:
        return 1.0
    try:
        dt = datetime.fromisoformat(last_seen)
    except ValueError:
        return 1.0
    days = max(0.0, (now - dt).total_seconds() / 86400)
    return 0.5 ** (days / HALF_LIFE_DAYS)


def propagate(nodes: list[dict], edges: list[dict], now: datetime | None = None, ignore_flag_reason: str | None = None) -> dict[str, dict]:
    """Return {node_id: {"risk", "source", "path"}} for every node reached from a seed."""
    now = now or datetime.now(timezone.utc)
    adj: dict[str, list[tuple[str, float, str]]] = {}
    # Case nodes annotate conclusions; they are never evidence for propagation.
    case_nodes = {n["id"] for n in nodes if n.get("type") == "Case"}
    nodes = [n for n in nodes if n["id"] not in case_nodes]
    edges = [e for e in edges if e["src"] not in case_nodes and e["dst"] not in case_nodes]
    for e in edges:
        w = e["confidence"] * TRANSFER.get(e["type"], 0.4) * _decay(e.get("last_seen"), now)
        adj.setdefault(e["src"], []).append((e["dst"], w, e["type"]))
        adj.setdefault(e["dst"], []).append((e["src"], w, e["type"]))
    best: dict[str, dict] = {}
    # Seeds are independent evidence only: analyst/case flags, or risk that comes from
    # threat intelligence (IPs, network indicators). Risk copied onto nodes from the very
    # events being scored is NOT a seed — that would be circular.
    seeds = [n for n in nodes if (n.get("flagged") or (n.get("type") in INTEL_SEEDED and n.get("risk", 0) >= SEED_MIN))
             and not (ignore_flag_reason and ignore_flag_reason in (n.get("flag_reason") or ""))]
    for s in seeds:
        base = max(s.get("risk", 0.0), 0.9 if s.get("flagged") else 0.0)
        frontier = [(s["id"], base, [s["id"]], [])]
        for hop in range(1, MAX_HOPS + 1):
            nxt = []
            for nid, r, path, rels in frontier:
                for other, w, rel in adj.get(nid, []):
                    if other in path:
                        continue
                    rr = r * w * (DAMPING ** (hop - 1))
                    if rr < 0.05:
                        continue
                    cur = best.get(other)
                    if cur is None or rr > cur["risk"]:
                        best[other] = {"risk": rr, "source": s["id"], "path": path + [other], "rels": rels + [rel], "hops": hop}
                        nxt.append((other, rr, path + [other], rels + [rel]))
            frontier = nxt
    return best


async def score(entity_ids: list[str], subject_ids: list[str], ignore_case_id: str | None = None) -> DetectorResult:
    """Graph risk for an event/case: propagated risk at the subject entities plus
    structural evidence (shared devices, mule beneficiaries, path to flagged)."""
    t = time.perf_counter()
    reasons: list[Reason] = []
    try:
        sub = await store.neighborhood(entity_ids, depth=2, limit=150)
    except Exception as exc:  # graph engine offline: report, do not guess
        return DetectorResult("graph-engine", "graph", 0.0, 0.0, [Reason("GRAPH_OFFLINE", str(exc)[:120])], "graph-v1", 0.0)
    nodes_by_id = {n["id"]: n for n in sub["nodes"]}
    # A case must not count its own conclusions as evidence (entities it flagged itself).
    prop = propagate(sub["nodes"], sub["edges"], ignore_flag_reason=ignore_case_id)

    subject_risk, subject_src = 0.0, None
    for sid in subject_ids:
        p = prop.get(sid)
        if p and p["source"] not in subject_ids and p["risk"] > subject_risk:
            subject_risk, subject_src = p["risk"], p
    if subject_src:
        src_node = nodes_by_id.get(subject_src["source"], {})
        chain = " → ".join(nodes_by_id.get(x, {}).get("label", x) for x in subject_src["path"])
        reasons.append(Reason("GRAPH_PROPAGATED", f"{subject_src['hops']}-hop link to {'flagged ' if src_node.get('flagged') else 'risky '}"
                              f"{src_node.get('type', 'entity')} ({chain})", round(subject_risk, 3)))

    structural = 0.0
    # shared devices with other customers
    for d in [n for n in sub["nodes"] if n["type"] == "Device" and n["id"] in entity_ids]:
        others = await store.shared_device_customers(d["id"], next((s for s in subject_ids if s.startswith("cust")), None))
        if others:
            flagged = sum(1 for o in others if o.get("flagged"))
            s = min(0.9, 0.25 + 0.15 * len(others) + 0.25 * flagged)
            structural = max(structural, s)
            reasons.append(Reason("SHARED_DEVICE", f"Device used by {len(others)} other customer(s){f', {flagged} flagged' if flagged else ''}", round(s, 3)))
    # beneficiary mule signals
    for b in [n for n in sub["nodes"] if n["type"] == "Beneficiary" and n["id"] in entity_ids]:
        inbound = await store.beneficiary_inbound(b["id"])
        if inbound["flagged_senders"] or inbound["senders"] >= 4 or inbound.get("flagged"):
            s = min(0.95, 0.2 + 0.08 * inbound["senders"] + 0.3 * inbound["flagged_senders"] + (0.4 if inbound.get("flagged") else 0))
            structural = max(structural, s)
            reasons.append(Reason("MULE_BENEFICIARY", f"Beneficiary {b['label']} receives from {inbound['senders']} customers"
                                  f"{f' ({inbound['flagged_senders']} previously flagged)' if inbound['flagged_senders'] else ''}", round(s, 3)))
    risk = max(subject_risk, structural)
    ms = (time.perf_counter() - t) * 1000
    telemetry.observe_inference("graph-engine", ms)
    return DetectorResult(
        detector="graph-engine", domain="graph", risk_score=round(100 * risk, 2),
        confidence=0.85 if sub["nodes"] else 0.3, reason_codes=reasons[:5], model_version="graph-propagation-v1", latency_ms=ms,
        metadata={"subgraph_nodes": len(sub["nodes"]), "subgraph_edges": len(sub["edges"]),
                  "propagated": {k: round(v["risk"], 3) for k, v in sorted(prop.items(), key=lambda kv: -kv[1]["risk"])[:15]}},
    )
