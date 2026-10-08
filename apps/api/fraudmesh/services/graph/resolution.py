"""Entity resolution: normalised event → typed entities + relationships.

Entity ids are deterministic (``dev:…``, ``ip:…``, ``ben:…``) so the same real-world
thing resolves to the same node across events and sources. Device identity uses the
client-provided device id when present, otherwise an HMAC of the fingerprint (the
raw fingerprint is never stored).

Relationship confidence reflects how strong the evidence for the link is:
system-of-record ownership is certain; an IP link is weak because of NAT/CGNAT.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fraudmesh.core.crypto import hmac_hex
from fraudmesh.domain import EntityType as E
from fraudmesh.domain import EventType
from fraudmesh.domain import RelType as R
from fraudmesh.services.graph.store import EdgeSpec, NodeSpec
from fraudmesh.services.ids import intel

REL_CONFIDENCE = {
    R.OWNS: 1.0,
    R.USES: 0.85,
    R.LOGGED_IN_FROM: 0.8,
    R.AUTHENTICATED_WITH: 0.9,
    R.VERIFIED_BY: 0.95,
    R.SHARES_DEVICE: 0.8,
    R.SHARES_IP: 0.45,
    R.SENT_TO: 1.0,
    R.RECEIVED_FROM: 1.0,
    R.ACCESSED: 0.9,
    R.CREATED: 1.0,
    R.LINKED_TO: 0.7,
    R.ASSOCIATED_WITH: 0.7,
}


@dataclass
class Resolved:
    nodes: list[NodeSpec] = field(default_factory=list)
    edges: list[EdgeSpec] = field(default_factory=list)
    entities: list[dict] = field(default_factory=list)  # stored on the event row

    def node(self, nid: str, etype: E, label: str, role: str, risk: float = 0.0, **meta) -> str:
        if not any(n.id == nid for n in self.nodes):
            self.nodes.append(NodeSpec(id=nid, type=etype.value, label=label, risk=risk, meta=meta))
            self.entities.append({"id": nid, "type": etype.value, "role": role, "label": label})
        return nid

    def edge(self, src: str, dst: str, rel: R, source: str, risk: float, confidence: float | None = None, **meta) -> None:
        self.edges.append(EdgeSpec(src=src, dst=dst, rel=rel.value, confidence=confidence if confidence is not None else REL_CONFIDENCE[rel],
                                   source=source, risk=risk, meta=meta))


def device_entity_id(device: dict | None) -> str | None:
    if not device:
        return None
    if device.get("id"):
        return f"dev:{device['id']}"
    if device.get("fingerprint"):
        return f"dev:fp-{hmac_hex('device:' + device['fingerprint'])[:16]}"
    return None


def ip_entity_id(ip: str | None) -> str | None:
    return f"ip:{ip}" if ip else None


def resolve(ev: dict, risk: float = 0.0, extra: dict | None = None) -> Resolved:
    """``ev`` is the normalised event dict (see pipeline.normalize). ``risk`` 0-1."""
    r = Resolved()
    et = EventType(ev["event_type"])
    src = ev.get("source", "api")
    p = ev.get("payload", {})
    extra = extra or {}

    cust = ev.get("customer_id")
    acct = ev.get("account_id")
    dev_id = device_entity_id(ev.get("device"))
    ip_id = ip_entity_id(ev.get("ip"))

    if cust:
        r.node(cust, E.CUSTOMER, extra.get("customer_label", cust), "subject")
    if acct:
        r.node(acct, E.ACCOUNT, extra.get("account_label", acct), "account")
        if cust:
            r.edge(cust, acct, R.OWNS, "core-banking", 0.0)
    if dev_id:
        d = ev.get("device") or {}
        label = " ".join(x for x in (d.get("model"), d.get("os")) if x) or dev_id
        r.node(dev_id, E.DEVICE, label, "device", emulator=d.get("emulator"), rooted=d.get("rooted"))
        if cust:
            r.edge(cust, dev_id, R.USES, src, risk, 0.9 if d.get("id") else 0.75)
    if ip_id:
        rep = intel.ip_reputation(ev.get("ip"))
        r.node(ip_id, E.IP, ev["ip"], "network", risk=rep["risk"], category=rep["category"])
        if cust:
            # CGNAT/residential pools are shared by many households: weaker link
            conf = 0.5 if rep["category"] == "residential_isp" else REL_CONFIDENCE[R.LOGGED_IN_FROM]
            r.edge(cust, ip_id, R.LOGGED_IN_FROM, src, risk, conf)
        if dev_id:
            r.edge(dev_id, ip_id, R.LINKED_TO, src, risk, 0.6)
    if ev.get("session_id") and cust:
        sid = f"ses:{ev['session_id']}"
        r.node(sid, E.SESSION, ev["session_id"][:12], "session")
        r.edge(cust, sid, R.ACCESSED, src, risk)
        if dev_id:
            r.edge(sid, dev_id, R.USES, src, risk, 0.95)

    if et == EventType.MFA and cust:
        mid = f"mfa:{cust}:{p.get('factor', 'totp')}"
        r.node(mid, E.MFA, f"{p.get('factor', 'totp').upper()} factor", "mfa")
        r.edge(cust, mid, R.AUTHENTICATED_WITH, src, risk)
    elif et == EventType.TRANSACTION:
        if p.get("beneficiary_id"):
            bid = f"ben:{p['beneficiary_id']}"
            r.node(bid, E.BENEFICIARY, p.get("beneficiary_name") or p["beneficiary_id"], "beneficiary")
            if acct:
                r.edge(acct, bid, R.SENT_TO, src, risk, amount=p.get("amount"))
            if risk >= 0.4 or p.get("amount", 0) >= 100_000:  # keep the graph bounded: notable transfers only
                tid = f"txn:{ev['id']}"
                r.node(tid, E.TRANSACTION, f"{p.get('currency', 'INR')} {p.get('amount', 0):,.0f}", "transaction", risk=risk)
                if acct:
                    r.edge(acct, tid, R.CREATED, src, risk)
                r.edge(tid, bid, R.SENT_TO, src, risk)
        if p.get("merchant_id"):
            mid = f"mer:{p['merchant_id']}"
            r.node(mid, E.MERCHANT, p["merchant_id"], "merchant")
            if acct:
                r.edge(acct, mid, R.SENT_TO, src, risk)
    elif et == EventType.BENEFICIARY and p.get("beneficiary_id"):
        bid = f"ben:{p['beneficiary_id']}"
        r.node(bid, E.BENEFICIARY, p.get("beneficiary_name") or p["beneficiary_id"], "beneficiary")
        if cust:
            r.edge(cust, bid, R.CREATED, src, risk)
    elif et in (EventType.KYC, EventType.BIOMETRIC, EventType.DEEPFAKE):
        if extra.get("doc_hmac") and cust:
            did = f"doc:{extra['doc_hmac'][:16]}"
            r.node(did, E.KYC_DOCUMENT, extra.get("doc_label", "Identity document"), "document", risk=risk)
            r.edge(cust, did, R.VERIFIED_BY, src, risk)
        if extra.get("face_id") and cust:
            fid = f"face:{extra['face_id']}"
            r.node(fid, E.FACE, "Face template", "face", risk=risk)
            r.edge(cust, fid, R.VERIFIED_BY, src, risk, 0.9)
    elif et in (EventType.NETWORK, EventType.IDS):
        for ind in extra.get("indicators", []):
            nid = f"ni:{ind['kind']}:{ind['value']}"[:80]
            r.node(nid, E.NETWORK_INDICATOR, ind["label"], "indicator", risk=ind.get("risk", risk))
            if ip_id:
                r.edge(ip_id, nid, R.ASSOCIATED_WITH, src, risk)
        dst = extra.get("dst_ip")
        if dst and ip_id:
            did = ip_entity_id(dst)
            rep = intel.ip_reputation(dst)
            r.node(did, E.IP, dst, "destination", risk=rep["risk"], category=rep["category"])
            r.edge(ip_id, did, R.ACCESSED, src, risk, 0.6)
    elif et == EventType.CLOUD:
        cid = f"cid:{p['principal']}"
        r.node(cid, E.CLOUD_IDENTITY, p["principal"], "cloud_identity")
        if p.get("resource"):
            rid = f"crs:{p['resource']}"[:80]
            r.node(rid, E.CLOUD_RESOURCE, p["resource"][-60:], "cloud_resource")
            r.edge(cid, rid, R.ACCESSED, src, risk, action=p.get("action"))
        if ip_id:
            r.edge(cid, ip_id, R.LOGGED_IN_FROM, src, risk)
    return r


def shared_entity_edges(r: Resolved, cust: str | None, others_by_device: list[dict], others_by_ip: list[dict], src: str) -> None:
    """Derived customer↔customer links once a device/IP is seen across customers."""
    if not cust:
        return
    for o in others_by_device:
        r.edge(cust, o["id"], R.SHARES_DEVICE, src, 0.5 if o.get("flagged") else 0.2)
    for o in others_by_ip[:10]:
        r.edge(cust, o["id"], R.SHARES_IP, src, 0.4 if o.get("flagged") else 0.1)
