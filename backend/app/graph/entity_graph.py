"""Entity graph built with NetworkX.

Nodes: customer, account, device, ip, transaction, kyc, cloud_resource,
cloud_principal. Edges (MultiDiGraph keyed by relation): OWNS, USED,
LOGGED_IN_FROM, INITIATED, VERIFIED_WITH, ACCESSED, CREATED, ASSOCIATED_WITH.

The graph risk score is a transparent noisy-OR of structural indicators
(shared devices, cross-bank links, shared IPs, mule beneficiaries,
watch-listed entities): ``1 - Π(1 - c_i)``.
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime
from typing import Any, Iterable

import networkx as nx

from app.schemas.events import EventType, NormalizedEvent
from app.utils.timeutil import iso

HUB_TYPES = {"cloud_principal", "cloud_resource", "ip"}
ENTITY_TYPES = ("customer", "account", "device", "ip", "kyc", "cloud_resource", "cloud_principal", "transaction")


def _shared_account_weight(n: int) -> float:
    return 0.0 if n < 2 else {2: 0.5, 3: 0.75}.get(n, 0.9)


class EntityGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()
        self.lock = threading.RLock()

    def reset(self) -> None:
        with self.lock:
            self.g.clear()

    # ---------------------------------------------------------------- building
    def _node(self, node_id: str | None, ntype: str, ts: datetime, label: str | None = None,
              signal: float = 0.0, added: list | None = None, **attrs: Any) -> str | None:
        if not node_id:
            return None
        if node_id not in self.g:
            self.g.add_node(node_id, type=ntype, label=label or node_id, first_seen=ts, last_seen=ts,
                            max_signal=signal, watchlist=False, trusted=False, events=0, **attrs)
            if added is not None:
                added.append(node_id)
        else:
            data = self.g.nodes[node_id]
            data["last_seen"] = max(data["last_seen"], ts)
            data["max_signal"] = max(data.get("max_signal", 0.0), signal)
            if label and data.get("label") == node_id:
                data["label"] = label
            for k, v in attrs.items():
                if v is not None:
                    data[k] = v
        self.g.nodes[node_id]["events"] += 1
        return node_id

    def _edge(self, u: str | None, v: str | None, rel: str, ts: datetime, event_id: str,
              added: list | None = None) -> None:
        if not u or not v or u == v:
            return
        if self.g.has_edge(u, v, key=rel):
            data = self.g.edges[u, v, rel]
            data["count"] += 1
            data["last_seen"] = max(data["last_seen"], ts)
            data["event_ids"] = (data["event_ids"] + [event_id])[-5:]
        else:
            self.g.add_edge(u, v, key=rel, relation=rel, count=1, first_seen=ts, last_seen=ts, event_ids=[event_id])
            if added is not None:
                added.append({"source": u, "target": v, "relation": rel})

    def add_event(self, ev: NormalizedEvent, labels: dict[str, str | None], signal: float = 0.0) -> dict[str, list]:
        """Insert the entities and relationships of one event. Returns what was added."""
        nodes_added: list[str] = []
        edges_added: list[dict] = []
        md = ev.metadata
        ts = ev.timestamp
        eid = ev.event_id
        with self.lock:
            cust = self._node(ev.customer_token, "customer", ts, labels.get("customer"), signal, nodes_added)
            acct = self._node(ev.account_token, "account", ts, labels.get("account"), signal, nodes_added,
                              bank=md.get("bank_name"), beneficiary=False)
            dev = self._node(ev.device_token, "device", ts, labels.get("device"), signal, nodes_added)
            ip = self._node(ev.ip_token, "ip", ts, labels.get("ip"), signal, nodes_added, city=md.get("city"))
            self._edge(cust, acct, "OWNS", ts, eid, edges_added)

            if ev.event_type == EventType.cloud_event:
                prn = self._node(md.get("principal_token"), "cloud_principal", ts,
                                 md.get("principal_display") or md.get("principal_token"), signal, nodes_added)
                res = self._node(md.get("resource_token"), "cloud_resource", ts,
                                 md.get("resource_label") or md.get("resource_token"), signal, nodes_added)
                self._edge(ip, prn, "ASSOCIATED_WITH", ts, eid, edges_added)
                self._edge(prn, res, "CREATED" if md.get("resource_created") else "ACCESSED", ts, eid, edges_added)
                self._edge(acct, prn, "ASSOCIATED_WITH", ts, eid, edges_added)
                return {"nodes": nodes_added, "edges": edges_added}

            self._edge(acct or cust, dev, "USED", ts, eid, edges_added)
            self._edge(dev or acct or cust, ip, "LOGGED_IN_FROM", ts, eid, edges_added)
            if md.get("previous_device_token"):
                prev = self._node(md["previous_device_token"], "device", ts, md.get("previous_device_label"), 0.0,
                                  nodes_added)
                self._edge(dev, prev, "ASSOCIATED_WITH", ts, eid, edges_added)

            if ev.event_type == EventType.transaction:
                txn = self._node(f"txn_{eid}", "transaction", ts, f"₹{ev.amount:,.0f}", signal, nodes_added,
                                 amount=ev.amount, event_id=eid)
                self._edge(acct or cust, txn, "INITIATED", ts, eid, edges_added)
                ben_tok = md.get("beneficiary_token")
                known = ben_tok in self.g if ben_tok else False
                ben = self._node(ben_tok, "account", ts, md.get("beneficiary_label") or "Beneficiary", signal,
                                 nodes_added, **({} if known else {"beneficiary": True}))
                self._edge(txn, ben, "ASSOCIATED_WITH", ts, eid, edges_added)
            elif ev.event_type == EventType.kyc_verification:
                kyc = self._node(md.get("kyc_token") or f"kyc_ev_{eid}", "kyc", ts, "KYC record", signal, nodes_added,
                                 event_id=eid)
                self._edge(cust or acct, kyc, "VERIFIED_WITH", ts, eid, edges_added)
                self._edge(kyc, dev, "ASSOCIATED_WITH", ts, eid, edges_added)
        return {"nodes": nodes_added, "edges": edges_added}

    def set_watchlist(self, tokens: Iterable[str], value: bool = True) -> None:
        with self.lock:
            for t in tokens:
                if t in self.g:
                    self.g.nodes[t]["watchlist"] = value

    # ---------------------------------------------------------------- queries
    def _neighbors(self, node: str, ntype: str | None = None, rel: str | None = None) -> set[str]:
        out: set[str] = set()
        for _, v, k in self.g.out_edges(node, keys=True):
            if (rel is None or k == rel) and (ntype is None or self.g.nodes[v]["type"] == ntype):
                out.add(v)
        for u, _, k in self.g.in_edges(node, keys=True):
            if (rel is None or k == rel) and (ntype is None or self.g.nodes[u]["type"] == ntype):
                out.add(u)
        return out

    def accounts_for_device(self, device: str) -> set[str]:
        return {a for a in self._neighbors(device, "account", "USED") if not self.g.nodes[a].get("beneficiary")}

    def accounts_for_ip(self, ip: str) -> set[str]:
        accts = {a for a in self._neighbors(ip, "account") if not self.g.nodes[a].get("beneficiary")}
        for dev in self._neighbors(ip, "device", "LOGGED_IN_FROM"):
            accts |= self.accounts_for_device(dev)
        return accts

    def owner(self, account: str) -> str | None:
        owners = self._neighbors(account, "customer", "OWNS")
        return next(iter(sorted(owners)), None)

    def identity_count(self, accounts: set[str]) -> int:
        """Distinct owners behind a set of accounts (one person with two bank accounts counts once)."""
        return len({self.owner(a) or a for a in accounts})

    def bank(self, account: str) -> str | None:
        return self.g.nodes[account].get("bank") if account in self.g else None

    def score_entities(self, tokens: Iterable[str]) -> dict[str, Any]:
        """Graph risk over a set of entity tokens (an event's or a whole case's)."""
        comps: list[dict[str, Any]] = []
        with self.lock:
            tokens = [t for t in set(tokens) if t and t in self.g]
            devices = [t for t in tokens if self.g.nodes[t]["type"] == "device"]
            ips = [t for t in tokens if self.g.nodes[t]["type"] == "ip"]
            bens = [t for t in tokens if self.g.nodes[t].get("beneficiary")]
            best_dev: tuple[int, str | None, set[str]] = (0, None, set())
            for d in devices:
                accts = self.accounts_for_device(d)
                n_ids = self.identity_count(accts)
                if n_ids > best_dev[0]:
                    best_dev = (n_ids, d, accts)
            if best_dev[0] >= 2:
                n_ids, d, accts = best_dev
                customers = {self.owner(a) for a in accts} - {None}
                banks = sorted({self.bank(a) for a in accts} - {None})
                comps.append({
                    "name": "device_reuse", "weight": _shared_account_weight(n_ids),
                    "label": f"Device {self.g.nodes[d]['label']} linked to {len(accts)} accounts "
                             f"({n_ids} distinct identities)",
                    "entity": d, "value": len(accts),
                    "accounts": [self.g.nodes[a]["label"] for a in sorted(accts)],
                })
                if len(customers) >= 2:
                    comps.append({"name": "device_multi_customer", "weight": 0.25, "entity": d,
                                  "label": f"Device shared by {len(customers)} different customers",
                                  "value": len(customers)})
                if len(banks) >= 2:
                    comps.append({"name": "cross_bank_link", "weight": 0.4 if len(banks) == 2 else 0.7, "entity": d,
                                  "label": f"Cross-bank entity relationship ({', '.join(banks)})",
                                  "value": len(banks), "banks": banks})
            for ip in ips:
                accts = self.accounts_for_ip(ip)
                n_ids = self.identity_count(accts)
                if n_ids >= 3:
                    comps.append({"name": "ip_shared_accounts", "weight": 0.3 if n_ids < 5 else 0.5,
                                  "entity": ip, "value": len(accts),
                                  "label": f"IP {self.g.nodes[ip]['label']} shared by {len(accts)} accounts "
                                           f"({n_ids} identities)"})
                    break
            for b in bens:
                payers = {u for txn in self._neighbors(b, "transaction") for u in self._neighbors(txn, "account", "INITIATED")}
                if len(payers) >= 3:
                    comps.append({"name": "mule_beneficiary", "weight": 0.4, "entity": b, "value": len(payers),
                                  "label": f"Beneficiary receives funds from {len(payers)} accounts"})
                    break
            watch = [t for t in tokens if self.g.nodes[t].get("watchlist")]
            if watch:
                comps.append({"name": "watchlisted_entity", "weight": 0.6, "entity": watch[0], "value": len(watch),
                              "label": "Entity previously confirmed in a fraud case"})
        prod = 1.0
        for c in comps:
            prod *= 1 - c["weight"]
        return {"score": round(1 - prod, 4), "signals": comps}

    def suspicious_paths(self, tokens: Iterable[str]) -> list[dict[str, Any]]:
        """Paths account → shared device/IP → other account(s) → owner."""
        paths: list[dict[str, Any]] = []
        with self.lock:
            tokens = {t for t in tokens if t and t in self.g}
            for hub in sorted(tokens):
                htype = self.g.nodes[hub]["type"]
                if htype not in ("device", "ip"):
                    continue
                accts = self.accounts_for_device(hub) if htype == "device" else self.accounts_for_ip(hub)
                if self.identity_count(accts) < 2:
                    continue
                case_accts = sorted(a for a in accts if a in tokens) or sorted(accts)[:1]
                for src in case_accts:
                    for dst in sorted(accts - {src}):
                        nodes = [n for n in (self.owner(src), src, hub, dst, self.owner(dst)) if n]
                        paths.append({"nodes": nodes, "hub": hub,
                                      "description": f"{self.g.nodes[src]['label']} → {self.g.nodes[hub]['label']} "
                                                     f"→ {self.g.nodes[dst]['label']}"})
        return paths[:20]

    def export(self, centers: Iterable[str], depth: int = 1, limit: int = 250,
               include_events: set[str] | None = None, hub_limit: int = 12) -> dict[str, Any]:
        """Undirected BFS neighbourhood around ``centers`` as JSON for the UI."""
        with self.lock:
            centers = [c for c in dict.fromkeys(centers) if c and c in self.g]
            seen: dict[str, int] = {c: 0 for c in centers}
            queue = deque(centers)
            und = self.g.to_undirected(as_view=True)
            while queue and len(seen) < limit:
                cur = queue.popleft()
                if seen[cur] >= depth:
                    continue
                # don't fan out through busy infrastructure hubs (e.g. a service principal used by
                # every corporate IP) — they add noise, not evidence
                if self.g.nodes[cur]["type"] in HUB_TYPES and und.degree(cur) > hub_limit:
                    continue
                for nb in und.neighbors(cur):
                    if nb in seen:
                        continue
                    data = self.g.nodes[nb]
                    if data["type"] in ("transaction", "kyc") and include_events is not None \
                            and data.get("event_id") not in include_events:
                        continue
                    seen[nb] = seen[cur] + 1
                    queue.append(nb)
                    if len(seen) >= limit:
                        break
            nodes = []
            for n in seen:
                d = self.g.nodes[n]
                nodes.append({
                    "id": n, "type": d["type"], "label": d.get("label", n), "bank": d.get("bank"),
                    "city": d.get("city"), "amount": d.get("amount"), "beneficiary": bool(d.get("beneficiary")),
                    "watchlist": bool(d.get("watchlist")), "max_signal": round(float(d.get("max_signal", 0)), 3),
                    "degree": int(und.degree(n)), "events": d.get("events", 0),
                    "first_seen": iso(d.get("first_seen")), "last_seen": iso(d.get("last_seen")),
                    "center": n in centers,
                })
            edges = []
            for u, v, k, d in self.g.edges(keys=True, data=True):
                if u in seen and v in seen:
                    edges.append({"id": f"{u}|{k}|{v}", "source": u, "target": v, "relation": k,
                                  "count": d["count"], "first_seen": iso(d["first_seen"]),
                                  "last_seen": iso(d["last_seen"]), "event_ids": d["event_ids"]})
            return {"nodes": nodes, "edges": edges}

    def stats(self) -> dict[str, Any]:
        with self.lock:
            counts: dict[str, int] = {}
            for _, d in self.g.nodes(data=True):
                counts[d["type"]] = counts.get(d["type"], 0) + 1
            shared = sum(1 for n, d in self.g.nodes(data=True)
                         if d["type"] == "device" and len(self.accounts_for_device(n)) >= 2)
            return {"nodes": self.g.number_of_nodes(), "edges": self.g.number_of_edges(), "by_type": counts,
                    "shared_devices": shared}
