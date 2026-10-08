"""Neo4j entity graph.

Schema
------
Nodes carry two labels: ``:Entity`` plus their concrete type (``:Device``, ``:IP`` ...).

    (:Entity {id, type, label, risk, flagged, flag_reason, first_seen, last_seen, meta})

``id`` is unique (constraint on :Entity). Every relationship carries
``confidence, source, created_at, last_seen, risk, count, meta``.

Labels and relationship types cannot be Cypher parameters, so they are
interpolated only after being validated against the ``EntityType`` / ``RelType``
enums — never from raw user input.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from fraudmesh.core.graphdb import driver
from fraudmesh.domain import EntityType, RelType

logger = logging.getLogger(__name__)

_ENTITY_LABELS = {e.value for e in EntityType}
_REL_TYPES = {r.value for r in RelType}

MAX_NEIGHBORHOOD_NODES = 150


@dataclass
class NodeSpec:
    id: str
    type: str
    label: str
    risk: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class EdgeSpec:
    src: str
    dst: str
    rel: str
    confidence: float
    source: str
    risk: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)


SCHEMA_STATEMENTS = [
    "CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE",
    "CREATE INDEX entity_type IF NOT EXISTS FOR (e:Entity) ON (e.type)",
    "CREATE INDEX entity_flagged IF NOT EXISTS FOR (e:Entity) ON (e.flagged)",
    "CREATE INDEX entity_risk IF NOT EXISTS FOR (e:Entity) ON (e.risk)",
    *[f"CREATE INDEX {lbl.lower()}_id IF NOT EXISTS FOR (n:{lbl}) ON (n.id)" for lbl in sorted(_ENTITY_LABELS)],
]


def _label(t: str) -> str:
    if t not in _ENTITY_LABELS:
        raise ValueError(f"unknown entity type {t!r}")
    return t


def _rel(r: str) -> str:
    if r not in _REL_TYPES:
        raise ValueError(f"unknown relationship type {r!r}")
    return r


def _iso(ts: datetime | None = None) -> str:
    return (ts or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


async def ensure_schema() -> None:
    async with driver().session() as s:
        for stmt in SCHEMA_STATEMENTS:
            await s.run(stmt)


async def ping() -> float:
    t = time.perf_counter()
    async with driver().session() as s:
        await (await s.run("RETURN 1")).consume()
    return (time.perf_counter() - t) * 1000


async def upsert(nodes: list[NodeSpec], edges: list[EdgeSpec], ts: datetime | None = None) -> None:
    """Idempotently merge nodes and relationships (batched with UNWIND per label/type)."""
    now = _iso(ts)
    by_label: dict[str, list[dict]] = {}
    for n in nodes:
        by_label.setdefault(_label(n.type), []).append(
            {"id": n.id, "label": n.label, "risk": float(n.risk), "meta": json.dumps(n.meta, default=str)}
        )
    by_rel: dict[str, list[dict]] = {}
    for e in edges:
        by_rel.setdefault(_rel(e.rel), []).append(
            {
                "src": e.src,
                "dst": e.dst,
                "confidence": float(e.confidence),
                "source": e.source,
                "risk": float(e.risk),
                "meta": json.dumps(e.meta, default=str),
            }
        )
    async with driver().session() as s:
        for lbl, rows in by_label.items():
            await s.run(
                f"""
                UNWIND $rows AS row
                MERGE (n:Entity {{id: row.id}})
                ON CREATE SET n:{lbl}, n.type = '{lbl}', n.label = row.label, n.first_seen = $now,
                              n.risk = row.risk, n.flagged = false, n.meta = row.meta
                ON MATCH SET n.risk = CASE WHEN row.risk > coalesce(n.risk, 0) THEN row.risk ELSE n.risk END
                SET n.last_seen = $now
                """,
                rows=rows,
                now=now,
            )
        for rel, rows in by_rel.items():
            await s.run(
                f"""
                UNWIND $rows AS row
                MATCH (a:Entity {{id: row.src}}), (b:Entity {{id: row.dst}})
                MERGE (a)-[r:{rel}]->(b)
                ON CREATE SET r.created_at = $now, r.count = 0, r.source = row.source,
                              r.confidence = row.confidence, r.risk = row.risk, r.meta = row.meta
                SET r.last_seen = $now, r.count = r.count + 1,
                    r.confidence = CASE WHEN row.confidence > r.confidence THEN row.confidence ELSE r.confidence END,
                    r.risk = CASE WHEN row.risk > r.risk THEN row.risk ELSE r.risk END
                """,
                rows=rows,
                now=now,
            )


async def flag_entities(ids: list[str], risk: float, reason: str) -> None:
    async with driver().session() as s:
        await s.run(
            """
            UNWIND $ids AS id MATCH (n:Entity {id: id})
            SET n.flagged = true, n.flag_reason = $reason,
                n.risk = CASE WHEN $risk > coalesce(n.risk,0) THEN $risk ELSE n.risk END
            """,
            ids=ids,
            risk=float(risk),
            reason=reason,
        )


async def unflag_entities(ids: list[str]) -> None:
    async with driver().session() as s:
        await s.run(
            "UNWIND $ids AS id MATCH (n:Entity {id: id}) SET n.flagged = false, n.flag_reason = null, n.risk = 0.1",
            ids=ids,
        )


def _node_dict(n) -> dict:
    return {
        "id": n["id"],
        "type": n.get("type"),
        "label": n.get("label") or n["id"],
        "risk": float(n.get("risk") or 0.0),
        "flagged": bool(n.get("flagged")),
        "flag_reason": n.get("flag_reason"),
        "first_seen": n.get("first_seen"),
        "last_seen": n.get("last_seen"),
    }


def _rel_dict(r) -> dict:
    return {
        "src": r.start_node["id"],
        "dst": r.end_node["id"],
        "type": r.type,
        "confidence": float(r.get("confidence") or 0.0),
        "source": r.get("source"),
        "risk": float(r.get("risk") or 0.0),
        "count": int(r.get("count") or 1),
        "created_at": r.get("created_at"),
        "last_seen": r.get("last_seen"),
    }


async def neighborhood(seed_ids: list[str], depth: int = 2, limit: int = MAX_NEIGHBORHOOD_NODES) -> dict:
    """Bounded subgraph around seeds. Infrastructure hubs (nodes with very high degree,
    e.g. a merchant everybody pays) are not expanded through, so the result stays readable."""
    depth = max(1, min(depth, 3))
    limit = max(10, min(limit, MAX_NEIGHBORHOOD_NODES))
    async with driver().session() as s:
        res = await s.run(
            f"""
            MATCH (seed:Entity) WHERE seed.id IN $seeds
            CALL (seed) {{
                MATCH p = (seed)-[*1..{depth}]-(m:Entity)
                WHERE all(x IN nodes(p)[1..-1] WHERE COUNT {{ (x)--() }} <= 60)
                RETURN p LIMIT 400
            }}
            WITH collect(p) AS paths, collect(DISTINCT seed) AS seeds
            WITH seeds, [p IN paths | nodes(p)] AS nps, [p IN paths | relationships(p)] AS rps
            WITH seeds,
                 reduce(acc = [], ns IN nps | acc + ns) AS allNodes,
                 reduce(acc = [], rs IN rps | acc + rs) AS allRels
            UNWIND (seeds + allNodes) AS n
            WITH collect(DISTINCT n)[0..$limit] AS nodes, allRels
            UNWIND (CASE WHEN size(allRels) = 0 THEN [null] ELSE allRels END) AS r
            WITH nodes, collect(DISTINCT r) AS rels
            RETURN nodes, [r IN rels WHERE startNode(r) IN nodes AND endNode(r) IN nodes] AS rels
            """,
            seeds=seed_ids,
            limit=limit,
        )
        rec = await res.single()
    if rec is None:
        return {"nodes": [], "edges": []}
    return {"nodes": [_node_dict(n) for n in rec["nodes"]], "edges": [_rel_dict(r) for r in rec["rels"]]}


async def entity(entity_id: str) -> dict | None:
    async with driver().session() as s:
        rec = await (
            await s.run(
                """
                MATCH (n:Entity {id: $id})
                OPTIONAL MATCH (n)-[r]-(m:Entity)
                RETURN n, count(r) AS degree,
                       collect({type: type(r), other: m.id, other_type: m.type, other_label: m.label,
                                other_flagged: m.flagged, confidence: r.confidence, last_seen: r.last_seen,
                                outgoing: startNode(r) = n})[0..50] AS rels
                """,
                id=entity_id,
            )
        ).single()
    if rec is None or rec["n"] is None:
        return None
    d = _node_dict(rec["n"])
    d["degree"] = rec["degree"]
    d["relationships"] = rec["rels"]
    return d


async def shared_device_customers(device_id: str, exclude_customer: str | None) -> list[dict]:
    """Other customers whose accounts were accessed from the same device."""
    async with driver().session() as s:
        res = await s.run(
            """
            MATCH (d:Device {id: $device})<-[:USES]-(c:Customer)
            WHERE $exclude IS NULL OR c.id <> $exclude
            RETURN c.id AS id, c.label AS label, c.flagged AS flagged, c.risk AS risk LIMIT 25
            """,
            device=device_id,
            exclude=exclude_customer,
        )
        return [dict(r) async for r in res]


async def shared_ip_customers(ip_id: str, exclude_customer: str | None) -> list[dict]:
    async with driver().session() as s:
        res = await s.run(
            """
            MATCH (i:IP {id: $ip})<-[:LOGGED_IN_FROM]-(c:Customer)
            WHERE $exclude IS NULL OR c.id <> $exclude
            RETURN c.id AS id, c.label AS label, c.flagged AS flagged, c.risk AS risk LIMIT 25
            """,
            ip=ip_id,
            exclude=exclude_customer,
        )
        return [dict(r) async for r in res]


async def beneficiary_inbound(benef_id: str) -> dict:
    """Mule indicator: how many distinct customers pay this beneficiary, and how many are flagged."""
    async with driver().session() as s:
        rec = await (
            await s.run(
                """
                MATCH (b:Beneficiary {id: $id})
                OPTIONAL MATCH (b)<-[:SENT_TO]-(:Account)<-[:OWNS]-(c:Customer)
                WITH b, collect(DISTINCT c) AS cs
                RETURN size(cs) AS senders, size([c IN cs WHERE c.flagged]) AS flagged_senders,
                       b.flagged AS flagged, b.risk AS risk
                """,
                id=benef_id,
            )
        ).single()
    if rec is None:
        return {"senders": 0, "flagged_senders": 0, "flagged": False, "risk": 0.0}
    return dict(rec)


async def shortest_suspicious_path(entity_id: str, max_hops: int = 4) -> dict | None:
    """Shortest path from an entity to any *other* flagged entity (bounded)."""
    max_hops = max(1, min(max_hops, 5))
    async with driver().session() as s:
        rec = await (
            await s.run(
                f"""
                MATCH (a:Entity {{id: $id}}), (f:Entity {{flagged: true}}) WHERE f.id <> $id
                MATCH p = shortestPath((a)-[*..{max_hops}]-(f))
                RETURN p ORDER BY length(p) ASC LIMIT 1
                """,
                id=entity_id,
            )
        ).single()
    if rec is None:
        return None
    p = rec["p"]
    return {
        "length": len(p.relationships),
        "nodes": [_node_dict(n) for n in p.nodes],
        "edges": [_rel_dict(r) for r in p.relationships],
    }


async def fraud_rings(min_size: int = 3, limit: int = 10) -> list[dict]:
    """Groups of customers linked through shared devices / IPs / beneficiaries where at
    least one member is flagged (bounded 2-hop expansion from flagged customers)."""
    async with driver().session() as s:
        res = await s.run(
            """
            MATCH (f:Customer {flagged: true})
            MATCH (f)-[:USES|LOGGED_IN_FROM|OWNS]->(hub)<-[:USES|LOGGED_IN_FROM|OWNS]-(c:Customer)
            WHERE c <> f AND COUNT { (hub)--() } <= 60
            WITH f, collect(DISTINCT c) AS linked, collect(DISTINCT hub.id) AS hubs
            WHERE size(linked) + 1 >= $min
            RETURN f.id AS anchor, f.label AS anchor_label, [c IN linked | {id: c.id, label: c.label, flagged: c.flagged}] AS members,
                   hubs ORDER BY size(linked) DESC LIMIT $limit
            """,
            min=min_size,
            limit=limit,
        )
        return [dict(r) async for r in res]


async def mule_beneficiaries(min_senders: int = 3, limit: int = 20) -> list[dict]:
    async with driver().session() as s:
        res = await s.run(
            """
            MATCH (b:Beneficiary)<-[r:SENT_TO]-(a:Account)<-[:OWNS]-(c:Customer)
            WITH b, count(DISTINCT c) AS senders, sum(r.count) AS transfers
            WHERE senders >= $min
            RETURN b.id AS id, b.label AS label, senders, transfers, b.flagged AS flagged
            ORDER BY senders DESC LIMIT $limit
            """,
            min=min_senders,
            limit=limit,
        )
        return [dict(r) async for r in res]


async def stats() -> dict:
    async with driver().session() as s:
        rec = await (
            await s.run(
                """
                CALL () { MATCH (n:Entity) RETURN count(n) AS nodes }
                CALL () { MATCH ()-[r]->() RETURN count(r) AS rels }
                CALL () { MATCH (n:Entity {flagged:true}) RETURN count(n) AS flagged }
                RETURN nodes, rels, flagged
                """
            )
        ).single()
    return dict(rec) if rec else {"nodes": 0, "rels": 0, "flagged": 0}


async def clear_all() -> None:
    """Test/demo-reset helper."""
    async with driver().session() as s:
        await s.run("MATCH (n) CALL (n) { DETACH DELETE n } IN TRANSACTIONS OF 5000 ROWS")
