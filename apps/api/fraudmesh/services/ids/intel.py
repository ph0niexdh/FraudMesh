"""Threat-intelligence lookups (IP reputation, JA3, domains, user agents)."""

from __future__ import annotations

import ipaddress
import json
import math
from collections import Counter
from functools import lru_cache

from fraudmesh.config import REPO_ROOT

INTEL_PATH = REPO_ROOT / "infra" / "config" / "threat_intel.json"


@lru_cache
def _intel() -> dict:
    data = json.loads(INTEL_PATH.read_text())
    data["_nets"] = [(ipaddress.ip_network(n["cidr"]), n) for n in data["networks"]]
    data["_ja3"] = {j["hash"]: j for j in data["ja3"]}
    data["_domains"] = {d["domain"]: d for d in data["domains"]}
    return data


def ip_reputation(ip: str | None) -> dict:
    if not ip:
        return {"risk": 0.0, "category": "unknown", "source": None}
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"risk": 0.3, "category": "invalid", "source": None}
    best = None
    for net, meta in _intel()["_nets"]:
        if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
            best = (net, meta)
    if best is None:
        return {"risk": 0.15, "category": "unclassified", "source": None}
    return {"risk": best[1]["risk"], "category": best[1]["category"], "source": best[1]["source"]}


def ja3(h: str | None) -> dict | None:
    return _intel()["_ja3"].get(h) if h else None


def domain(d: str | None) -> dict | None:
    if not d:
        return None
    d = d.lower().rstrip(".")
    doms = _intel()["_domains"]
    parts = d.split(".")
    for i in range(len(parts) - 1):
        hit = doms.get(".".join(parts[i:]))
        if hit:
            return hit
    return None


def user_agent(ua: str | None) -> dict | None:
    if not ua:
        return None
    for u in _intel()["user_agents"]:
        if u["pattern"].lower() in ua.lower():
            return u
    return None


def is_auth_endpoint(uri: str | None) -> bool:
    return bool(uri) and any(uri.split("?")[0].endswith(p) for p in _intel()["auth_endpoints"])


def is_protected_domain(host: str | None) -> bool:
    return bool(host) and host.lower() in _intel()["protected_domains"]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def dga_score(qname: str | None) -> float:
    """Heuristic algorithmically-generated-domain score for the left-most label(s)."""
    if not qname:
        return 0.0
    labels = qname.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return 0.0
    core = max(labels[:-1], key=len)
    if len(core) < 10:
        return 0.0
    ent = entropy(core)
    digits = sum(ch.isdigit() for ch in core) / len(core)
    consonant_run = max((len(r) for r in "".join(ch if ch in "bcdfghjklmnpqrstvwxz" else " " for ch in core).split()), default=0)
    score = 0.0
    score += max(0.0, (ent - 3.2) / 1.0) * 0.5
    score += min(1.0, digits * 3) * 0.2
    score += min(1.0, max(0, consonant_run - 3) / 4) * 0.3
    if len(qname) > 60:  # long encoded subdomains → tunnelling
        score += 0.3
    return float(min(1.0, score))
