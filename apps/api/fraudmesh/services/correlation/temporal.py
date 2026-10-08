"""Temporal attack engine.

Matches the time-ordered events of a case against known attack *sequences*. Each
pattern is an ordered list of stages (predicates over an event) with a maximum
span. Matching is greedy in time order, stages may be skipped (attackers do not
always perform every step), and the score rewards:

* coverage  – fraction of stages observed, in order
* order     – stages appeared in the expected order
* tempo     – the whole chain happened quickly (compressed timelines are typical
              of scripted takeovers)

The output explains exactly which events satisfied which stage, so the timeline
in the UI can mark them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from fraudmesh.detection.base import DetectorResult, Reason


def _has(ev: dict, code_prefix: str) -> bool:
    return any(rc.get("code", "").startswith(code_prefix) for rc in ev.get("reason_codes", []))


@dataclass
class Stage:
    name: str
    test: Callable[[dict], bool]


@dataclass
class Pattern:
    id: str
    name: str
    stages: list[Stage]
    max_span_s: int
    attack_type: str
    # each group must contribute at least one matched stage, otherwise the pattern does
    # not apply (e.g. "deepfake KYC" without any deepfake evidence is not that attack)
    required: list[set[str]] | None = None


def _login_new(ev):
    return ev["event_type"] == "LOGIN" and ev["payload"].get("success") and (ev.get("ctx", {}).get("is_new_device") or ev.get("ctx", {}).get("ip_new") or _has(ev, "ID_NEW_DEVICE"))


def _new_device(ev):
    return (ev["event_type"] == "DEVICE") or (ev["event_type"] == "LOGIN" and ev.get("ctx", {}).get("is_new_device"))


def _mfa_change(ev):
    return ev["event_type"] == "MFA" and ev["payload"].get("action") in ("reset", "disabled", "factor_changed", "enrolled")


def _kyc_anomaly(ev):
    return ev["event_type"] in ("KYC", "BIOMETRIC", "DEEPFAKE") and ev.get("risk_score", 0) >= 50


def _deepfake(ev):
    return ev["event_type"] in ("KYC", "BIOMETRIC", "DEEPFAKE") and (ev.get("ctx", {}).get("deepfake_risk", 0) >= 0.6 or _has(ev, "DF_"))


def _beneficiary(ev):
    return ev["event_type"] == "BENEFICIARY" or (ev["event_type"] == "TRANSACTION" and ev.get("ctx", {}).get("beneficiary_new"))


def _big_txn(ev):
    return ev["event_type"] == "TRANSACTION" and (ev["payload"].get("amount", 0) >= 50_000 or ev.get("risk_score", 0) >= 65)


def _net_alert(ev):
    return ev["event_type"] in ("NETWORK", "IDS") and ev.get("risk_score", 0) >= 50


def _failed_logins(ev):
    return ev["event_type"] == "LOGIN" and not ev["payload"].get("success")


def _login_success(ev):
    return ev["event_type"] == "LOGIN" and ev["payload"].get("success")


def _cloud_sensitive(ev):
    return ev["event_type"] == "CLOUD" and ev.get("risk_score", 0) >= 40


PATTERNS = [
    Pattern("ATO_DEEPFAKE", "Account takeover with deepfake re-verification", [
        Stage("New device / network login", _login_new),
        Stage("MFA reset", _mfa_change),
        Stage("KYC / biometric anomaly", _kyc_anomaly),
        Stage("Deepfake detected", _deepfake),
        Stage("New beneficiary", _beneficiary),
        Stage("High-value transfer", _big_txn),
    ], 3600, "ACCOUNT_TAKEOVER_DEEPFAKE", [{"New device / network login"}, {"MFA reset"}, {"Deepfake detected", "KYC / biometric anomaly"}]),
    Pattern("ATO", "Account takeover", [
        Stage("New device / network login", _login_new),
        Stage("MFA change", _mfa_change),
        Stage("New beneficiary", _beneficiary),
        Stage("High-value transfer", _big_txn),
    ], 3600, "ACCOUNT_TAKEOVER", [{"New device / network login"}, {"MFA change", "New beneficiary"}]),
    Pattern("DEEPFAKE_KYC", "Synthetic / deepfake identity onboarding", [
        Stage("Device / network registration", lambda e: _new_device(e) or _login_success(e)),
        Stage("Deepfake media in verification", _deepfake),
        Stage("Further deepfake / liveness evidence", _deepfake),
        Stage("Beneficiary or transfer", lambda e: _beneficiary(e) or _big_txn(e)),
    ], 7 * 86400, "DEEPFAKE_KYC", [{"Deepfake media in verification"}]),
    Pattern("CRED_STUFFING", "Credential stuffing to takeover", [
        Stage("Burst of failed logins / IDS stuffing", lambda e: _failed_logins(e) or (_net_alert(e) and _has(e, "CREDENTIAL_STUFFING"))),
        Stage("Successful login", _login_success),
        Stage("Account change or transfer", lambda e: _mfa_change(e) or _beneficiary(e) or _big_txn(e)),
    ], 3600, "CREDENTIAL_STUFFING", [{"Burst of failed logins / IDS stuffing"}, {"Successful login"}]),
    Pattern("INSIDER", "Insider-assisted account takeover", [
        Stage("Sensitive data / secrets access by employee identity", _cloud_sensitive),
        Stage("Customer MFA changed from the same network", _mfa_change),
        Stage("Login with the new factor", _login_success),
        Stage("Beneficiary or transfer", lambda e: _beneficiary(e) or _big_txn(e)),
    ], 3 * 3600, "INSIDER_THREAT", [{"Sensitive data / secrets access by employee identity"}, {"Customer MFA changed from the same network"}]),
    Pattern("CLOUD_COMPROMISE", "Cloud identity compromise", [
        Stage("Suspicious network activity", _net_alert),
        Stage("Sensitive cloud API", _cloud_sensitive),
        Stage("Further sensitive actions", _cloud_sensitive),
    ], 3600, "CLOUD_COMPROMISE", [{"Sensitive cloud API"}]),
]


def _ts(ev: dict) -> datetime:
    t = ev["ts"]
    return t if isinstance(t, datetime) else datetime.fromisoformat(t)


def match(events: list[dict], pattern: Pattern) -> dict:
    """Longest order-preserving match of events to stages (dynamic programming, like LCS),
    restricted to chains that fit inside the pattern's maximum span."""
    evs = sorted(events, key=_ts)
    n, m = len(evs), len(pattern.stages)
    ok = [[pattern.stages[j].test(evs[i]) for j in range(m)] for i in range(n)]
    best: tuple[int, list[tuple[int, int]]] = (0, [])
    # try every start event so the span limit can be enforced on each candidate chain
    for start in range(n):
        t0 = _ts(evs[start])
        window = [i for i in range(start, n) if (_ts(evs[i]) - t0).total_seconds() <= pattern.max_span_s]
        # dp[k][j] = longest chain using window[:k] events and stages[:j]
        L = len(window)
        dp = [[0] * (m + 1) for _ in range(L + 1)]
        for k in range(1, L + 1):
            i = window[k - 1]
            for j in range(1, m + 1):
                dp[k][j] = max(dp[k - 1][j], dp[k][j - 1], dp[k - 1][j - 1] + (1 if ok[i][j - 1] else 0))
        if dp[L][m] > best[0]:
            pairs, k, j = [], L, m
            while k > 0 and j > 0:
                i = window[k - 1]
                if ok[i][j - 1] and dp[k][j] == dp[k - 1][j - 1] + 1:
                    pairs.append((i, j - 1))
                    k, j = k - 1, j - 1
                elif dp[k - 1][j] >= dp[k][j - 1]:
                    k -= 1
                else:
                    j -= 1
            best = (dp[L][m], list(reversed(pairs)))
    matched = [(pattern.stages[j], evs[i]) for i, j in best[1]]
    names = {s.name for s, _ in matched}
    valid = all(names & group for group in (pattern.required or []))
    coverage = len(matched) / m
    span = (_ts(matched[-1][1]) - _ts(matched[0][1])).total_seconds() if len(matched) > 1 else 0.0
    tempo = 1.0 if span <= 900 else (0.8 if span <= 3600 else 0.5)
    score = 0.0 if (len(matched) < 2 or not valid) else min(1.0, coverage ** 0.8 * (0.75 + 0.25 * tempo))
    return {
        "pattern": pattern.id,
        "name": pattern.name,
        "attack_type": pattern.attack_type,
        "score": round(score, 3),
        "coverage": round(coverage, 3),
        "valid": valid,
        "span_s": round(span, 1),
        "stages": [{"stage": s.name, "event_id": e["id"], "ts": _ts(e).isoformat(), "event_type": e["event_type"]} for s, e in matched],
        "missing": [s.name for s in pattern.stages if s.name not in names],
    }


def analyze(events: list[dict]) -> tuple[DetectorResult, dict | None]:
    if len(events) < 2:
        return DetectorResult("temporal-engine", "temporal", 0.0, 0.4, [], "temporal-sequences-v1", 0.0), None
    # Prefer the valid pattern that explains the most events (the most specific story),
    # then the higher score. "ATO + deepfake" (5 stages) beats generic "ATO" (4 stages).
    results = sorted((match(events, p) for p in PATTERNS), key=lambda r: (r["score"] <= 0, -len(r["stages"]) if r["score"] > 0 else 0, -r["score"]))
    best = results[0]
    reasons = []
    if best["score"] > 0:
        chain = " → ".join(s["stage"] for s in best["stages"])
        reasons.append(Reason(f"SEQ_{best['pattern']}", f"{best['name']}: {chain} within {best['span_s'] / 60:.0f} min", best["score"]))
    burst = len(events) >= 5 and (_ts(max(events, key=_ts)) - _ts(min(events, key=_ts))).total_seconds() <= 900
    risk = best["score"]
    if burst:
        reasons.append(Reason("SEQ_BURST", f"{len(events)} correlated events within 15 min", 0.3))
        risk = max(risk, 0.35)
    conf = 0.5 + 0.4 * best["coverage"]
    return (
        DetectorResult("temporal-engine", "temporal", round(100 * risk, 2), round(conf, 3), reasons, "temporal-sequences-v1", 0.0,
                       {"best": best, "alternatives": results[1:3]}),
        best if best["score"] > 0 else None,
    )
