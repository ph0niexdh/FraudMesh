#!/usr/bin/env python3
"""Stream the flagship cross-channel fraud scenario into a running FraudMesh backend.

    python scripts/simulate_attack.py                 # default: http://localhost:8000, 3 s between events
    python scripts/simulate_attack.py --delay 1 --api http://localhost:8000
    python scripts/simulate_attack.py --no-reset      # keep previous live demo data

SIMULATED DATA — NO REAL BANK INCIDENT. SBI / HDFC Bank / ICICI Bank appear
only as fictional demo entities; every identifier is synthetic.

Events are posted one by one to POST /api/events, so the dashboard updates
over WebSockets exactly as it would for real traffic. Uses only the Python
standard library.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
for _stream in (sys.stdout, sys.stderr):  # Windows consoles may not default to UTF-8
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
from app.services.scenarios import DEMO, SIMULATION_BANNER, flagship_attack  # noqa: E402

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[2m", "\033[1m", "\033[0m"
if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
    GREEN = RED = YELLOW = CYAN = DIM = BOLD = RESET = ""


def call(api: str, method: str, path: str, body: dict | None = None, admin_token: str | None = None) -> dict:
    data = json.dumps(body, default=str).encode() if body is not None else None
    req = urllib.request.Request(f"{api}{path}", data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if admin_token:
        req.add_header("X-Admin-Token", admin_token)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def wait_ready(api: str, timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if call(api, "GET", "/api/health").get("ready"):
                return
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            pass
        print(f"{DIM}waiting for backend at {api} …{RESET}")
        time.sleep(2)
    sys.exit(f"backend at {api} not ready after {timeout:.0f}s — is it running?")


def score_line(result: dict) -> str:
    parts = []
    for r in result["detector_results"]:
        if r["channel"] == "graph" and r["score"] == 0:
            continue
        name = {"transaction": "Transaction Risk", "takeover": "Takeover Risk", "kyc": "KYC Manipulation Score",
                "cloud": "Cloud Risk", "graph": "Graph Risk"}.get(r["channel"], r["channel"])
        parts.append(f"{name}: {r['score']:.2f}")
    return " | ".join(parts)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default=os.getenv("FRAUDMESH_API", "http://localhost:8000"))
    ap.add_argument("--delay", type=float, default=3.0, help="seconds between events (default 3)")
    ap.add_argument("--no-reset", action="store_true", help="do not clear previous live demo data first")
    ap.add_argument("--admin-token", default=os.getenv("FRAUDMESH_ADMIN_TOKEN"))
    args = ap.parse_args()

    print(f"\n{BOLD}{YELLOW}  ⚠  {SIMULATION_BANNER}  ⚠{RESET}")
    print(f"{BOLD}{CYAN}  FRAUDMESH — Cross-Channel Fraud Simulation{RESET}")
    print(f"{DIM}  Connect the signals. Expose the attack. Explain the risk.{RESET}\n")
    wait_ready(args.api)
    if not args.no_reset:
        try:
            r = call(args.api, "POST", "/api/demo/reset", {}, args.admin_token)
            print(f"{DIM}  reset previous live demo data: {r}{RESET}\n")
        except urllib.error.HTTPError as err:
            print(f"{YELLOW}  could not reset live data ({err.code}); continuing{RESET}\n")

    steps = flagship_attack()
    base = datetime.now(timezone.utc) - timedelta(seconds=steps[-1]["offset"] + 5)
    case_id = None
    final = None
    for step in steps:
        ts = base + timedelta(seconds=step["offset"])
        ev = {**step["event"], "timestamp": ts.isoformat()}
        try:
            res = call(args.api, "POST", "/api/events", ev)
        except urllib.error.HTTPError as err:
            sys.exit(f"{RED}event rejected ({err.code}): {err.read().decode()[:300]}{RESET}")
        e = res["event"]
        t_label = f"T+{int(step['offset'] // 60):02d}:{int(step['offset'] % 60):02d}"
        color = RED if res["suspicious"] else GREEN
        print(f"{BOLD}[{ts.strftime('%H:%M')}] {t_label}  {color}{step['title']}{RESET}")
        if e.get("bank_name"):
            print(f"       Bank: {e['bank_name']}   Account: {e.get('account_label') or '—'}")
        if e.get("device_label"):
            print(f"       Device: {e['device_label']}   IP: {e.get('ip_label') or '—'}")
        if e["event_type"] == "transaction":
            print(f"       Amount: ₹{e['amount']:,.0f}")
        print(f"       {DIM}{step['narrative']}{RESET}")
        print(f"       {score_line(res)}")
        if res["case"]:
            c = res["case"]
            verb = "CREATED" if res["case_created"] else "UPDATED"
            print(f"       {YELLOW}→ CASE {c['case_id']} {verb}: risk {c['risk_score']:.0f}/100 "
                  f"[{c['severity']}] {c['policy']['action_label']}{RESET}")
            case_id, final = c["case_id"], c
        print()
        time.sleep(args.delay)

    if not final:
        print(f"{YELLOW}No case was created — check detector configuration.{RESET}")
        return
    detail = call(args.api, "GET", f"/api/cases/{case_id}")
    print(f"{BOLD}{RED}🚨 FRAUDMESH CASE #{detail['case_id']}{RESET}")
    print(f"   Risk:     {BOLD}{detail['risk_score']:.0f} / 100{RESET}   Severity: {detail['severity']}")
    print(f"   Status:   {detail['status']}")
    print(f"   Action:   {BOLD}{detail['policy']['action_label']}{RESET}  ({detail['policy']['policy_id']})")
    print("   Channel scores: " + ", ".join(f"{k} {v:.2f}" for k, v in detail["channel_scores"].items()))
    print(f"   Events correlated: {detail['event_count']}   Banks: {', '.join(detail['banks'])}")
    print("   WHY FLAGGED?")
    for item in detail["explanations"][:10]:
        print(f"     ✓ {item['text']}  {DIM}(+{item['contribution']:.1f} pts, {item['channel_name']}){RESET}")
    print(f"\n   Open the dashboard → Case Investigation → {detail['case_id']}")
    print(f"{DIM}   Baseline for {DEMO['victim_account']}: ₹{DEMO['baseline_low']:,}–₹{DEMO['baseline_high']:,} "
          f"(synthetic){RESET}\n")


if __name__ == "__main__":
    main()
