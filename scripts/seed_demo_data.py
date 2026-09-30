#!/usr/bin/env python3
"""Generate SYNTHETIC demo data and populate the FraudMesh database.

    python scripts/seed_demo_data.py            # seed if the database is empty
    python scripts/seed_demo_data.py --reset    # drop all tables and re-seed

SIMULATED DATA — NO REAL BANK INCIDENT. Creates ≥100 customers, 150
accounts (SBI / HDFC Bank / ICICI Bank as fictional demo entities), 100+
devices, 150 IP tokens, ~1000 transactions, ~500 logins, ~100 KYC checks,
~200 cloud events and six historical fraud scenario types. Every event goes
through the real FraudMesh pipeline, so cases and explanations are genuine
system output.

Stop the backend first when using --reset (SQLite allows one writer), or
call POST /api/demo/reset to clear only live demo data.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
for _stream in (sys.stdout, sys.stderr):  # Windows consoles may not default to UTF-8
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

from app.config import get_settings  # noqa: E402
from app.utils.logging import configure_logging  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reset", action="store_true", help="drop and recreate all tables before seeding")
    ap.add_argument("--seed", type=int, default=2024, help="random seed (deterministic population)")
    args = ap.parse_args()
    configure_logging(get_settings().log_level)

    from app.services.engine import get_engine
    from app.services.seeder import seed

    print("SIMULATED DATA — NO REAL BANK INCIDENT")
    print(f"database: {get_settings().database_url}")
    summary = seed(get_engine(), reset=args.reset, seed_value=args.seed)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
