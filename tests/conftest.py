"""Test configuration: isolated temp database, one trained engine per session."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

_TMP = tempfile.mkdtemp(prefix="fraudmesh-test-")
os.environ["FRAUDMESH_DATA_DIR"] = _TMP
os.environ["FRAUDMESH_MODELS_DIR"] = os.path.join(_TMP, "models")
os.environ["FRAUDMESH_TOKEN_SECRET"] = "test-secret-not-for-production"
os.environ["FRAUDMESH_AUTO_SEED"] = "false"
os.environ["FRAUDMESH_ADMIN_TOKEN"] = "test-admin-token"
os.environ["FRAUDMESH_RATE_LIMIT_PER_MINUTE"] = "100000"
os.environ["FRAUDMESH_KYC_RATE_LIMIT_PER_MINUTE"] = "1000"


@pytest.fixture(scope="session")
def engine():
    from app.database.db import init_db
    from app.services.engine import get_engine

    init_db()
    eng = get_engine()
    eng.startup()
    return eng


@pytest.fixture(scope="session")
def client(engine):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        # lifespan initialisation runs in the background; wait until ready
        import time

        for _ in range(120):
            if c.get("/api/health").json().get("ready"):
                break
            time.sleep(0.25)
        yield c


def unique(prefix: str) -> str:
    import uuid

    return f"{prefix}{uuid.uuid4().hex[:6].upper()}"


def unique_digits(n: int = 4) -> str:
    import random

    return str(random.randint(10 ** (n - 1), 10 ** n - 1))


def unique_ip() -> str:
    import random

    return f"100.{random.randint(64, 127)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def build_history(engine, customer, account, bank, device, ip, city="Mumbai", amount=30_000.0, days=20):
    """Give a synthetic customer a normal baseline (logins + transactions) in the past."""
    from datetime import timedelta

    from app.schemas.events import EventIn
    from app.utils.timeutil import utcnow

    now = utcnow()
    common = dict(customer_id=customer, account_id=account, bank_name=bank, device_id=device, ip_address=ip)
    for d in range(days, 0, -1):
        base = now - timedelta(days=d, hours=2)
        engine.process_event(EventIn(event_type="login", timestamp=base, metadata={"city": city}, **common),
                             source="seed")
        engine.process_event(EventIn(event_type="transaction", timestamp=base + timedelta(minutes=5),
                                     amount=amount * (0.85 + 0.3 * (d % 3) / 2),
                                     metadata={"city": city, "merchant": f"SYN-M{d % 4}"}, **common), source="seed")
