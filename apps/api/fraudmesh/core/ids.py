"""Prefixed, sortable identifiers (time-ordered so they sort like ULIDs)."""

from __future__ import annotations

import os
import time


def new_id(prefix: str) -> str:
    ts = int(time.time() * 1000)
    return f"{prefix}_{ts:012x}{os.urandom(5).hex()}"


def case_id() -> str:
    return f"CASE-{int(time.time()) % 10_000_000:07d}-{os.urandom(2).hex().upper()}"
