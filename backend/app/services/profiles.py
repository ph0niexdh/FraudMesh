"""Behavioural baselines per customer and per cloud principal.

Detectors read a profile *before* the current event is applied; the pipeline
then updates the profile. Entities seen in suspicious events (new device,
new IP, new beneficiary) are *not* promoted to "trusted" — an attacker's
device must not become part of the victim's baseline.
"""
from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.schemas.events import EventType, NormalizedEvent
from app.utils.geo import coords_for


@dataclass
class SessionEntry:
    ts: datetime
    event_type: str
    device: str | None
    ip: str | None
    signals: set[str]


@dataclass
class CustomerProfile:
    token: str
    home_city: str | None = None
    seeded_mean: float = 0.0
    seeded_std: float = 0.0
    typical_hour: int | None = None
    amounts: deque = field(default_factory=lambda: deque(maxlen=300))
    beneficiaries: set[str] = field(default_factory=set)
    merchants: set[str] = field(default_factory=set)
    devices: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    login_hours: deque = field(default_factory=lambda: deque(maxlen=200))
    txn_times: deque = field(default_factory=lambda: deque(maxlen=500))
    login_times: deque = field(default_factory=lambda: deque(maxlen=200))
    last_location: tuple[tuple[float, float], datetime] | None = None
    session: deque = field(default_factory=lambda: deque(maxlen=100))
    history_events: int = 0

    # --- derived statistics -------------------------------------------------
    @property
    def amount_mean(self) -> float:
        if len(self.amounts) >= 5:
            return float(statistics.fmean(self.amounts))
        return self.seeded_mean or (float(statistics.fmean(self.amounts)) if self.amounts else 0.0)

    @property
    def amount_std(self) -> float:
        if len(self.amounts) >= 5:
            return float(statistics.pstdev(self.amounts))
        return self.seeded_std

    @property
    def usual_hour(self) -> float | None:
        if self.login_hours:
            return float(statistics.median(self.login_hours))
        return None if self.typical_hour is None else float(self.typical_hour)

    def count_since(self, times: deque, now: datetime, window: timedelta) -> int:
        return sum(1 for t in times if now - window <= t <= now)

    def session_since(self, now: datetime, window: timedelta) -> list[SessionEntry]:
        return [s for s in self.session if now - window <= s.ts <= now]


@dataclass
class PrincipalProfile:
    token: str
    regions: set[str] = field(default_factory=set)
    actions: set[str] = field(default_factory=set)
    hours: deque = field(default_factory=lambda: deque(maxlen=200))
    call_times: deque = field(default_factory=lambda: deque(maxlen=500))
    history_events: int = 0


class ProfileStore:
    def __init__(self) -> None:
        self.customers: dict[str, CustomerProfile] = {}
        self.principals: dict[str, PrincipalProfile] = {}

    def reset(self) -> None:
        self.customers.clear()
        self.principals.clear()

    def customer(self, token: str | None) -> CustomerProfile | None:
        if not token:
            return None
        prof = self.customers.get(token)
        if prof is None:
            prof = CustomerProfile(token=token)
            self.customers[token] = prof
        return prof

    def principal(self, token: str | None) -> PrincipalProfile | None:
        if not token:
            return None
        prof = self.principals.get(token)
        if prof is None:
            prof = PrincipalProfile(token=token)
            self.principals[token] = prof
        return prof

    def seed_customer(self, token: str, home_city: str | None, mean: float, std: float, hour: int | None) -> None:
        prof = self.customer(token)
        assert prof is not None
        prof.home_city = home_city
        prof.seeded_mean = mean
        prof.seeded_std = std
        prof.typical_hour = hour

    def trust_entities(self, customer_token: str | None, devices: list[str], ips: list[str]) -> None:
        """Analyst feedback (false positive) — promote entities to the customer's baseline."""
        prof = self.customer(customer_token)
        if prof is None:
            return
        prof.devices.update(d for d in devices if d)
        prof.ips.update(i for i in ips if i)

    # --- learning ---------------------------------------------------------------
    def update(self, event: NormalizedEvent, trusted: bool, signals: set[str] | None = None) -> None:
        md = event.metadata
        ts = event.timestamp
        if event.event_type == EventType.cloud_event:
            prof_p = self.principal(md.get("principal_token"))
            if prof_p is not None:
                prof_p.history_events += 1
                prof_p.call_times.append(ts)
                if trusted:
                    if md.get("region"):
                        prof_p.regions.add(md["region"])
                    if md.get("action"):
                        prof_p.actions.add(md["action"])
                    prof_p.hours.append(ts.hour)
            return

        prof = self.customer(event.customer_token)
        if prof is None:
            return
        prof.history_events += 1
        loc = coords_for(md.get("city"))
        if loc is not None:
            prof.last_location = (loc, ts)
        if event.event_type in (EventType.login, EventType.device_change, EventType.mfa_reset):
            prof.login_times.append(ts)
            prof.session.append(SessionEntry(ts, event.event_type.value, event.device_token, event.ip_token,
                                             set(signals or ())))
            if trusted:
                prof.login_hours.append(ts.hour)
        if event.event_type == EventType.transaction:
            prof.txn_times.append(ts)
            if trusted:
                prof.amounts.append(event.amount)
                if md.get("beneficiary_token"):
                    prof.beneficiaries.add(md["beneficiary_token"])
                if md.get("merchant"):
                    prof.merchants.add(md["merchant"])
        if trusted:
            if event.device_token:
                prof.devices.add(event.device_token)
            if event.ip_token:
                prof.ips.add(event.ip_token)
            if prof.home_city is None and md.get("city"):
                prof.home_city = md["city"]
