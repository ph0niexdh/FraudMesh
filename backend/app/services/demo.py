"""Live scenario runner used by the dashboard's simulation controls."""
from __future__ import annotations

import asyncio
import random
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select, update
from starlette.concurrency import run_in_threadpool

from app.database.db import session_scope
from app.database.models import Account, AnalystFeedback, Customer, CaseEntity, CaseEvent, CloudEvent, Event, FraudCase, KycEvent, \
    RiskScore, Transaction
from app.schemas.events import EventIn
from app.services import scenarios as sc
from app.services.audit import audit
from app.services.broadcaster import Broadcaster
from app.services.engine import FraudMeshEngine
from app.utils.logging import get_logger
from app.utils.timeutil import iso, utcnow

log = get_logger(__name__)


class DemoRunner:
    def __init__(self, engine: FraudMeshEngine, broadcaster: Broadcaster) -> None:
        self.engine = engine
        self.broadcaster = broadcaster
        self.task: asyncio.Task | None = None
        self.state: dict[str, Any] = {"running": False}

    @property
    def running(self) -> bool:
        return self.task is not None and not self.task.done()

    def _random_context(self, scenario: str) -> sc.ScenarioContext:
        rng = random.Random()
        with session_scope() as s:
            accounts = s.scalars(select(Account).where(Account.display_label.like("%-SYN-%"))).all()
            accounts = [a for a in accounts if a.customer_token]
            pick = rng.sample(accounts, 3)
            parties = []
            for acct in pick:
                last = s.scalars(select(Event).where(Event.account_token == acct.account_token,
                                                     Event.suspicious.is_(False))
                                 .order_by(Event.timestamp.desc()).limit(1)).first()
                city = (last.event_metadata or {}).get("city", "Mumbai") if last else "Mumbai"
                baseline = 20_000.0
                cust = s.get(Customer, acct.customer_token)
                if cust:
                    baseline = cust.baseline_amount_mean
                parties.append(sc.Party(acct.customer_token, acct.account_token, acct.bank_name,
                                        last.device_token if last else f"DEVICE-{rng.randrange(65536):04X}",
                                        last.ip_token if last else "100.70.1.1", city, baseline))
        return sc.ScenarioContext(
            victim=parties[0], mules=parties[1:], attacker_device=f"DEVICE-{rng.randrange(0xE000, 0xFFFF):04X}",
            attacker_ip=f"100.98.{rng.randrange(1, 250)}.{rng.randrange(1, 250)}",
            attacker_city=rng.choice(["Kolkata", "Guwahati", "Singapore", "Dubai"]), rng=rng, tag="live",
        )

    def plan(self, scenario: str) -> list[dict[str, Any]]:
        if scenario == "coordinated_cross_channel_fraud":
            return sc.flagship_attack()
        return sc.GENERATORS[scenario](self._random_context(scenario))

    async def start(self, scenario: str, step_seconds: float, reset: bool, actor: str) -> dict[str, Any]:
        if self.running:
            raise RuntimeError("a simulation is already running")
        if reset:
            await run_in_threadpool(self.reset_live_data, actor)
            await self.broadcaster.publish([{"type": "demo.reset", "data": {}}])
        steps = await run_in_threadpool(self.plan, scenario)
        self.state = {"running": True, "scenario": scenario, "total_steps": len(steps), "step": 0,
                      "started_at": iso(utcnow()), "case_id": None, "banner": sc.SIMULATION_BANNER}
        self.task = asyncio.create_task(self._run(scenario, steps, step_seconds))
        return self.state

    async def _run(self, scenario: str, steps: list[dict[str, Any]], step_seconds: float) -> None:
        # simulated clock: events keep their real relative spacing (T+00 … T+10 min) and end "now"
        base = utcnow() - timedelta(seconds=steps[-1]["offset"] + 5)
        await self.broadcaster.publish([{"type": "simulation.started", "data": {**self.state,
                                                                                "steps": [{k: st[k] for k in ("offset", "title", "narrative")} for st in steps]}}])
        try:
            for i, step in enumerate(steps):
                payload = {**step["event"], "timestamp": base + timedelta(seconds=step["offset"])}
                ev = EventIn.model_validate(payload)
                result = await run_in_threadpool(self.engine.process_event, ev, source="live", scenario=scenario)
                self.state.update(step=i + 1, case_id=result["case"]["case_id"] if result["case"] else self.state.get("case_id"))
                await self.broadcaster.publish([{"type": "simulation.step", "data": {
                    "index": i, "total": len(steps), "title": step["title"], "narrative": step["narrative"],
                    "offset": step["offset"], "event_id": result["event"]["event_id"],
                    "signal_score": result["signal_score"], "case_id": self.state["case_id"],
                    "risk_score": result["case"]["risk_score"] if result["case"] else None}}])
                await self.broadcaster.publish(result["messages"])
                if i < len(steps) - 1:
                    await asyncio.sleep(step_seconds)
            final = None
            if self.state.get("case_id"):
                with session_scope() as s:
                    row = s.get(FraudCase, self.state["case_id"])
                    final = {"case_id": row.case_id, "risk_score": row.risk_score, "severity": row.severity,
                             "status": row.status, "policy": row.policy} if row else None
            self.state.update(running=False, finished_at=iso(utcnow()), final=final)
            await self.broadcaster.publish([{"type": "simulation.completed", "data": self.state}])
        except Exception as err:  # pragma: no cover - surfaced to UI
            log.exception("simulation failed")
            self.state.update(running=False, error=type(err).__name__)
            await self.broadcaster.publish([{"type": "simulation.failed", "data": self.state}])

    def reset_live_data(self, actor: str = "system") -> dict[str, int]:
        """Remove live (non-seed) events and cases, then rebuild in-memory state."""
        with self.engine.lock, session_scope() as s:
            live_cases = s.scalars(select(FraudCase.case_id).where(FraudCase.source == "live")).all()
            live_events = s.scalars(select(Event.event_id).where(Event.source == "live")).all()
            for model, col, values in (
                (RiskScore, RiskScore.case_id, live_cases), (RiskScore, RiskScore.event_id, live_events),
                (AnalystFeedback, AnalystFeedback.case_id, live_cases), (CaseEntity, CaseEntity.case_id, live_cases),
                (CaseEvent, CaseEvent.case_id, live_cases), (CaseEvent, CaseEvent.event_id, live_events),
                (Transaction, Transaction.event_id, live_events), (KycEvent, KycEvent.event_id, live_events),
                (CloudEvent, CloudEvent.event_id, live_events), (Event, Event.event_id, live_events),
                (FraudCase, FraudCase.case_id, live_cases),
            ):
                for i in range(0, len(values), 500):
                    s.execute(delete(model).where(col.in_(values[i:i + 500])))
            for i in range(0, len(live_cases), 500):
                s.execute(update(Event).where(Event.case_id.in_(live_cases[i:i + 500])).values(case_id=None))
            audit(s, "demo.reset", actor=actor, entity_type="system",
                  details={"cases_removed": len(live_cases), "events_removed": len(live_events)})
            s.flush()
            self.engine.rebuild_state(s)
        return {"cases_removed": len(live_cases), "events_removed": len(live_events)}
