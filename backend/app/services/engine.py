"""FraudMesh engine: EVENT → NORMALIZE → DETECT → CORRELATE → GRAPH → SCORE → EXPLAIN → ACT → LEARN.

The engine owns in-memory state (profiles, entity graph, recent-event index,
open-case index) which is rebuilt from the database at start-up, and
persists every result so the API and dashboard read from the database.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database.db import session_scope
from app.database.models import (
    Account, AnalystFeedback, CaseEntity, CaseEvent, CloudEvent, Customer, Event, FraudCase, KycEvent,
    PolicyRecord, RiskScore, Transaction,
)
from app.detectors.behavior import BehaviorDetector
from app.detectors.cloud import CloudDetector
from app.detectors.kyc import KycDetector
from app.detectors.transaction import FEATURES as TXN_FEATURES
from app.detectors.transaction import TransactionDetector
from app.explainability.explainer import build_explanations, summarize
from app.graph.entity_graph import EntityGraph
from app.policies.engine import evaluate as evaluate_policy
from app.policies.fusion import fuse
from app.schemas.cases import ACTION_TO_STATUS, OPEN_STATUSES, AnalystAction, CaseStatus, FeedbackIn
from app.schemas.config import FusionConfig, PolicyAction, PolicyConfig, default_policy
from app.schemas.events import DetectorResult, EventIn, EventType, NormalizedEvent
from app.services.audit import audit
from app.services.normalizer import normalize
from app.services.profiles import ProfileStore
from app.services.serializers import case_summary, event_to_dict, feedback_to_dict
from app.utils.logging import get_logger
from app.utils.timeutil import ensure_utc, iso, utcnow

log = get_logger(__name__)

DETECTOR_CHANNELS = ("transaction", "takeover", "kyc", "cloud")
ATTACHABLE_STATUSES = OPEN_STATUSES | {CaseStatus.CONFIRMED_FRAUD.value}
CASE_ID_START = 10270
RECENT_RETENTION = timedelta(hours=6)


@dataclass
class RecentEvent:
    event_id: str
    ts: datetime
    entities: frozenset[str]
    suspicious: bool
    record: dict[str, Any]


@dataclass
class OpenCase:
    case_id: str
    status: str
    first_event_at: datetime
    last_event_at: datetime
    entities: set[str] = field(default_factory=set)
    events: list[dict[str, Any]] = field(default_factory=list)
    risk: float = 0.0
    policy_action: str = ""
    scenario: str | None = None


def event_entities(ev: NormalizedEvent) -> set[str]:
    md = ev.metadata
    tokens = {ev.customer_token, ev.account_token, ev.device_token, ev.ip_token,
              md.get("beneficiary_token"), md.get("kyc_token"), md.get("principal_token"), md.get("resource_token")}
    return {t for t in tokens if t}


def _dict_entities(rec: dict[str, Any]) -> set[str]:
    md = rec.get("metadata", {})
    tokens = {rec.get("customer_token"), rec.get("account_token"), rec.get("device_token"), rec.get("ip_token"),
              md.get("beneficiary_token"), md.get("kyc_token"), md.get("principal_token"), md.get("resource_token")}
    return {t for t in tokens if t}


def _ts(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return ensure_utc(value)
    return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


class FraudMeshEngine:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.lock = threading.RLock()
        self.profiles = ProfileStore()
        self.graph = EntityGraph()
        self.txn = TransactionDetector(self.settings.models_dir)
        self.behavior = BehaviorDetector()
        self.kyc = KycDetector()
        self.cloud = CloudDetector()
        self.fusion_config = FusionConfig()
        self.policy_config = default_policy()
        self.recent: deque[RecentEvent] = deque()
        self.recent_index: dict[str, list[RecentEvent]] = defaultdict(list)
        self.open_cases: dict[str, OpenCase] = {}
        self.case_index: dict[str, set[str]] = defaultdict(set)
        self.pipeline_latencies: deque[float] = deque(maxlen=1000)
        self.case_build_latencies: deque[float] = deque(maxlen=1000)
        self.started_at = utcnow()
        self.ready = False
        self._case_seq = CASE_ID_START

    # ================================================================ lifecycle
    def train_models(self) -> None:
        self.txn.train()
        self.behavior.train()
        self.cloud.train()

    def startup(self) -> None:
        with self.lock:
            if self.txn.model is None:
                self.train_models()
            with session_scope() as s:
                self._load_config(s)
                self.rebuild_state(s)
            self.ready = True

    def _load_config(self, s: Session) -> None:
        fusion = s.get(PolicyRecord, "fusion")
        policy = s.get(PolicyRecord, "policy")
        if fusion is None:
            s.add(PolicyRecord(key="fusion", config=self.fusion_config.model_dump(), updated_at=utcnow()))
        else:
            self.fusion_config = FusionConfig.model_validate(fusion.config)
        if policy is None:
            s.add(PolicyRecord(key="policy", config=self.policy_config.model_dump(mode="json"), updated_at=utcnow()))
        else:
            self.policy_config = PolicyConfig.model_validate(policy.config)
        self.behavior.window = self.window

    @property
    def window(self) -> timedelta:
        return timedelta(minutes=self.fusion_config.temporal_window_minutes)

    def rebuild_state(self, s: Session) -> None:
        """Rebuild profiles, graph and indices from the database (no re-detection)."""
        t0 = time.perf_counter()
        self.profiles.reset()
        self.graph.reset()
        self.recent.clear()
        self.recent_index.clear()
        self.open_cases.clear()
        self.case_index.clear()
        for c in s.scalars(select(Customer)):
            self.profiles.seed_customer(c.customer_token, c.home_city, c.baseline_amount_mean,
                                        c.baseline_amount_std, c.typical_login_hour)
        bank_by_account = {a.account_token: (a.bank_name, a.display_label) for a in s.scalars(select(Account))}
        rows = s.scalars(select(Event).order_by(Event.timestamp, Event.received_at)).all()
        for row in rows:
            ev = NormalizedEvent(
                event_id=row.event_id, event_type=row.event_type, timestamp=ensure_utc(row.timestamp),
                customer_token=row.customer_token, account_token=row.account_token,
                device_token=row.device_token, ip_token=row.ip_token, channel=row.channel,
                amount=row.amount, metadata=row.event_metadata or {},
            )
            labels = {"customer": row.customer_label, "account": row.account_label,
                      "device": row.device_label, "ip": row.ip_label}
            if ev.account_token in bank_by_account and not ev.metadata.get("bank_name"):
                ev.metadata["bank_name"] = bank_by_account[ev.account_token][0]
            self.graph.add_event(ev, labels, row.signal_score or 0.0)
            self.profiles.update(ev, trusted=not row.suspicious, signals=self._fired_signals(row.detector_results))
            self._remember(ev, bool(row.suspicious), event_to_dict(row))
        seq = s.scalar(select(func.max(FraudCase.case_id)))
        if seq:
            self._case_seq = max(self._case_seq, int(seq.split("-")[1]) + 1)
        for case in s.scalars(select(FraudCase)):
            if case.status == CaseStatus.CONFIRMED_FRAUD.value:
                ents = s.scalars(select(CaseEntity).where(CaseEntity.case_id == case.case_id)).all()
                self.graph.set_watchlist([e.entity_token for e in ents if e.entity_type in ("device", "ip")])
            if case.status == CaseStatus.FALSE_POSITIVE.value:
                self._trust_case_entities(s, case.case_id)
            if case.status in ATTACHABLE_STATUSES:
                self._load_open_case(s, case)
        log.info("state rebuilt: %d events, %d open cases, graph %s in %.0f ms", len(rows), len(self.open_cases),
                 self.graph.stats()["nodes"], (time.perf_counter() - t0) * 1000)

    def _load_open_case(self, s: Session, case: FraudCase) -> None:
        rows = s.scalars(select(Event).join(CaseEvent, CaseEvent.event_id == Event.event_id)
                         .where(CaseEvent.case_id == case.case_id).order_by(Event.timestamp)).all()
        oc = OpenCase(case_id=case.case_id, status=case.status, first_event_at=ensure_utc(case.first_event_at),
                      last_event_at=ensure_utc(case.last_event_at), events=[event_to_dict(r) for r in rows],
                      risk=case.risk_score, policy_action=case.policy_action, scenario=case.scenario)
        for rec in oc.events:
            oc.entities |= _dict_entities(rec)
        self._index_case(oc)

    def _index_case(self, oc: OpenCase) -> None:
        self.open_cases[oc.case_id] = oc
        for t in oc.entities:
            self.case_index[t].add(oc.case_id)

    def _unindex_case(self, case_id: str) -> None:
        oc = self.open_cases.pop(case_id, None)
        if oc:
            for t in oc.entities:
                self.case_index[t].discard(case_id)

    @staticmethod
    def _fired_signals(results: list[dict[str, Any]] | None) -> set[str]:
        for r in results or []:
            if r.get("channel") == "takeover":
                return set(r.get("details", {}).get("current_event_signals", []))
        return set()

    def _remember(self, ev: NormalizedEvent, suspicious: bool, record: dict[str, Any]) -> None:
        item = RecentEvent(ev.event_id, ev.timestamp, frozenset(event_entities(ev)), suspicious, record)
        self.recent.append(item)
        for t in item.entities:
            self.recent_index[t].append(item)
        newest = max(ev.timestamp, self.recent[-1].ts)
        while self.recent and self.recent[0].ts < newest - RECENT_RETENTION:
            old = self.recent.popleft()
            for t in old.entities:
                lst = self.recent_index.get(t)
                if lst:
                    try:
                        lst.remove(old)
                    except ValueError:
                        pass
                    if not lst:
                        self.recent_index.pop(t, None)

    # ================================================================ detection
    def _detect(self, ev: NormalizedEvent, image_features: dict[str, Any] | None) -> list[DetectorResult]:
        results: list[DetectorResult] = []
        et = ev.event_type
        try:
            if et == EventType.transaction:
                results.append(self.txn.detect(ev, self.profiles.customer(ev.customer_token)))
            elif et in (EventType.login, EventType.device_change, EventType.mfa_reset):
                results.append(self.behavior.detect(ev, self.profiles.customer(ev.customer_token)))
            elif et == EventType.kyc_verification:
                results.append(self.kyc.detect(ev, image_features))
            elif et == EventType.cloud_event:
                results.append(self.cloud.detect(ev, self.profiles.principal(ev.metadata.get("principal_token"))))
        except Exception as err:  # a failing detector must not break the pipeline
            det = {EventType.transaction: self.txn, EventType.kyc_verification: self.kyc,
                   EventType.cloud_event: self.cloud}.get(et, self.behavior)
            det.stats.record_error(err)
            log.exception("detector failure for %s", ev.event_id)
        return results

    def _graph_result(self, entities: set[str]) -> DetectorResult:
        t0 = time.perf_counter()
        g = self.graph.score_entities(entities)
        return DetectorResult(
            score=g["score"], confidence=0.8 if g["signals"] else 0.6, detector="entity_graph", channel="graph",
            timestamp=utcnow(), model_version="networkx-rules-v1",
            signals=[s["name"] for s in g["signals"]],
            signal_details=[{k: v for k, v in s.items()} for s in g["signals"]],
            details={"components": g["signals"]}, latency_ms=round((time.perf_counter() - t0) * 1000, 3),
        )

    # ================================================================ correlation
    def _cluster(self, seed_entities: set[str], ts: datetime) -> list[RecentEvent]:
        """Events in the temporal window transitively connected through shared entities."""
        lo, hi = ts - self.window, ts + timedelta(minutes=1)
        frontier = set(seed_entities)
        seen_entities: set[str] = set()
        cluster: dict[str, RecentEvent] = {}
        for _ in range(4):  # bounded hops
            nxt: set[str] = set()
            for ent in frontier - seen_entities:
                seen_entities.add(ent)
                for item in self.recent_index.get(ent, ()):
                    if lo <= item.ts <= hi and item.event_id not in cluster:
                        cluster[item.event_id] = item
                        nxt |= item.entities
            frontier = nxt - seen_entities
            if not frontier:
                break
        return sorted(cluster.values(), key=lambda i: i.ts)

    def score_case(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        cfg = self.fusion_config
        thr = cfg.suspicious_event_threshold
        channel_scores = {c: 0.0 for c in DETECTOR_CHANNELS}
        confidences: dict[str, float] = {}
        entities: set[str] = set()
        for rec in events:
            entities |= _dict_entities(rec)
            for r in rec.get("detector_results", []):
                ch = r.get("channel")
                if ch in channel_scores and r["score"] >= channel_scores[ch]:
                    channel_scores[ch] = float(r["score"])
                    confidences[ch] = float(r.get("confidence", 0.5))
        g = self.graph.score_entities(entities)
        channel_scores["graph"] = g["score"]
        confidences["graph"] = 0.8

        susp = [e for e in events if e.get("suspicious")]
        stamps = [_ts(e["timestamp"]) for e in susp] or [_ts(e["timestamp"]) for e in events]
        span_min = (max(stamps) - min(stamps)).total_seconds() / 60 if stamps else 0.0
        channels = {c for c in DETECTOR_CHANNELS if channel_scores[c] >= thr} | ({"graph"} if g["score"] >= thr else set())
        if len(susp) >= 2:
            temporal = min(1.0, 0.12 * (len(susp) - 1) + 0.18 * max(0, len(channels) - 1))
            if span_min > cfg.temporal_window_minutes:
                temporal *= 0.5
        else:
            temporal = 0.0
        channel_scores["temporal"] = round(temporal, 4)
        confidences["temporal"] = 0.9
        channel_scores = {k: round(v, 4) for k, v in channel_scores.items()}

        risk, contributions = fuse(channel_scores, cfg)
        policy = evaluate_policy(risk, self.policy_config)
        temporal_info = {"score": temporal, "suspicious_events": len(susp), "channels": len(channels),
                         "span_minutes": round(span_min, 1)}
        explanations = build_explanations(events, contributions, g, temporal_info, thr)
        total = sum(contributions.values()) or 1.0
        confidence = sum(contributions[c] * confidences.get(c, 0.5) for c in contributions) / total
        return {
            "risk": risk, "channel_scores": channel_scores, "contributions": contributions, "graph": g,
            "temporal": temporal_info, "policy": policy, "explanations": explanations,
            "confidence": round(confidence, 4), "entities": entities,
            "summary": summarize(explanations, channel_scores, thr),
        }

    # ================================================================ pipeline
    def process_event(self, event_in: EventIn, *, source: str = "live", session: Session | None = None,
                      image_features: dict[str, Any] | None = None, scenario: str | None = None,
                      received_at: datetime | None = None) -> dict[str, Any]:
        if session is None:
            with session_scope() as s:
                return self.process_event(event_in, source=source, session=s, image_features=image_features,
                                          scenario=scenario, received_at=received_at)
        s = session
        stages: dict[str, float] = {}
        messages: list[dict[str, Any]] = []
        with self.lock:
            t_all = time.perf_counter()
            t = time.perf_counter()
            ev, labels, sanitized_keys = normalize(event_in)
            if s.get(Event, ev.event_id) is not None:
                raise ValueError(f"duplicate event_id {ev.event_id}")
            if ev.account_token and not ev.metadata.get("bank_name"):
                acct = s.get(Account, ev.account_token)
                if acct is not None:
                    ev.metadata["bank_name"] = acct.bank_name
            stages["normalize_ms"] = (time.perf_counter() - t) * 1000

            t = time.perf_counter()
            results = self._detect(ev, image_features)
            stages["detect_ms"] = (time.perf_counter() - t) * 1000

            t = time.perf_counter()
            entities = event_entities(ev)
            primary = max((r.score for r in results), default=0.0)
            delta = self.graph.add_event(ev, labels, primary)
            g_res = self._graph_result(entities)
            results.append(g_res)
            stages["graph_ms"] = (time.perf_counter() - t) * 1000

            signal = max(r.score for r in results)
            suspicious = signal >= self.fusion_config.suspicious_event_threshold
            received = received_at or utcnow()
            record = {
                "event_id": ev.event_id, "event_type": ev.event_type.value, "timestamp": iso(ev.timestamp),
                "received_at": iso(received), "customer_token": ev.customer_token,
                "account_token": ev.account_token, "device_token": ev.device_token, "ip_token": ev.ip_token,
                "customer_label": labels.get("customer"), "account_label": labels.get("account"),
                "device_label": labels.get("device"), "ip_label": labels.get("ip"), "channel": ev.channel,
                "bank_name": ev.metadata.get("bank_name"), "amount": ev.amount, "metadata": ev.metadata,
                "signal_score": round(signal, 4), "suspicious": suspicious,
                "detector_results": [r.model_dump(mode="json") for r in results], "case_id": None, "source": source,
            }

            # ---------------- correlate
            t = time.perf_counter()
            case_payload = None
            created = False
            pending: tuple[OpenCase, list[dict[str, Any]], dict[str, Any] | None] | None = None
            target = self._find_open_case(entities, ev.timestamp)
            if target is not None:
                record["case_id"] = target.case_id
                target.events.append(record)
                target.entities |= entities
                for tok in entities:
                    self.case_index[tok].add(target.case_id)
                target.last_event_at = max(target.last_event_at, ev.timestamp)
                pending = (target, [record], None)
            elif suspicious:
                cluster = self._cluster(entities, ev.timestamp)
                members = [c.record for c in cluster if c.record.get("case_id") is None] + [record]
                n_susp = sum(1 for m in members if m["suspicious"])
                if n_susp >= self.fusion_config.min_correlated_signals:
                    scored = self.score_case(members)
                    if scored["risk"] >= self.fusion_config.case_creation_min_risk:
                        case_id = f"FM-{self._case_seq}"
                        self._case_seq += 1
                        stamps = [_ts(m["timestamp"]) for m in members]
                        oc = OpenCase(case_id=case_id, status=CaseStatus.NEW.value, first_event_at=min(stamps),
                                      last_event_at=max(stamps), events=members, scenario=scenario)
                        for m in members:
                            m["case_id"] = case_id
                            oc.entities |= _dict_entities(m)
                        self._index_case(oc)
                        pending = (oc, members, scored)
                        created = True
            stages["correlate_ms"] = (time.perf_counter() - t) * 1000

            # ---------------- persist event + channel tables
            t = time.perf_counter()
            self._persist_event(s, ev, record, labels, received, source, image_features)
            audit(s, "event.received", actor=source, entity_type="event", entity_id=ev.event_id,
                  details={"event_type": ev.event_type.value, "signal_score": round(signal, 4),
                           "sanitized_keys": sanitized_keys, "case_id": record["case_id"]}, timestamp=received)
            stages["persist_ms"] = (time.perf_counter() - t) * 1000

            # ---------------- score + explain + policy (case level)
            if pending is not None:
                t = time.perf_counter()
                oc, new_records, scored = pending
                case_payload = self._persist_case(s, oc, new_records, created=created, source=source, scored=scored)
                stages["score_explain_policy_ms"] = (time.perf_counter() - t) * 1000
                self.case_build_latencies.append(stages["correlate_ms"] + stages["score_explain_policy_ms"])

            # ---------------- learn (profile update after detection)
            self.profiles.update(ev, trusted=not suspicious and record["case_id"] is None,
                                 signals=self._fired_signals(record["detector_results"]))
            self._remember(ev, suspicious, record)
            stages["total_ms"] = (time.perf_counter() - t_all) * 1000
            self.pipeline_latencies.append(stages["total_ms"])

        stages = {k: round(v, 3) for k, v in stages.items()}
        if source != "seed":
            messages.extend(self._event_messages(record, labels, delta, stages, case_payload, created))
        return {
            "event": record,
            "detector_results": record["detector_results"],
            "signal_score": record["signal_score"],
            "suspicious": suspicious,
            "graph_delta": delta,
            "case": case_payload["case"] if case_payload else None,
            "case_created": created,
            "policy": case_payload["case"]["policy"] if case_payload else None,
            "stages": stages,
            "messages": messages,
        }

    def _find_open_case(self, entities: set[str], ts: datetime) -> OpenCase | None:
        candidates: set[str] = set()
        for tok in entities:
            candidates |= self.case_index.get(tok, set())
        best = None
        for cid in candidates:
            oc = self.open_cases.get(cid)
            if oc is None or oc.status not in ATTACHABLE_STATUSES:
                continue
            if ts - self.window <= oc.last_event_at + timedelta(seconds=1) and ts >= oc.first_event_at - self.window:
                if best is None or oc.risk > best.risk:
                    best = oc
        return best

    def _persist_event(self, s: Session, ev: NormalizedEvent, record: dict[str, Any], labels: dict[str, Any],
                       received: datetime, source: str, image_features: dict[str, Any] | None) -> None:
        s.add(Event(
            event_id=ev.event_id, event_type=ev.event_type.value, timestamp=ev.timestamp, received_at=received,
            customer_token=ev.customer_token, account_token=ev.account_token, device_token=ev.device_token,
            ip_token=ev.ip_token, customer_label=labels.get("customer"), account_label=labels.get("account"),
            device_label=labels.get("device"), ip_label=labels.get("ip"), channel=ev.channel,
            bank_name=ev.metadata.get("bank_name"), amount=ev.amount, event_metadata=ev.metadata,
            signal_score=record["signal_score"], suspicious=record["suspicious"],
            detector_results=record["detector_results"], case_id=record["case_id"], source=source,
        ))
        s.flush()
        md = ev.metadata
        if ev.event_type == EventType.transaction:
            s.add(Transaction(event_id=ev.event_id, customer_token=ev.customer_token, account_token=ev.account_token,
                              beneficiary_token=md.get("beneficiary_token"), merchant=md.get("merchant"),
                              amount=ev.amount, currency=md.get("currency", "INR"), city=md.get("city"),
                              timestamp=ev.timestamp))
        elif ev.event_type == EventType.kyc_verification:
            kyc_res = next((r for r in record["detector_results"] if r["channel"] == "kyc"), {})
            s.add(KycEvent(event_id=ev.event_id, customer_token=ev.customer_token, kyc_token=md.get("kyc_token"),
                           media_sha256=md.get("media_sha256"), media_retained=bool(md.get("media_retained")),
                           manipulation_score=kyc_res.get("score", 0.0),
                           face_detected=(image_features["faces_detected"] > 0)
                           if image_features and image_features.get("face_detection_available") else None,
                           features=kyc_res.get("details", {}).get("features", {}),
                           detector_version=self.kyc.version_label, timestamp=ev.timestamp))
        elif ev.event_type == EventType.cloud_event:
            cloud_res = next((r for r in record["detector_results"] if r["channel"] == "cloud"), {})
            s.add(CloudEvent(event_id=ev.event_id, principal_token=md.get("principal_token"),
                             action=md.get("action"), resource_token=md.get("resource_token"),
                             region=md.get("region"),
                             privileged=bool(cloud_res.get("details", {}).get("features", {}).get("privileged")),
                             timestamp=ev.timestamp))

    def _persist_case(self, s: Session, oc: OpenCase, new_records: list[dict[str, Any]], *, created: bool,
                      source: str, scored: dict[str, Any] | None = None, link: bool = True) -> dict[str, Any]:
        scored = scored or self.score_case(oc.events)
        now = utcnow()
        policy = scored["policy"]
        row = s.get(FraudCase, oc.case_id)
        prev_action = row.policy_action if row else None
        prev_risk = row.risk_score if row else 0.0
        status = oc.status
        # policy-driven status transitions never override analyst decisions
        if status in (CaseStatus.NEW.value, CaseStatus.INVESTIGATING.value):
            if policy["action"] in (PolicyAction.HOLD_INVESTIGATE.value, PolicyAction.BLOCK_HOLD_INVESTIGATE.value):
                status = CaseStatus.HOLD.value
            elif policy["action"] == PolicyAction.STEP_UP.value and status == CaseStatus.NEW.value:
                status = CaseStatus.INVESTIGATING.value
        oc.status = status
        oc.risk = scored["risk"]
        oc.policy_action = policy["action"]
        banks = sorted({r["bank_name"] for r in oc.events if r.get("bank_name")})
        primary = next((r["customer_token"] for r in oc.events if r.get("customer_token")), None)
        created_at = oc.first_event_at if source == "seed" else now
        updated_at = oc.last_event_at if source == "seed" else now
        if row is None:
            row = FraudCase(case_id=oc.case_id, created_at=created_at, source=source, scenario=oc.scenario,
                            first_event_at=oc.first_event_at)
            s.add(row)
        row.risk_score = scored["risk"]
        row.severity = policy["severity"]
        row.status = status
        row.updated_at = updated_at
        row.first_event_at = oc.first_event_at
        row.last_event_at = oc.last_event_at
        row.channel_scores = scored["channel_scores"]
        row.graph_score = scored["channel_scores"]["graph"]
        row.temporal_score = scored["channel_scores"]["temporal"]
        row.confidence = scored["confidence"]
        row.explanations = scored["explanations"]
        row.contributions = scored["contributions"]
        row.graph_signals = scored["graph"]["signals"]
        row.policy_action = policy["action"]
        row.policy = policy
        row.summary = scored["summary"]
        row.primary_customer = primary
        row.banks = banks
        s.flush()
        for rec in new_records if link else []:
            s.add(CaseEvent(case_id=oc.case_id, event_id=rec["event_id"], added_at=now))
            existing = s.get(Event, rec["event_id"])
            if existing is not None:
                existing.case_id = oc.case_id
        existing_entities = {e for e in s.scalars(select(CaseEntity.entity_token).where(CaseEntity.case_id == oc.case_id))}
        for tok in sorted(oc.entities - existing_entities):
            node = self.graph.g.nodes[tok] if tok in self.graph.g else {}
            s.add(CaseEntity(case_id=oc.case_id, entity_token=tok, entity_type=node.get("type", "unknown"),
                             label=node.get("label", tok), bank_name=node.get("bank")))
        s.add(RiskScore(case_id=oc.case_id, event_id=new_records[-1]["event_id"], risk_score=scored["risk"],
                        channel_scores=scored["channel_scores"], policy_action=policy["action"],
                        timestamp=_ts(new_records[-1]["timestamp"])))
        audit_ts = oc.last_event_at if source == "seed" else now
        if created:
            audit(s, "case.created", entity_type="case", entity_id=oc.case_id, timestamp=audit_ts,
                  details={"risk": scored["risk"], "events": len(oc.events)})
        else:
            audit(s, "case.score_updated", entity_type="case", entity_id=oc.case_id, timestamp=audit_ts,
                  details={"risk_from": prev_risk, "risk_to": scored["risk"], "event_id": new_records[-1]["event_id"]})
        policy_changed = prev_action != policy["action"]
        if policy_changed:
            audit(s, "policy.triggered", entity_type="case", entity_id=oc.case_id, timestamp=audit_ts,
                  details={"policy_id": policy["policy_id"], "action": policy["action"], "risk": scored["risk"]})
        return {"case": case_summary(row, len(oc.events)), "policy_changed": policy_changed,
                "previous_risk": prev_risk}

    def _event_messages(self, record: dict[str, Any], labels: dict[str, Any], delta: dict[str, list],
                        stages: dict[str, float], case_payload: dict[str, Any] | None,
                        created: bool) -> list[dict[str, Any]]:
        eid = record["event_id"]
        brief = {k: record[k] for k in ("event_id", "event_type", "timestamp", "bank_name", "amount", "channel",
                                         "account_label", "device_label", "ip_label", "customer_label")}
        brief["subtype"] = record["metadata"].get("subtype")
        brief["city"] = record["metadata"].get("city")
        msgs: list[dict[str, Any]] = [
            {"type": "event.received", "data": brief},
            {"type": "event.normalized", "data": {k: record[k] for k in (
                "event_id", "event_type", "timestamp", "customer_token", "account_token", "device_token",
                "ip_token", "channel", "amount", "metadata")}},
            {"type": "detector.result", "data": {"event_id": eid, "results": record["detector_results"],
                                                  "signal_score": record["signal_score"],
                                                  "suspicious": record["suspicious"]}},
            {"type": "graph.updated", "data": {"event_id": eid, "case_id": record["case_id"],
                                                "nodes_added": [{"id": n, "type": self.graph.g.nodes[n]["type"],
                                                                 "label": self.graph.g.nodes[n]["label"]}
                                                                for n in delta["nodes"]],
                                                "edges_added": delta["edges"]}},
        ]
        if case_payload is not None:
            case = case_payload["case"]
            msgs.append({"type": "risk.updated", "data": {"case_id": case["case_id"], "event_id": eid,
                                                           "risk_score": case["risk_score"],
                                                           "previous_risk": case_payload["previous_risk"],
                                                           "channel_scores": case["channel_scores"]}})
            msgs.append({"type": "case.created" if created else "case.updated", "data": case})
            if case_payload["policy_changed"]:
                msgs.append({"type": "policy.triggered", "data": {"case_id": case["case_id"], "policy": case["policy"]}})
        msgs.append({"type": "event.processed", "data": {"event_id": eid, "stages": stages,
                                                          "case_id": record["case_id"],
                                                          "signal_score": record["signal_score"]}})
        return msgs

    # ================================================================ analyst feedback / learn
    def apply_feedback(self, case_id: str, fb: FeedbackIn, at: datetime | None = None) -> dict[str, Any]:
        with self.lock, session_scope() as s:
            row = s.get(FraudCase, case_id)
            if row is None:
                raise KeyError(case_id)
            prev = row.status
            new_status = ACTION_TO_STATUS[fb.action.value] or prev
            now = at or utcnow()
            row.status = new_status
            row.updated_at = now
            if fb.action == AnalystAction.BLOCK:
                row.policy = {**(row.policy or {}), "analyst_override": "BLOCK", "overridden_at": iso(now)}
                row.policy_action = PolicyAction.BLOCK_HOLD_INVESTIGATE.value
            elif fb.action == AnalystAction.STEP_UP:
                row.policy = {**(row.policy or {}), "analyst_override": "STEP_UP", "overridden_at": iso(now)}
            fb_row = AnalystFeedback(case_id=case_id, action=fb.action.value, previous_status=prev,
                                     new_status=new_status, analyst=fb.analyst, notes=fb.notes, created_at=now)
            s.add(fb_row)
            audit(s, "analyst.action", actor=fb.analyst, entity_type="case", entity_id=case_id, timestamp=now,
                  details={"action": fb.action.value, "from": prev, "to": new_status})
            audit(s, "feedback.submitted", actor=fb.analyst, entity_type="case", entity_id=case_id, timestamp=now,
                  details={"action": fb.action.value, "has_notes": bool(fb.notes)})
            learning = self._learn_from_feedback(s, row, fb.action)
            oc = self.open_cases.get(case_id)
            if oc is not None:
                oc.status = new_status
            if new_status not in ATTACHABLE_STATUSES:
                self._unindex_case(case_id)
            elif oc is None:
                self._load_open_case(s, row)
            s.flush()
            n_events = s.scalar(select(func.count()).select_from(CaseEvent).where(CaseEvent.case_id == case_id))
            summary = case_summary(row, n_events)
            fb_dict = feedback_to_dict(fb_row)
        msgs = [
            {"type": "analyst.action", "data": {"case_id": case_id, "feedback": fb_dict, "learning": learning}},
            {"type": "case.updated", "data": summary},
        ]
        return {"case": summary, "feedback": fb_dict, "learning": learning, "messages": msgs}

    def _case_entity_tokens(self, s: Session, case_id: str) -> list[CaseEntity]:
        return list(s.scalars(select(CaseEntity).where(CaseEntity.case_id == case_id)))

    def _trust_case_entities(self, s: Session, case_id: str) -> None:
        ents = self._case_entity_tokens(s, case_id)
        devices = [e.entity_token for e in ents if e.entity_type == "device"]
        ips = [e.entity_token for e in ents if e.entity_type == "ip"]
        for c in (e.entity_token for e in ents if e.entity_type == "customer"):
            self.profiles.trust_entities(c, devices, ips)

    def _learn_from_feedback(self, s: Session, row: FraudCase, action: AnalystAction) -> dict[str, Any]:
        ents = self._case_entity_tokens(s, row.case_id)
        if action == AnalystAction.CONFIRM_FRAUD:
            tokens = [e.entity_token for e in ents if e.entity_type in ("device", "ip")]
            self.graph.set_watchlist(tokens, True)
            return {"effect": "watchlist", "entities": len(tokens),
                    "note": "Devices/IPs from this case now raise graph risk for future events."}
        if action == AnalystAction.MARK_LEGITIMATE:
            self._trust_case_entities(s, row.case_id)
            self.graph.set_watchlist([e.entity_token for e in ents], False)
            return {"effect": "trusted", "entities": len(ents),
                    "note": "Case devices/IPs added to the customers' trusted baseline (fewer repeat alerts)."}
        return {"effect": "none"}

    def labelled_transaction_examples(self) -> tuple[np.ndarray, np.ndarray]:
        X, y = [], []
        with session_scope() as s:
            q = (select(Event, FraudCase.status).join(FraudCase, FraudCase.case_id == Event.case_id)
                 .where(Event.event_type == "transaction")
                 .where(FraudCase.status.in_([CaseStatus.CONFIRMED_FRAUD.value, CaseStatus.FALSE_POSITIVE.value])))
            for ev, status in s.execute(q):
                res = next((r for r in ev.detector_results or [] if r.get("channel") == "transaction"), None)
                feats = (res or {}).get("details", {}).get("features")
                if feats:
                    X.append([float(feats[f]) for f in TXN_FEATURES])
                    y.append(1 if status == CaseStatus.CONFIRMED_FRAUD.value else 0)
        return np.asarray(X, dtype=float).reshape(-1, len(TXN_FEATURES)), np.asarray(y, dtype=int)

    def retrain_transaction_model(self, actor: str) -> dict[str, Any]:
        X, y = self.labelled_transaction_examples()
        with self.lock:
            self.txn.train(X if len(y) else None, y if len(y) else None)
        with session_scope() as s:
            audit(s, "model.retrained", actor=actor, entity_type="model", entity_id=self.txn.version_label,
                  details={"feedback_samples": int(len(y)), "evaluation": self.txn.evaluation})
        return {"model_version": self.txn.version_label, "feedback_samples": int(len(y)),
                "evaluation": self.txn.evaluation}

    # ================================================================ config
    def update_fusion(self, cfg: FusionConfig, actor: str) -> None:
        with self.lock, session_scope() as s:
            old = self.fusion_config.model_dump()
            self.fusion_config = cfg
            self.behavior.window = self.window
            rec = s.get(PolicyRecord, "fusion")
            rec.config, rec.updated_at, rec.updated_by = cfg.model_dump(), utcnow(), actor
            audit(s, "config.updated", actor=actor, entity_type="config", entity_id="fusion",
                  details={"from": old, "to": cfg.model_dump()})

    def update_policy(self, cfg: PolicyConfig, actor: str) -> None:
        with self.lock, session_scope() as s:
            old = self.policy_config.model_dump(mode="json")
            self.policy_config = cfg
            rec = s.get(PolicyRecord, "policy")
            rec.config, rec.updated_at, rec.updated_by = cfg.model_dump(mode="json"), utcnow(), actor
            audit(s, "policy.updated", actor=actor, entity_type="config", entity_id="policy",
                  details={"from": old, "to": cfg.model_dump(mode="json")})

    def rescore_open_cases(self) -> list[dict[str, Any]]:
        """Apply new weights/thresholds to open cases (analyst-visible re-evaluation)."""
        msgs = []
        with self.lock, session_scope() as s:
            for oc in list(self.open_cases.values()):
                if not oc.events:
                    continue
                payload = self._persist_case(s, oc, [oc.events[-1]], created=False, source="live", link=False)
                msgs.append({"type": "case.updated", "data": payload["case"]})
        return msgs


_engine: FraudMeshEngine | None = None


def get_engine() -> FraudMeshEngine:
    global _engine
    if _engine is None:
        _engine = FraudMeshEngine()
    return _engine


def reset_engine() -> None:
    global _engine
    _engine = None
