# FRAUDMESH

**Cross-Channel Fraud Detection & Intelligence**

> *Connect the signals. Expose the attack. Explain the risk.*

> ⚠️ **SIMULATED DATA — NO REAL BANK INCIDENT.** This is a hackathon prototype. "SBI", "HDFC Bank" and
> "ICICI Bank" appear only as fictional demo entities in a controlled simulation. Every customer, account,
> device, IP and event is synthetic. Nothing here implies that any real bank experienced any incident.

FraudMesh does not treat suspicious events as isolated alerts. It connects related events, entities and
behaviours into **a single explainable fraud case**:

```
EVENT → NORMALIZE → DETECT → CORRELATE → GRAPH → RISK FUSION → EXPLAIN → POLICY → INVESTIGATOR UI → ANALYST FEEDBACK → LEARN
```

---

## Contents

1. [Project overview](#1-project-overview) · 2. [Problem statement](#2-problem-statement) · 3. [Innovation](#3-innovation) ·
4. [Target users](#4-target-users) · 5. [System architecture](#5-system-architecture) · 6. [Detailed data flow](#6-detailed-data-flow) ·
7. [Technology stack](#7-technology-stack) · 8. [Backend architecture](#8-backend-architecture) · 9. [Frontend architecture](#9-frontend-architecture) ·
10. [ML architecture](#10-ml-architecture) · 11. [Entity graph architecture](#11-entity-graph-architecture) · 12. [Risk-fusion methodology](#12-risk-fusion-methodology) ·
13. [Explainability methodology](#13-explainability-methodology) · 14. [Privacy architecture](#14-privacy-architecture) · 15. [Database schema](#15-database-schema) ·
16. [API documentation](#16-api-documentation) · 17. [Repository structure](#17-repository-structure) · 18. [Installation](#18-installation) ·
19. [Environment setup](#19-environment-setup) · 20. [Database setup](#20-database-setup) · 21. [Demo data generation](#21-demo-data-generation) ·
22. [Attack simulation](#22-attack-simulation) · 23. [Frontend startup](#23-frontend-startup) · 24. [Backend startup](#24-backend-startup) ·
25. [Docker deployment](#25-docker-deployment) · 26. [Testing](#26-testing) · 27. [Evaluation metrics](#27-evaluation-metrics) ·
28. [Security considerations](#28-security-considerations) · 29. [Limitations](#29-limitations) · 30. [Future improvements](#30-future-improvements) ·
[Troubleshooting](#troubleshooting)

---

## Quick start (judges)

```bash
docker compose up --build          # dashboard → http://localhost:3000 · API docs → http://localhost:8000/docs
```

Or without Docker (two terminals):

```bash
cd backend && pip install -r requirements.txt && uvicorn app.main:app --reload     # :8000, auto-seeds synthetic data
cd frontend && npm install && npm run dev                                          # :5173
```

Open the dashboard, press **▶ Start simulated attack**, and watch the case develop in real time —
or run `python scripts/simulate_attack.py` in a third terminal.

---

## 1. Project overview

FraudMesh is a locally runnable web application that demonstrates **cross-channel fraud correlation**.
Independent detectors score transactions, logins/sessions, device and IP changes, KYC media and cloud-security
events. A temporal + entity-graph correlation engine merges related weak signals into one case, fuses the
channel scores into a 0–100 risk, explains *why*, applies a configurable policy, and learns from analyst
feedback. A real-time dashboard (WebSockets) lets an audience watch an attack unfold:

| T+ | Event | What FraudMesh sees |
|---|---|---|
| 00:00 | Normal login — SBI `SBI-DEMO-1042` | low risk |
| 01:00 | New device `DEVICE-7F21` | takeover risk ↑ |
| 02:00 | New IP / network (Kolkata) | impossible travel; **case created** |
| 03:00 | MFA reset + password change | takeover ↑↑ |
| 05:00 | KYC re-verification | prototype KYC detector → manipulation 0.91 |
| 07:00 | ₹1,85,000 to a NEW beneficiary | ~6× baseline, XGBoost ≈ 0.99 → HOLD + INVESTIGATE |
| 08:00 | `DEVICE-7F21` logs into `HDFC-DEMO-7781` | graph: device reuse → CRITICAL |
| 09:00 | Same device/IP on `ICICI-DEMO-5520` | cross-bank link (3 banks) |
| 10:00 | `PRIVILEGED_API_CALL` from attacker network | cloud anomaly |
| **Result** | **One case, 9 events, risk ≈ 97/100, CRITICAL** | **BLOCK / HOLD + INVESTIGATE** |

The final score is computed by the running system, not hard-coded (it was 96.8 in the run recorded below).

## 2. Problem statement

Modern fraud is multi-stage and multi-channel: an account takeover, a manipulated KYC selfie, a mule transfer
and a cloud-privilege change can each look only mildly unusual in isolation — and in many organisations they
land in different tools owned by different teams. Individually thresholded alerts either miss the attack
(thresholds too high) or drown analysts (too low). What is missing is the **connection** between the signals.

## 3. Innovation

* **Correlation first, not classification first.** Weak signals from six channels are linked through shared
  entities (customer, account, device, IP, beneficiary, KYC record, cloud principal/resource) inside a
  configurable temporal window (default 15 min) into a single case.
* **Entity + temporal graph.** A NetworkX graph exposes structure a per-event model cannot see: one device
  driving accounts of three different people at three banks.
* **Linear, auditable fusion** with exact per-channel contributions, plus TreeSHAP for the ML model.
* **Policy as data.** Thresholds and actions are configurable via API; every case carries `action`, `reason`,
  `policy_id`, `threshold`.
* **Closed loop.** Analyst decisions change the system: confirmed-fraud devices/IPs are watch-listed in the graph,
  false-positive devices/IPs join the customer's trusted baseline, and the transaction model can be retrained
  with analyst labels.
* **Privacy by design.** Keyed tokenization, PII-scrubbed metadata, no raw KYC media retention, redacted logs.

## 4. Target users

* Fraud investigators / analysts (case investigation, actions, feedback)
* Fraud-strategy & risk teams (weights, thresholds, policies)
* SOC / cloud-security teams (cloud anomalies correlated with customer fraud)
* ML / model-risk teams (detector health, distributions, evaluation)
* Hackathon judges (one-command demo)

## 5. System architecture

```
                         ┌──────────────── React + TypeScript dashboard (Vite, Tailwind, Recharts, Cytoscape.js) ───────────────┐
                         │ Dashboard · Case Investigation · Event Explorer · Entity Graph · Policy Center · Model Monitoring │
                         └───────────────▲──────────────────────────────────────────────▲───────────────────────────────────┘
                                   REST /api/*                                    WebSocket /ws/events
┌──────────────────────────────────────────┴──────────── FastAPI backend ─────────────────┴────────────────────────────────────┐
│  API (validation, rate limit, admin token) → FraudMeshEngine                                                              │
│                                                                                                                            │
│  normalizer ─► privacy/tokenizer ─► detectors ──────────────┐   graph/entity_graph (NetworkX)                              │
│                                     • transaction (XGBoost+SHAP)│         ▲                                                  │
│                                     • behavior/ATO (IForest+rules)        │                                                  │
│                                     • KYC (OpenCV, PROTOTYPE)  ├─► correlation (temporal window + shared entities)          │
│                                     • cloud (IForest+rules)    │         ▼                                                   │
│  services/profiles (baselines) ◄────┘                          └─► case engine ─► policies/fusion ─► explainability ─► policies/engine
│                                                                          │                                                   │
│  services/broadcaster (WebSocket) ◄──────────── messages ────────────────┤                                                   │
│  services/audit, database (SQLAlchemy: SQLite / PostgreSQL-compatible) ◄─┘                                                   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 6. Detailed data flow

1. **EVENT** — `POST /api/events` (or batch / KYC upload / demo runner). Pydantic validates type, size and bank.
2. **NORMALIZE** — `services/normalizer.py` tokenizes identifiers (`CUSTOMER_10291 → usr_…`), sanitises metadata
   (drops PII keys, tokenizes beneficiary/principal ids, scrubs PII-like strings), stamps UTC time.
3. **DETECT** — the detector for the event type reads the customer/principal profile *before* the event is applied.
4. **GRAPH** — entities and relationships are inserted; the graph detector scores the event's neighbourhood.
5. **CORRELATE** — if any entity belongs to an open case whose activity is within the window, the event joins it.
   Otherwise, if the event is suspicious (signal ≥ 0.35), a bounded BFS over recent events sharing entities
   builds a cluster; ≥ 2 suspicious events **and** fused risk ≥ 15 create a case containing the whole cluster.
6. **RISK FUSION** — per-channel case scores (max over events; graph over the case's entity set; temporal from
   the cluster shape) → weighted sum → 0–100.
7. **EXPLAIN** — ranked evidence items with approximate point contributions.
8. **POLICY** — configurable tiers map the risk to an action; status moves NEW → INVESTIGATING/HOLD automatically
   but never overrides analyst decisions.
9. **PERSIST + AUDIT** — event, channel tables, case, case_events, case_entities, risk_scores, audit_logs.
10. **LEARN (profile)** — the customer baseline is updated; entities from suspicious events are *not* trusted.
11. **BROADCAST** — `event.received`, `event.normalized`, `detector.result`, `graph.updated`, `risk.updated`,
    `case.created|updated`, `policy.triggered`, `event.processed` (stage timings).
12. **ANALYST FEEDBACK → LEARN** — `POST /api/cases/{id}/feedback` updates status, writes feedback + audit, and
    watch-lists or trusts entities; `POST /api/models/retrain` retrains XGBoost with analyst labels.

## 7. Technology stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI, Pydantic v2, WebSockets, SQLAlchemy 2 |
| ML | scikit-learn (Isolation Forest), XGBoost, SHAP (TreeExplainer), NetworkX, OpenCV (headless) |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Recharts, Cytoscape.js, lucide-react |
| Storage | SQLite (default, WAL) — PostgreSQL-compatible schema via `DATABASE_URL` |
| Deployment | Docker, Docker Compose, nginx (static + reverse proxy for `/api` and `/ws`) |
| Tests | pytest, FastAPI TestClient |

Redis is optional and not required: the single-process prototype keeps real-time state in memory and rebuilds
it from the database on start-up.

## 8. Backend architecture

```
backend/app/
├── main.py                 FastAPI app, lifespan (train → auto-seed → rebuild state), middleware
├── config.py               environment-driven settings (no secrets in code)
├── api/                    events.py · cases.py · admin.py (config/policies/metrics/models/graph/audit/health)
│                           kyc.py (upload) · demo.py (scenarios, simulate, reset, /ws/events) · deps.py (admin auth)
├── schemas/                events.py (EventIn, NormalizedEvent, DetectorResult) · cases.py · config.py
├── services/               engine.py (pipeline + case engine) · normalizer.py · profiles.py · scenarios.py
│                           seeder.py · demo.py · metrics.py · broadcaster.py · audit.py · serializers.py
├── detectors/              transaction.py · behavior.py · kyc.py · cloud.py · base.py
├── graph/                  entity_graph.py
├── explainability/         explainer.py
├── policies/               fusion.py · engine.py
├── privacy/                tokenizer.py
├── database/               models.py · db.py
└── utils/                  logging.py (redaction) · ratelimit.py · geo.py · timeutil.py
```

**Module guide**

| Module | Responsibility |
|---|---|
| `services/engine.py` | `FraudMeshEngine`: owns detectors, profiles, graph, recent-event index and open-case index; `process_event` runs the full pipeline; `score_case`, `apply_feedback`, `retrain_transaction_model`, `rebuild_state` |
| `services/normalizer.py` | Converts `EventIn` → `NormalizedEvent` + safe display labels |
| `services/profiles.py` | Per-customer and per-cloud-principal baselines (amounts, beneficiaries, merchants, trusted devices/IPs, login hours, last location, session window) |
| `services/scenarios.py` | Six synthetic scenario generators (stdlib-only; imported by scripts) |
| `services/seeder.py` | Synthetic population + history; runs everything through the real pipeline |
| `services/demo.py` | Live scenario runner with WebSocket step events; `reset_live_data` |
| `services/metrics.py` | Dashboard and monitoring metrics computed from the database |
| `detectors/*` | Independent detectors returning the standard `DetectorResult` |
| `graph/entity_graph.py` | Graph construction, graph risk, suspicious paths, JSON export |
| `explainability/explainer.py` | Ranked explanations and case summary |
| `policies/fusion.py`, `policies/engine.py` | Weighted fusion; policy tier evaluation |
| `privacy/tokenizer.py` | HMAC tokenization, display labels, metadata sanitisation, media fingerprint |

## 9. Frontend architecture

```
frontend/src/
├── main.tsx                routes + LiveProvider + StartupGate (waits for backend readiness)
├── api/                    client.ts (fetch wrapper, admin token header) · types.ts
├── hooks/                  live.tsx (WebSocket context, auto-reconnect, simulation state) · useApi.ts (live refetch)
├── components/             Layout · RiskGauge · ChannelScores · Timeline · EntityGraph (Cytoscape) · CaseParts
│                           (WhyFlagged, CaseActions, RiskTrajectory) · DetectorOutputs (SHAP bars) · LiveStream
│                           · PipelineStrip · SimulationPanel · ui (badges, loading/empty/error states, banner)
└── pages/                  Dashboard · Cases · CaseInvestigation · EventExplorer · GraphPage · PolicyCenter · ModelMonitoring
```

* All numbers come from the backend (`/api/metrics`, `/api/cases/{id}`, …). Live WebSocket messages trigger
  throttled refetches, so the UI never drifts from the database.
* The entity graph updates incrementally (new nodes glow, layout animates) so the audience sees it expand.
* Every action button calls a real endpoint (`POST /api/cases/{id}/feedback`, `/api/demo/simulate`,
  `/api/demo/reset`, `PUT /api/config`, `PUT /api/policies`, `POST /api/models/retrain`, `POST /api/kyc/analyze`).
* Loading, empty and error states on every page; responsive down to phone width.

## 10. ML architecture

| Detector | Method | Output |
|---|---|---|
| **Transaction** (`transaction_xgboost`) | XGBoost (160 trees, depth 4) on 9 features: amount deviation (× baseline), 1-h velocity, beneficiary novelty, merchant novelty, time-of-day deviation, geographic deviation (km from home), device novelty, frequency ratio, amount rarity. Trained at start-up on a **deterministic synthetic dataset** (8 000 rows, 12 % fraud, 2 % label noise); retrainable with analyst labels (weight 5). | `score`, `confidence`, `signals`, TreeSHAP values |
| **Behaviour / account takeover** (`behavior_takeover`) | Isolation Forest on 10 session features (trained on synthetic normal sessions) → `behavior_score`; deterministic rules (new device +18, new IP +12, MFA reset +15, impossible travel +15, login burst +10, device change +10, device switching +8, abnormal session +8, IP switching +6, unusual hour +6) accumulated over the session window. `takeover_score = clamp(Σ rules + 0.2 × behavior_score)` | `behavior_score`, `takeover_score`, `top_signals` |
| **KYC / media** (`kyc_media_demo`) | **Prototype KYC / Media Authenticity Detector**: OpenCV blur/exposure/contrast, Haar face detection, JPEG error-level-analysis and block-noise inconsistency, face/background sharpness mismatch, liveness/face-match metadata. Scripted scenarios may pass a clearly labelled *controlled scenario value*. **Not a deepfake model.** The interface is ready for a validated model (e.g. EfficientNet-B0). | `manipulation_score`, indicators |
| **Cloud** (`cloud_anomaly`) | Isolation Forest (synthetic normal API activity) + rules: unusual privileged call, privilege escalation, new access key, unusual region, API burst, suspicious resource creation, auth anomaly, logging tampering. | `cloud_risk_score`, `cloud_signals` |
| **Graph** (`entity_graph`) | Structural rules on the NetworkX graph (see §11). | graph score, components |

Every detector returns the standard structure:

```json
{ "score": 0.99, "confidence": 0.66, "signals": ["amount_deviation", "new_beneficiary", "new_device"],
  "detector": "transaction_xgboost", "timestamp": "…", "channel": "transaction",
  "model_version": "xgb-synthetic-v1", "signal_details": [...], "details": {...}, "latency_ms": 2.6 }
```

Model persistence: XGBoost is saved as **JSON** (no pickle) with a SHA-256 manifest in `models/`. Isolation
Forests are retrained deterministically at start-up (< 1 s) instead of being unpickled.

## 11. Entity graph architecture

* **Nodes:** customer, account, device, ip, transaction, kyc, cloud_resource, cloud_principal.
* **Edges** (MultiDiGraph keyed by relation): `OWNS` (customer→account), `USED` (account→device),
  `LOGGED_IN_FROM` (device→ip), `INITIATED` (account→transaction), `ASSOCIATED_WITH` (transaction→beneficiary,
  kyc→device, ip→principal, device→previous device), `VERIFIED_WITH` (customer→kyc), `ACCESSED` / `CREATED`
  (principal→resource). Each edge keeps count, first/last seen and recent event ids.
* An account-number beneficiary shares the account token space, so a transfer to `HDFC-DEMO-7781` links to the
  same node that later logs in from `DEVICE-7F21`.
* **Graph risk** is a noisy-OR `1 − Π(1 − cᵢ)` of transparent components:

| Component | Weight |
|---|---|
| Device reused by 2 / 3 / ≥4 **distinct identities** (one person's two bank accounts count once) | 0.50 / 0.75 / 0.90 |
| Device shared by ≥ 2 different customers | 0.25 |
| Cross-bank relationship through a shared device (2 / ≥3 banks) | 0.40 / 0.70 |
| IP shared by ≥ 3 / ≥ 5 identities | 0.30 / 0.50 |
| Beneficiary paid by ≥ 3 accounts (mule-like) | 0.40 |
| Entity watch-listed after a confirmed-fraud decision | 0.60 |

* **Suspicious paths:** `account → shared device/IP → other account (→ owner)`, returned with every case and
  highlighted in red in the UI. Busy infrastructure hubs are not expanded in exports to keep views readable.

## 12. Risk-fusion methodology

```
risk = 100 × ( 0.30·transaction + 0.20·takeover + 0.20·kyc + 0.10·cloud + 0.15·graph + 0.05·temporal )
risk = clamp(risk, 0, 100)
```

* Case channel scores: max of each detector's scores across the case's events; `graph` is computed over the whole
  case entity set; `temporal = min(1, 0.12·(suspicious events − 1) + 0.18·(active channels − 1))`, halved if the
  suspicious events span more than the window.
* Weights, window, suspicious-event threshold (0.35), minimum correlated signals (2) and case-creation minimum risk
  (15) are configurable via `PUT /api/config` or the Policy Center; changes can re-score open cases.
* **These weights are demonstration configuration values, not scientifically optimised parameters.**

**Default policy** (configurable via `PUT /api/policies`):

| Risk | Severity | Action |
|---|---|---|
| 0–29 | LOW | ALLOW |
| 30–59 | MEDIUM | STEP-UP AUTHENTICATION |
| 60–79 | HIGH | HOLD + INVESTIGATE |
| 80–100 | CRITICAL | BLOCK / HOLD + INVESTIGATE |

## 13. Explainability methodology

* Because fusion is linear, each channel's contribution `100 × wᶜ × scoreᶜ` is **exact**.
* Within a channel, points are shared among the signals of that channel's peak event in proportion to the
  detector's own weights: **TreeSHAP values** for XGBoost (from `shap.TreeExplainer`, falling back to XGBoost's
  native `pred_contribs`, which is also exact TreeSHAP); rule points for takeover/cloud; heuristic weights for KYC;
  noisy-OR component weights for the graph. The UI labels these "approximate share".
* A test verifies that SHAP base value + contributions reproduce the model's log-odds — **no SHAP value is invented**.
* Each case exposes: overall risk, channel scores and contributions, ranked evidence with timestamps and source
  events, evidence timeline, entity graph + suspicious paths, triggered policy with reason, confidence, and every
  raw detector output (including SHAP bars in the UI).

## 14. Privacy architecture

* `privacy/tokenizer.py`: `HMAC-SHA256(secret, kind:value)` → `usr_…`, `acc_…`, `dev_…`, `ip_…`, `ben_…`, `kyc_…`,
  `prn_…`, `res_…`. Deterministic (enables correlation), non-reversible without the secret, idempotent on tokens.
  The secret comes from `FRAUDMESH_TOKEN_SECRET` or is generated on first run into `data/.token_secret` (git-ignored).
* Raw identifiers are never persisted. Display labels: customers → token only; IPs → `/16` + token suffix
  (`100.99.x.x #da7e`); synthetic demo ids (`SBI-DEMO-1042`, `DEVICE-7F21`) shown verbatim; anything else masked.
* Metadata sanitisation drops PII keys (name, email, phone, PAN, Aadhaar, address, DOB, password, OTP, card, raw
  image/selfie…), tokenizes identifier keys, and scrubs PII-looking values (emails, phones, PAN, Aadhaar/card-like numbers).
* Logs pass through a redaction filter (emails, IPs, phones, PAN, card/Aadhaar-like numbers, `password=`…).
  Validation errors never echo submitted values.
* KYC media is validated and analysed in memory; only a SHA-256 fingerprint and derived features are stored.
  `FRAUDMESH_KYC_RETAIN_MEDIA=false` by default.
* Coverage is **measured** on `/api/models`: PII tokenization coverage, raw KYC media retained, audit coverage.

## 15. Database schema

SQLAlchemy models (`backend/app/database/models.py`) use only portable types (String, Integer, Float, Boolean,
`DateTime(timezone=True)`, JSON), so the schema runs on SQLite and PostgreSQL.

| Table | Key columns |
|---|---|
| `customers` | customer_token (PK), display_label, home_city, segment, baseline_amount_mean/std, typical_login_hour |
| `accounts` | account_token (PK), customer_token (FK), bank_name, display_label, account_type, opened_at |
| `devices` | device_token (PK), display_label, device_type, os, first_seen |
| `ip_addresses` | ip_token (PK), display_label (masked), city, network_type, first_seen |
| `events` | event_id (PK), event_type, timestamp, received_at, *_token, *_label, channel, bank_name, amount, metadata (JSON), signal_score, suspicious, detector_results (JSON), case_id, source (seed/live) |
| `transactions` | event_id (FK), customer/account/beneficiary tokens, merchant, amount, currency, city |
| `kyc_events` | event_id (FK), kyc_token, media_sha256, media_retained, manipulation_score, face_detected, features, detector_version |
| `cloud_events` | event_id (FK), principal_token, action, resource_token, region, privileged |
| `fraud_cases` | case_id (PK), risk_score, severity, status, created/updated/first/last_event_at, channel_scores, graph_score, temporal_score, confidence, explanations, contributions, graph_signals, policy_action, policy, summary, banks, scenario, source |
| `case_events` | case_id (FK), event_id (FK) |
| `case_entities` | case_id (FK), entity_token, entity_type, label, bank_name |
| `risk_scores` | case_id, event_id, risk_score, channel_scores, policy_action, timestamp (risk history) |
| `analyst_feedback` | case_id (FK), action, previous_status, new_status, analyst, notes, created_at |
| `policies` | key (`fusion` / `policy`), config (JSON), updated_at, updated_by |
| `audit_logs` | timestamp, action, actor, entity_type, entity_id, details (sanitised JSON) |

Case statuses: `NEW, INVESTIGATING, HOLD, RESOLVED, FALSE_POSITIVE, CONFIRMED_FRAUD`.

## 16. API documentation

Interactive OpenAPI docs: **http://localhost:8000/docs**.

| Method | Path | Description |
|---|---|---|
| POST | `/api/events` | Submit one event (runs the full pipeline, broadcasts over WebSocket) |
| POST | `/api/events/batch` | Submit up to 500 events (processed in timestamp order) |
| GET | `/api/events` | Recent events; filters `customer, account, bank, device, ip, event_type, channel, case_id, since, until, min_risk, max_risk, suspicious, source, limit, offset` |
| GET | `/api/events/{event_id}` | One event with detector results |
| GET | `/api/cases` | Cases; `status` (`active` or a status), `severity`, `min_risk`, `sort=updated|risk|created`, `limit` |
| GET | `/api/cases/{case_id}` | Full case: events, entities, explanations, contributions, detector outputs, risk history, feedback, graph, suspicious paths |
| POST | `/api/cases/{case_id}/feedback` | Analyst action: `HOLD, STEP_UP, BLOCK, INVESTIGATE, MARK_LEGITIMATE, CONFIRM_FRAUD, RESOLVE, COMMENT` |
| GET | `/api/metrics` | Dashboard metrics |
| GET / PUT | `/api/policies` | Policy tiers (PUT needs `X-Admin-Token` when configured; `?rescore=true`) |
| GET / PUT | `/api/config` | Risk-fusion configuration (PUT as above) |
| GET | `/api/health` | Service health / readiness |
| GET | `/api/graph` | Graph around `case_id`, `entity` (token or synthetic label) with `depth`, or all active cases |
| GET | `/api/models` | Detector health, versions, latency, distributions, evaluation, privacy/audit coverage |
| POST | `/api/models/retrain` | Retrain the transaction model with analyst labels (admin) |
| POST | `/api/kyc/analyze` | Multipart KYC image upload (JPEG/PNG ≤ 5 MB); optional `submit_event` |
| GET | `/api/audit` | Recent audit entries |
| GET | `/api/demo/scenarios` | Scenario list + flagship steps |
| POST | `/api/demo/simulate` | Stream a scenario live `{scenario, step_seconds, reset}` |
| GET | `/api/demo/status` | Simulation progress |
| POST | `/api/demo/reset` | Remove live (non-seed) events/cases (admin) |
| WS | `/ws/events` | Real-time messages |

**WebSocket message types:** `event.received`, `event.normalized`, `detector.result`, `graph.updated`,
`risk.updated`, `case.created`, `case.updated`, `policy.triggered`, `event.processed`, `analyst.action`,
`simulation.started|step|completed|failed`, `demo.reset`, `config.updated`, `policy.updated`, `model.retrained`.

### Example requests and responses

Submit an event (raw synthetic identifiers are tokenized on ingestion):

```bash
curl -X POST http://localhost:8000/api/events -H 'Content-Type: application/json' -d '{
  "event_type": "login", "customer_id": "CUSTOMER_10291", "account_id": "SBI-DEMO-1042",
  "bank_name": "SBI", "device_id": "DEVICE-A1C3", "ip_address": "100.72.14.21",
  "metadata": {"city": "Mumbai"}
}'
```

Response (trimmed; recorded right after the flagship attack, so the login joins the open case):

```json
{
  "event": {
    "event_id": "evt_e06e1234b6154009", "event_type": "login", "timestamp": "2026-09-30T02:52:41.525360Z",
    "customer_token": "usr_d6746e109d", "account_token": "acc_cba3992fed", "device_token": "dev_7682ae39e7",
    "ip_token": "ip_28ec971752", "account_label": "SBI-DEMO-1042", "bank_name": "SBI",
    "signal_score": 1.0, "suspicious": true, "case_id": "FM-10282"
  },
  "detector_results": [
    {"detector": "behavior_takeover", "channel": "takeover", "score": 1.0, "confidence": 1.0,
     "signals": ["new_device", "impossible_travel", "mfa_reset", "new_ip", "login_burst", "device_switching", "..."],
     "model_version": "iforest-synthetic-v1+rules-v1"},
    {"detector": "entity_graph", "channel": "graph", "score": 0.3, "confidence": 0.8,
     "signals": ["ip_shared_accounts"], "model_version": "networkx-rules-v1"}
  ],
  "case_created": false,
  "stages": {"normalize_ms": 0.676, "detect_ms": 9.488, "graph_ms": 0.227, "correlate_ms": 0.017,
             "persist_ms": 0.826, "score_explain_policy_ms": 3.756, "total_ms": 15.091}
}
```

The session is still inside the attack window, so its accumulated takeover signals still apply.

Get the case:

```bash
curl http://localhost:8000/api/cases/FM-10282
```

```json
{
  "case_id": "FM-10282", "risk_score": 96.8, "severity": "CRITICAL", "status": "HOLD",
  "channel_scores": {"transaction": 0.9897, "takeover": 1.0, "kyc": 0.91, "cloud": 0.95, "graph": 0.9606, "temporal": 1.0},
  "graph_score": 0.9606, "temporal_score": 1.0, "confidence": 0.7399,
  "policy_action": "BLOCK_HOLD_INVESTIGATE",
  "policy": {"action": "BLOCK_HOLD_INVESTIGATE", "action_label": "BLOCK / HOLD + INVESTIGATE",
             "reason": "Risk 97/100 is within CRITICAL band 80–100 (POL-CRITICAL) → BLOCK / HOLD + INVESTIGATE",
             "policy_id": "POL-CRITICAL", "threshold": 80, "severity": "CRITICAL"},
  "banks": ["HDFC Bank", "ICICI Bank", "SBI"],
  "top_signals": ["₹1,85,000 transfer is 6.0× customer baseline (avg ₹30,700)",
                  "KYC manipulation score = 0.91 (prototype media detector)", "..."],
  "events": ["..."], "entities": ["..."], "explanations": ["..."], "analyst_feedback": [], "graph": {"nodes": ["..."], "edges": ["..."]}
}
```

Analyst feedback:

```bash
curl -X POST http://localhost:8000/api/cases/FM-10282/feedback -H 'Content-Type: application/json' \
  -d '{"action": "CONFIRM_FRAUD", "analyst": "analyst-1", "notes": "mule network confirmed"}'
# → {"case": {..., "status": "CONFIRMED_FRAUD"}, "feedback": {...},
#    "learning": {"effect": "watchlist", "entities": 4, "note": "Devices/IPs from this case now raise graph risk for future events."}}
```

Update weights (admin token required if `FRAUDMESH_ADMIN_TOKEN` is set):

```bash
curl -X PUT 'http://localhost:8000/api/config?rescore=true' -H 'Content-Type: application/json' \
  -H "X-Admin-Token: $FRAUDMESH_ADMIN_TOKEN" -d '{
  "weights": {"transaction": 0.25, "takeover": 0.20, "kyc": 0.20, "cloud": 0.10, "graph": 0.20, "temporal": 0.05},
  "temporal_window_minutes": 15, "suspicious_event_threshold": 0.35, "min_correlated_signals": 2, "case_creation_min_risk": 15
}'
```

KYC upload:

```bash
curl -X POST http://localhost:8000/api/kyc/analyze -F file=@selfie.png -F customer_id=CUSTOMER_10291 -F submit_event=true
```

## 17. Repository structure

```
fraudmesh/
├── backend/            FastAPI app (see §8), requirements.txt, Dockerfile
├── frontend/           React + TS dashboard (see §9), Dockerfile, nginx.conf
├── data/               SQLite database + generated token secret (git-ignored)
├── models/             Trained model artefacts + SHA-256 manifest (git-ignored)
├── scripts/            seed_demo_data.py · simulate_attack.py
├── tests/              pytest suite
├── docker-compose.yml
├── .env.example
├── pytest.ini
├── README.md
└── LICENSE
```

## 18. Installation

Prerequisites: Python 3.11+, Node.js 18+ (20/22 recommended), or Docker with Compose v2.

```bash
git clone <this repo> fraudmesh && cd fraudmesh
python -m venv .venv && source .venv/bin/activate      # optional
pip install -r backend/requirements-dev.txt             # runtime + pytest/httpx
cd frontend && npm install && cd ..
```

## 19. Environment setup

```bash
cp .env.example .env      # then edit
```

| Variable | Default | Purpose |
|---|---|---|
| `FRAUDMESH_TOKEN_SECRET` | generated into `data/.token_secret` | HMAC key for tokenization |
| `FRAUDMESH_ADMIN_TOKEN` | empty (open demo mode, warning logged) | Required `X-Admin-Token` for config/policy/retrain/reset |
| `DATABASE_URL` | `sqlite:///data/fraudmesh.db` | Any SQLAlchemy URL (PostgreSQL-compatible schema) |
| `FRAUDMESH_DATA_DIR` / `FRAUDMESH_MODELS_DIR` | `data/` / `models/` | Storage locations |
| `FRAUDMESH_AUTO_SEED` | `true` | Generate synthetic data when the DB is empty |
| `FRAUDMESH_CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000` | Allowed browser origins |
| `FRAUDMESH_RATE_LIMIT_PER_MINUTE` / `FRAUDMESH_KYC_RATE_LIMIT_PER_MINUTE` | 600 / 20 | Per-client limits |
| `FRAUDMESH_KYC_MAX_BYTES` / `FRAUDMESH_KYC_RETAIN_MEDIA` | 5 MiB / `false` | KYC upload policy |
| `FRAUDMESH_SHOW_SYNTHETIC_LABELS` | `true` | Show synthetic demo ids as labels |
| `FRAUDMESH_LOG_LEVEL` | `INFO` | Logging level |

The backend reads real environment variables. `uvicorn` does not load `.env` by itself: export the variables or
use `docker compose`, which does load `.env`.

## 20. Database setup

Nothing to do for SQLite: tables are created on start-up (`init_db()`), WAL mode and foreign keys are enabled.

PostgreSQL (optional):

```sql
CREATE DATABASE fraudmesh;
CREATE USER fraudmesh_app WITH PASSWORD '<strong password>';
GRANT CONNECT ON DATABASE fraudmesh TO fraudmesh_app;
-- after the first start creates the tables, keep the app role to DML only:
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO fraudmesh_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fraudmesh_app;
```

```bash
pip install psycopg2-binary
export DATABASE_URL=postgresql+psycopg2://fraudmesh_app:<password>@localhost:5432/fraudmesh
```

## 21. Demo data generation

```bash
python scripts/seed_demo_data.py            # seeds only if the DB is empty (the backend also auto-seeds)
python scripts/seed_demo_data.py --reset    # drop & recreate all tables, then seed (stop the backend first)
```

Generated (deterministic, seed 2024), **all synthetic**:

| Entity | Count |
|---|---|
| Customers | 100 (+ identities created by the synthetic-identity scenario) |
| Accounts | 150 across SBI / HDFC Bank / ICICI Bank (`*-SYN-*`, plus `SBI-DEMO-1042`, `HDFC-DEMO-7781`, `ICICI-DEMO-5520`) |
| Devices | 100 customer devices + scenario/attacker devices |
| IP tokens | 150 (home broadband + mobile) |
| Transactions / logins / KYC / cloud events | ~1 000 / ~500 / ~100 / 200 over 30 days (+ scenario events) |

Historical scenarios: `unusual_transaction`, `account_takeover`, `synthetic_identity`, `kyc_manipulation`,
`coordinated_cross_channel_fraud`, `normal`. Every event goes through the real pipeline, so the resulting ~9 cases
and their explanations are genuine outputs. Some cases receive synthetic analyst decisions (confirmed fraud, false
positive, hold, investigate) so feedback metrics are populated. Seeding takes ~15 s on a laptop-class CPU.

## 22. Attack simulation

**From the dashboard:** choose a scenario (default: *coordinated cross channel fraud*), set seconds between
events, keep *clear previous live data* ticked, press **Start simulated attack**.

**From the terminal:**

```bash
python scripts/simulate_attack.py                     # 3 s between events
python scripts/simulate_attack.py --delay 1           # faster
python scripts/simulate_attack.py --no-reset          # keep earlier live demo data
python scripts/simulate_attack.py --api http://localhost:8000 --admin-token "$FRAUDMESH_ADMIN_TOKEN"
```

The script (stdlib only) waits for readiness, resets previous live data, then posts each event to
`POST /api/events`, so the dashboard updates over WebSockets. Real output from this repository:

```
[02:25] T+00:00  NORMAL LOGIN
       Bank: SBI   Account: SBI-DEMO-1042
       Device: DEVICE-A1C3   IP: 100.72.x.x #f10e
       Takeover Risk: 0.14
[02:26] T+01:00  NEW DEVICE LOGIN
       Device: DEVICE-7F21 …  Takeover Risk: 0.52
[02:27] T+02:00  NEW IP / NETWORK
       Takeover Risk: 0.85
       → CASE FM-10280 CREATED: risk 18/100 [LOW] ALLOW
[02:28] T+03:00  MFA RESET              → risk 21/100 [LOW] ALLOW
[02:30] T+05:00  KYC VERIFICATION       KYC Manipulation Score: 0.91 → risk 41/100 [MEDIUM] STEP-UP AUTHENTICATION
[02:32] T+07:00  HIGH-VALUE TRANSACTION Amount: ₹185,000  Transaction Risk: 0.99 → risk 72/100 [HIGH] HOLD + INVESTIGATE
[02:33] T+08:00  DEVICE REUSE           HDFC-DEMO-7781  Graph Risk: 0.78 → risk 84/100 [CRITICAL]
[02:34] T+09:00  CROSS-BANK LINK        ICICI-DEMO-5520 Graph Risk: 0.96 → risk 87/100 [CRITICAL]
[02:35] T+10:00  CLOUD SECURITY ANOMALY Cloud Risk: 0.95 → risk 97/100 [CRITICAL] BLOCK / HOLD + INVESTIGATE

🚨 FRAUDMESH CASE #FM-10280
   Risk: 97 / 100   Severity: CRITICAL   Status: HOLD
   Action: BLOCK / HOLD + INVESTIGATE (POL-CRITICAL)
   Events correlated: 9   Banks: HDFC Bank, ICICI Bank, SBI
```

Event timestamps follow a simulated clock (real T+ spacing ending "now") while events stream every few seconds.

## 23. Frontend startup

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173 — proxies /api and /ws to http://localhost:8000
# VITE_BACKEND_URL=http://host:8000 npm run dev   to point at another backend
npm run build        # type-check + production build into dist/
```

The UI waits (StartupGate) until `/api/health` reports ready.

## 24. Backend startup

```bash
cd backend
uvicorn app.main:app --reload          # http://localhost:8000 · docs at /docs
```

On start-up the backend trains the detectors (a few seconds), auto-seeds synthetic data if the database is empty
(~15 s, first run only), rebuilds in-memory state (profiles, graph, open cases) from the database, and reports
`ready: true` on `/api/health`. Until then API routes return `503` with a clear message.

## 25. Docker deployment

```bash
cp .env.example .env            # optional: set FRAUDMESH_ADMIN_TOKEN / FRAUDMESH_TOKEN_SECRET
docker compose up --build
```

| Service | URL |
|---|---|
| Dashboard (nginx serving the build, proxying `/api` and `/ws`) | http://localhost:3000 |
| Backend API / OpenAPI docs | http://localhost:8000 · http://localhost:8000/docs |

* The backend runs as an unprivileged user; data and models live in named volumes (`fraudmesh-data`,
  `fraudmesh-models`), so restarts keep the database and token secret.
* Run the simulation against the container: `python scripts/simulate_attack.py` (host), or
  `docker compose exec backend python -c "…"`.
* Full reset: `docker compose down -v`.

## 26. Testing

```bash
pip install -r backend/requirements-dev.txt
pytest                      # from the repository root — 45 tests, ~10 s
```

| Area | File |
|---|---|
| Event normalization, privacy tokenization, log redaction, validation | `tests/test_privacy_and_normalization.py` |
| Transaction (incl. SHAP consistency), behaviour, KYC, cloud detectors | `tests/test_detectors.py` |
| Risk fusion, policy engine, graph construction / cross-bank reuse | `tests/test_fusion_policy_graph.py` |
| **Cross-channel correlation** (the 7-signal single-case test), case creation, window, feedback learning | `tests/test_correlation_and_cases.py` |
| API endpoints (events, batch, cases, feedback, metrics, models, graph, config/policies auth, KYC upload validation, demo) | `tests/test_api.py` |

The most important test, `test_seven_weak_signals_create_one_correlated_case`, sends NEW_DEVICE + NEW_IP +
MFA_RESET + KYC_ANOMALY + HIGH_VALUE_TRANSACTION + DEVICE_REUSE (+ cross-bank) + CLOUD_ANOMALY and asserts exactly
one case contains every event, is CRITICAL with a BLOCK/HOLD policy, spans all three banks, has every channel active,
explains the key signals, and that its risk rose monotonically.

## 27. Evaluation metrics

No performance number in this project is invented; everything below is **measured by the running system** and
available at `/api/models` and `/api/metrics`. Values are from one run on the development machine and on
**synthetic data only** — they say nothing about real bank customers.

| Category | Metric | Where | Value observed |
|---|---|---|---|
| Detection | Precision / Recall / F1 / PR-AUC / FPR (transaction model, 25 % synthetic hold-out, threshold 0.5) | `/api/models → transaction_evaluation` | 0.975 / 0.843 / 0.904 / 0.896 / 0.35 % |
| Operations | Event processing latency (end-to-end pipeline) | `/api/metrics → pipeline_latency_ms`, `stages` in every event response | ~15 ms per event |
| Operations | Case construction latency | `/api/metrics → case_construction_latency_ms` | ~4 ms |
| Operations | Events per minute, alerts merged per case | `/api/metrics` | 9 events → 1 case in the flagship demo |
| Operations | Average investigation time (case creation → decisive analyst action) | `/api/metrics → avg_investigation_minutes` | from synthetic seed decisions |
| Explainability | Explanation coverage / top-signal availability | `/api/models → explainability` | 100 % / 100 % |
| Explainability | Analyst feedback counts and analyst precision | `/api/models → feedback` | computed |
| Privacy | PII tokenization coverage / raw KYC media retained / audit-log coverage | `/api/models → privacy, audit` | 100 % / 0 / 100 % |
| System | Peak RSS, CPU time, uptime; per-detector avg & p95 latency | `/api/models → system, detectors` | ~350 MB RSS |
| System | API latency / WebSocket latency | per-stage timings in `event.processed`; `server_ts` on every WS message | measured per event |

Reproduce: `pytest`, then start the backend and open **Model Monitoring**.

## 28. Security considerations

* **Input validation:** Pydantic schemas with length limits, enum event types, whitelisted synthetic banks,
  positive transaction amounts, bounded metadata (≤ 64 keys, ≤ 16 KB), event-id pattern, batch cap; validation
  errors never echo input.
* **Rate limiting:** per-client sliding window (general API and a stricter KYC bucket) → HTTP 429.
* **Authorisation:** configuration, policy, retraining and reset endpoints require `X-Admin-Token` (constant-time
  compare) when `FRAUDMESH_ADMIN_TOKEN` is set. Analyst actions are open in this prototype (no user accounts).
* **Secrets:** no credentials in code; `.env` and `data/.token_secret` are git-ignored; `.env.example` has no values.
* **Safe uploads:** size limit, declared MIME whitelist, magic-byte check, declared/actual type match, decode check,
  dimension cap, in-memory processing, SHA-256 fingerprint only, retention off by default.
* **PII:** tokenization, sanitised metadata, masked labels, redacted logs, sanitised audit details.
* **Audit:** event received, case created, score updated, policy triggered, analyst action, feedback submitted,
  config/policy updated, model retrained, demo reset.
* **Model loading:** XGBoost JSON (no pickle) with SHA-256 manifest; Isolation Forests retrained deterministically.
* **Least privilege:** container runs as a non-root user; PostgreSQL guidance grants DML only to the app role.
* **HTTP hardening:** restrictive CORS (configurable), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

## 29. Limitations

**This is a hackathon prototype.** It does **not** claim:

* production-grade fraud detection;
* guaranteed deepfake detection — the KYC/deepfake detector is a heuristic prototype unless trained and validated
  on an appropriate benchmark;
* regulatory certification or complete AML compliance;
* zero false positives;
* replacement of human investigators;
* direct access to real Indian banking systems;
* detection accuracy on real bank customers.

Further technical limitations:

* Models are trained on synthetic distributions; evaluation numbers reflect that synthetic data only.
* Fusion weights and rule points are demonstration values, not calibrated probabilities.
* Single-process design: in-memory state and rate limiting are per process (no horizontal scaling yet).
* Correlation can over-merge through genuinely shared infrastructure (e.g. a busy NAT IP) within the window.
* No authentication/authorisation for analysts beyond the admin token; no multi-tenant isolation.
* Timestamps are trusted as provided by the event source.

The Indian-bank scenarios are synthetic simulations only.

## 30. Future improvements

Kafka event streaming · Neo4j graph database · feature store · model registry · model drift detection ·
graph neural networks · stronger, benchmark-validated deepfake detection · federated learning ·
privacy-preserving collaborative intelligence across institutions · differential privacy · continual learning ·
adversarial testing · cloud-native deployment · SIEM/SOC integration · analyst SSO and RBAC · Redis-backed
real-time state for multi-instance deployments.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard stuck on "Waiting for the backend" | Start the backend on :8000 (`cd backend && uvicorn app.main:app --reload`). With a different host/port run `VITE_BACKEND_URL=http://host:port npm run dev`. |
| "Backend initialising…" for a long time | First start trains models and seeds ~1 900 synthetic events (~15–30 s). Check the backend log. |
| `503 FraudMesh is initialising` from the API | Same as above — wait for `/api/health` → `ready: true`. |
| LIVE indicator shows OFFLINE | WebSocket `/ws/events` is not reachable: check the Vite proxy / nginx, corporate proxies, or browser extensions. The UI reconnects automatically. |
| Re-running the attack attaches to the previous case | Keep *clear previous live data* ticked (default), or run `simulate_attack.py` without `--no-reset`. |
| `401 valid X-Admin-Token header required` | `FRAUDMESH_ADMIN_TOKEN` is set: enter it in Policy Center → Authorisation, or pass `--admin-token` / the header. |
| `database is locked` when seeding | Stop the backend before `seed_demo_data.py --reset` (SQLite has a single writer), or use `POST /api/demo/reset`. |
| Start fresh | Stop the backend and delete `data/fraudmesh.db*` (or `docker compose down -v`). Deleting `data/.token_secret` changes every token, so remove the DB with it. |
| `ImportError: libgomp.so.1` (XGBoost) on Linux | `apt-get install libgomp1` (already in the Docker image). |
| OpenCV import errors | Use `opencv-python-headless<5` (4.x ships the Haar cascades FraudMesh uses). |
| Port already in use | Change ports in `docker-compose.yml` or run `uvicorn … --port 8001` and `VITE_BACKEND_URL=http://localhost:8001 npm run dev`. |
| `429 Rate limit exceeded` | Raise `FRAUDMESH_RATE_LIMIT_PER_MINUTE` for load testing. |

---

*FraudMesh — SIMULATED DATA — NO REAL BANK INCIDENT.*
