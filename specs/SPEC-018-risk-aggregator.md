# SPEC-018 — Risk Aggregator (composite org risk scoring)

- **Status**: BACKFILL (documents shipped code; reconciled to source 2026-06-02)
- **Owner family**: Risk / CTEM
- **Routers**: `risk_aggregator_router.py` (prefix `/api/v1/risk-aggregator`)
- **Engines**: `core/risk_aggregator_engine.py` (`RiskAggregatorEngine`)
- **Stores**: SQLite `risk_scores` + `risk_thresholds` tables (org-scoped)
- **Depends on**: SPEC-007 (tenancy / `get_org_id`), SPEC-001/005b (brain → sync source). Auth: `api_key_auth`.
- **Last updated**: 2026-06-02

## 1. Intent (the why)
Findings, exposures, CVEs and posture signals are produced by many engines, each with its own score.
The Risk Aggregator is the single place that **rolls per-entity risk into one composite organisational
risk score (0-100) with trend**, exposes a heatmap + top-risks view, and lets teams set thresholds —
the executive/CISO risk lens a SCIF customer needs for prioritisation and ATO risk acceptance.

**Code-truth (2026-06-02):** real engine, no stubs (0 stub/mock/NotImplemented markers). `calculate_org_risk_score`
performs real SQL aggregation (latest score per entity via a `MAX(recorded_at)` self-join, org-scoped).
All endpoints are `api_key_auth` + org-scoped via `Depends(get_org_id)`.

## 2. Scope — endpoints (as implemented)
| Method | Path | Purpose | Auth | Tenant |
|--------|------|---------|------|--------|
| POST | /api/v1/risk-aggregator/scores | record a per-entity risk score (from any source engine) | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/scores | list recorded scores (filterable) | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/scores/entity/{entity_id} | latest risk for one entity | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/heatmap | risk heatmap (by entity_type/severity bucket) | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/top-risks | top-N highest-risk entities | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/org-score | composite 0-100 org risk score + trend | api_key_auth | org |
| POST | /api/v1/risk-aggregator/thresholds | create a risk threshold | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/thresholds | list thresholds | api_key_auth | org |
| GET  | /api/v1/risk-aggregator/stats | aggregator stats | api_key_auth | org |
| POST | /api/v1/risk-aggregator/sync | pull entity risk from the correlation brain (Store B) | api_key_auth | org |

Out of scope: producing the per-engine scores (each engine owns its own); UI; alerting (thresholds only record).

## 3. Data contracts
```
POST /scores  body {entity_id, entity_type, risk_score (0-100), source_engine?, ...}
              → 201 {id, ...}  | 400 {detail} on invalid input
GET  /org-score → 200 {"org_risk_score": 0-100, "trend": "up|down|flat", "entity_count": N, ...}
GET  /top-risks?limit=N → 200 [{entity_id, entity_type, risk_score, ...}]
GET  /heatmap → 200 {buckets/grid of counts by entity_type × severity}
```
Unconfigured/empty org → real empty aggregates (e.g. org_score 0, []), never fabricated numbers.

## 4. Functional requirements (reconciled to code)
- **REQ-018-01**: `/scores` POST validates `risk_score` ∈ [0,100], `entity_type` ∈ allowed set, `severity` ∈ allowed set (or derived from score); out-of-range/invalid → `ValueError` → HTTP 400 (REJECT, not clamp); persists org-scoped.
- **REQ-018-02**: `/org-score` computes a composite from the LATEST score per entity (no double-count of stale rows), org-scoped.
- **REQ-018-03**: `/top-risks` and `/heatmap` derive only from this org's recorded scores (no cross-tenant bleed).
- **REQ-018-04**: `/sync` ingests entity risk from the correlation brain (Store B) for the org — keeps the aggregator current with pipeline output.
- **REQ-018-05**: thresholds are org-scoped CRUD; all reads/writes filter by `org_id` (SPEC-007).
- **REQ-018-06**: every endpoint requires `api_key_auth` and resolves org via the canonical `get_org_id`.

## 5. Non-functional requirements
- Tenancy: every SQL query predicated on `org_id`; cross-org → empty/404, never another org's rows.
- Honesty: empty org → genuine zero/empty aggregates; no placeholder/sample data.
- Latency: GET aggregates < 2s on a normal org corpus (single indexed SQLite query each).

## 6. Acceptance criteria (executable)
- **AC-018-01**: POST `/scores` with `risk_score=150` → HTTP 400 (rejected, not clamped); valid 0-100 → 201.
- **AC-018-02**: record 3 scores for one entity at different times → `/scores/entity/{id}` returns the latest only.
- **AC-018-03**: `/org-score` for a fresh org → `{org_risk_score: 0, entity_count: 0, trend: "stable"}` (honest empty), not fabricated.
- **AC-018-04**: org-A cannot see org-B's scores via `/scores`, `/top-risks`, `/org-score` (org-scoped).
- **AC-018-05**: `create_app()` boots with the router mounted; 13-file Beast smoke stays 756.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-02 | Author (backfill) | Documented as-built; engine verified real (SQL aggregation, 0 stubs), all endpoints org-scoped. |
| — | SCIF-Accreditor (pending) | Confirm `/org-score` + `/sync` never aggregate cross-tenant; empty org → 0 not fabricated. |
| — | Red-Team (pending) | Attack: can `/scores` POST be used to poison another org's composite via spoofed org? (org from auth, not body — verify.) |

## 8. Implementation notes
As-built backfill — no code change. Spec governs future changes to `risk_aggregator_router` / `RiskAggregatorEngine`.
Pending: run the SCIF-Accreditor + Red-Team debate and add executable AC tests (tests/test_spec018_risk_aggregator.py).
