# SPEC-024 — Deception (Canaries / Honeypots + Deception Analytics)

- **Status**: BACKFILL
- **Owner family**: Deception / Active Defense
- **Routers** (attributed via runtime `endpoint.__module__` — both clean single-routers, no collision): `suite-api/apps/api/deception_router.py` (prefix `/api/v1/deception`), `suite-api/apps/api/deception_analytics_router.py` (prefix `/api/v1/deception-analytics`)
- **Engines**: deception engine (canary/honeypot lifecycle + trip detection), deception-analytics engine (decoy assets + interactions + campaigns)
- **Stores**: deception SQLite (canaries / honeypots / alerts), deception-analytics SQLite (assets / interactions / campaigns), per-org scoped
- **Depends on**: SPEC-001 (TrustGraph — a tripped canary/interaction is a high-fidelity signal to correlate); env: none required
- **Last updated**: 2026-06-03

## 1. Intent (the why)
Deception gives a SCIF SOC near-zero-false-positive detection: a canary token or honeypot has
no legitimate reason to be touched, so any interaction is a high-confidence intrusion signal.
This spec governs canary/honeypot lifecycle + trip alerts (`/deception`) and the decoy-asset /
interaction / campaign analytics (`/deception-analytics`). Honest-empty: a fresh org has zero
canaries / assets / alerts, never fabricated decoys or invented trips.

## 2. Scope — endpoints (live-verified)
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET·POST | /api/v1/deception/canaries | list / deploy canary tokens | api_key | yes |
| DELETE | /api/v1/deception/canaries/{id} | remove a canary | api_key | yes |
| POST | /api/v1/deception/check | check/trip a canary (interaction) | api_key | yes |
| GET | /api/v1/deception/alerts | canary trip alerts | api_key | yes |
| GET·POST | /api/v1/deception/honeypots | list / deploy honeypots | api_key | yes |
| GET | /api/v1/deception/stats | counts (canaries/active/alerts) | api_key | yes |
| GET·POST | /api/v1/deception-analytics/assets | list / create decoy assets | api_key | yes |
| GET | /api/v1/deception-analytics/assets/{id} | fetch one decoy asset | api_key | yes |
| PUT | /api/v1/deception-analytics/assets/{id}/deactivate | deactivate a decoy | api_key | yes |
| GET·POST | /api/v1/deception-analytics/interactions | list / record interactions | api_key | yes |
| GET·POST | /api/v1/deception-analytics/campaigns | list / create campaigns | api_key | yes |
| PUT | /api/v1/deception-analytics/campaigns/{id}/stats | update campaign stats | api_key | yes |
| GET | /api/v1/deception-analytics/stats | counts (assets/interactions) | api_key | yes |

Out of scope: real network honeypot deployment infra (the API tracks decoys; standing up the
listeners is operator infra); UI (must follow NO-MOCKS and consume these endpoints).

## 3. Data contracts (honest-empty first-class)
```
GET /api/v1/deception/canaries?org_id=O    → 200 [...]   (empty org → [])
GET /api/v1/deception/alerts?org_id=O       → 200 [...]   (empty → [])
GET /api/v1/deception/stats?org_id=O        → 200 {"org_id","total_canaries","active_canaries","total_alerts",...}  (empty → zeros)
GET /api/v1/deception-analytics/assets?org_id=O      → 200 [...]
GET /api/v1/deception-analytics/stats?org_id=O       → 200 {"org_id","total_assets","active_assets","total_interactions",...}  (empty → zeros)
(missing X-API-Key) → 401
```

## 4. Functional requirements
- **REQ-024-01**: Empty org → honest empty (`[]` / zeroed stats), never fabricated canaries,
  honeypots, decoy assets, or trip alerts.
- **REQ-024-02**: All reads/writes are org-scoped; one org never sees another's decoys/alerts.
- **REQ-024-03**: A canary trip / decoy interaction is recorded as a real event (and is a
  candidate high-fidelity signal for TrustGraph correlation, SPEC-001).
- **REQ-024-04**: `stats` are computed from real records, not invented.

## 5. Non-functional requirements
- Latency: GET reads < 2s.
- Tenancy: org_id via get_org_id; cross-org → no foreign records.
- Auth: every endpoint requires X-API-Key; missing → 401.
- Failure mode: empty/unconfigured → honest empty, never 500/hang/fabricated.

## 6. Acceptance criteria (executable, verified 2026-06-03)
- **AC-024-01**: `GET /api/v1/deception/canaries?org_id=X` → 200 list; empty org → `[]`. (verified)
- **AC-024-02**: `GET /api/v1/deception/alerts?org_id=X` → 200 list. (verified)
- **AC-024-03**: `GET /api/v1/deception/stats?org_id=X` → 200 with `total_canaries`,
  `active_canaries`, `total_alerts`; empty → zeros. (verified)
- **AC-024-04**: `GET /api/v1/deception/honeypots?org_id=X` → 200 list. (verified)
- **AC-024-05**: `GET /api/v1/deception-analytics/assets?org_id=X` → 200 list; empty → `[]`. (verified)
- **AC-024-06**: `GET /api/v1/deception-analytics/stats?org_id=X` → 200 with `total_assets`,
  `active_assets`, `total_interactions`; empty → zeros. (verified)
- **AC-024-07**: `GET /api/v1/deception/stats` without `X-API-Key` → 401. (verified)
- **AC-024-08**: pytest deception suites (`tests/test_deception*.py`) pass.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Documented existing deception + deception-analytics surface. Routers attributed via runtime `endpoint.__module__` from the start (lesson from SPEC-023) — both confirmed clean single-routers in `suite-api/apps/api/`, no shadow collision. All 8 GET ACs grounded on live TestClient probes (200 honest-empty; no-key 401). |

## 8. Implementation notes
Already implemented; this spec backfills governance over the deception surface for the Augment
Code intent-IDE map (specs/INDEX.md). Unlike `/api/v1/playbooks` (SPEC-023, a 4-router collision
zone), `/api/v1/deception` and `/api/v1/deception-analytics` are each served by exactly one
router (verified via `endpoint.__module__`). No code change introduced by this spec.
