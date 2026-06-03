# SPEC-023 — SOAR / Playbooks (Incident-Response Automation)

- **Status**: BACKFILL
- **Owner family**: SOAR / Response
- **Routers**: `suite-api/apps/api/soar_router.py` (prefix `/api/v1/soar`), `suite-api/apps/api/playbook_router.py` (prefix `/api/v1/playbooks`)
- **Engines**: SOAR playbook engine (playbook CRUD + execution + MTTR/stats), playbook execution store
- **Stores**: SOAR SQLite (playbooks / executions), per-org scoped
- **Depends on**: SPEC-019 (evidence chain — execution artifacts), SPEC-001 (TrustGraph — emits `playbook.executed`); env: none required
- **Last updated**: 2026-06-03

## 1. Intent (the why)
SOAR turns a finding/incident into an automated, auditable response: define playbooks, trigger
them (manually or on event), execute steps, and report MTTR — the "close-the-loop" capability a
SCIF SOC needs to act on the platform's verdicts instead of just reading them. Like the rest of
the platform it is honest-empty: a fresh org sees zero playbooks / zero executions / 0.0 MTTR,
never fabricated activity.

## 2. Scope — endpoints (live-verified)
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/soar/ | router summary `{router, org_id, items, count}` | api_key | yes |
| GET·POST | /api/v1/soar/playbooks | list / create playbooks | api_key | yes |
| GET | /api/v1/soar/playbooks/{id} | fetch one playbook | api_key | yes |
| POST | /api/v1/soar/playbooks/{id}/execute | execute a playbook | api_key | yes |
| POST | /api/v1/soar/trigger | event-trigger a playbook | api_key | yes |
| GET | /api/v1/soar/executions | execution history | api_key | yes |
| GET | /api/v1/soar/stats | counts (playbooks/enabled/executions) | api_key | yes |
| GET | /api/v1/soar/mttr | mean-time-to-respond (seconds/minutes) | api_key | yes |
| GET | /api/v1/playbooks/ | playbook list `{items[]}` | api_key | yes |
| GET | /api/v1/playbooks/{id} | fetch one playbook | api_key | yes |
| POST | /api/v1/playbooks/{id}/execute | execute a playbook | api_key | yes |
| GET | /api/v1/playbooks/executions[/{id}] | execution history / detail | api_key | yes |

Out of scope: connector-specific SOAR backends (Splunk SOAR / XSOAR have their own routers +
specs-to-come); the playbook marketplace (`/playbook-marketplace/*`, separate surface); the UI
(must follow NO-MOCKS and consume these endpoints).

## 3. Data contracts (honest-empty first-class)
```
GET /api/v1/soar/?org_id=O           → 200 {"router":"soar","org_id":"O","items":[...],"count":N}
GET /api/v1/soar/playbooks?org_id=O  → 200 [...]                          (empty org → [])
GET /api/v1/soar/stats?org_id=O      → 200 {"org_id","total_playbooks","enabled_playbooks","total_executions",...}  (empty → zeros)
GET /api/v1/soar/mttr?org_id=O       → 200 {"org_id","mttr_seconds","mttr_minutes"}                                 (no data → 0.0)
GET /api/v1/playbooks/?org_id=O      → 200 {"items":[{"id","name",...}]}
GET /api/v1/playbooks/executions?org_id=O → 200 [...]                     (empty → [])
(missing X-API-Key) → 401
```

## 4. Functional requirements
- **REQ-023-01**: Empty org → honest empty (`[]` / zeroed stats / `mttr 0.0`), never fabricated
  playbooks or executions.
- **REQ-023-02**: Playbooks + executions are org-scoped; one org never sees another's.
- **REQ-023-03**: `stats`/`mttr` are computed from real execution records, not invented.
- **REQ-023-04**: A successful playbook execution emits a `playbook.executed` event to the
  TrustGraph EventBus (close-the-loop correlation).

## 5. Non-functional requirements
- Latency: GET reads < 2s; execution is POST-triggered (not synchronous heavy work on a GET).
- Tenancy: org_id via get_org_id; cross-org → no foreign records.
- Auth: every endpoint requires X-API-Key; missing → 401.
- Failure mode: empty/unconfigured → honest empty, never 500/hang/fabricated.

## 6. Acceptance criteria (executable, verified 2026-06-03)
- **AC-023-01**: `GET /api/v1/soar/?org_id=X` → 200 `{router:"soar", items, count}`. (verified)
- **AC-023-02**: `GET /api/v1/soar/playbooks?org_id=X` → 200 list; empty org → `[]`. (verified)
- **AC-023-03**: `GET /api/v1/soar/stats?org_id=X` → 200 with `total_playbooks`,
  `enabled_playbooks`, `total_executions`; empty org → zeros. (verified)
- **AC-023-04**: `GET /api/v1/soar/mttr?org_id=X` → 200 `{mttr_seconds, mttr_minutes}`; no data → 0.0. (verified)
- **AC-023-05**: `GET /api/v1/playbooks/?org_id=X` → 200 `{items:[...]}`. (verified)
- **AC-023-06**: `GET /api/v1/playbooks/executions?org_id=X` → 200 list. (verified)
- **AC-023-07**: `GET /api/v1/soar/playbooks` without `X-API-Key` → 401. (verified)
- **AC-023-08**: pytest `tests/test_phase9_playbooks.py` (+ any SOAR suites) pass.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Documented existing SOAR + playbook surface; ACs grounded on live TestClient probes. Found `/api/v1/playbooks/builtin` 404s — shadowed by `GET /{playbook_id}` route ordering (id="builtin"); recorded as a minor route-ordering observation, NOT claimed as a working endpoint. |

## 8. Implementation notes
Already implemented; this spec backfills governance over the SOAR/playbook surface for the
Augment Code intent-IDE map (specs/INDEX.md). Observed minor route-shadow: in `playbook_router`
the parametric `GET /{playbook_id}` precedes `GET /builtin`, so `/playbooks/builtin` resolves to
the param route and 404s — a low-severity ordering fix (move `/builtin` above `/{playbook_id}`),
left as a follow-up; not claimed in ACs. No code change introduced by this spec.
