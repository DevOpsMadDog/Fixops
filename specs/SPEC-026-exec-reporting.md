# SPEC-026 — Executive Reporting + Evidence Export

- **Status**: BACKFILL
- **Owner family**: Reporting / Evidence
- **Routers** (attributed via runtime `endpoint.__module__` — both clean single-routers): `suite-api/apps/api/executive_reporting_router.py` (prefix `/api/v1/exec-reporting`), `suite-evidence-risk/api/evidence_router.py` (prefix `/api/v1/evidence`, export endpoints)
- **Engines**: executive-reporting engine (reports + KPIs + board presentations + TrustGraph context), evidence-export pipeline (`core/crypto`, compliance engine — signed evidence bundle)
- **Stores**: exec-reporting SQLite (reports / kpis / presentations), evidence store, per-org scoped
- **Depends on**: SPEC-014 (auth/tenancy — api_key + tier gating), SPEC-018 (risk aggregator — summary risk inputs), SPEC-019 (evidence chain-of-custody — export integrity), SPEC-006b (crypto — signed bundle)
- **Last updated**: 2026-06-03

## 1. Intent (the why)
Executive reporting rolls the platform's signal up to a CISO/board view (reports, KPIs with
on-track/at-risk/off-track, board presentations, an exec summary), and evidence-export produces
a cryptographically-signed evidence bundle for an auditor/ATO package. Both are honest-empty (a
fresh org has zero reports/KPIs) and — post-2026-06-03 — both require authentication.

## 2. Scope — endpoints (live-verified)
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/exec-reporting/ | router index `{router, org_id, items, count}` | api_key | yes |
| GET·POST | /api/v1/exec-reporting/reports | list / create reports | api_key (POST: tier≥pro) | yes |
| GET | /api/v1/exec-reporting/reports/{id} | fetch a report | api_key | yes |
| POST | /api/v1/exec-reporting/reports/{id}/metrics·/publish | add metric / publish | api_key | yes |
| GET | /api/v1/exec-reporting/reports/{id}/export/pdf | export report PDF | api_key | yes |
| GET·POST | /api/v1/exec-reporting/kpis | list / set KPIs | api_key | yes |
| GET | /api/v1/exec-reporting/kpis/{name} | fetch a KPI | api_key | yes |
| GET·POST | /api/v1/exec-reporting/board-presentations | list / create (POST: tier≥enterprise) | api_key | yes |
| GET | /api/v1/exec-reporting/summary | exec summary {recent_reports, kpi_summary, top_risks} | api_key | yes |
| GET | /api/v1/exec-reporting/context/{entity_id} | TrustGraph context for an entity | api_key | yes |
| POST | /api/v1/evidence/export | produce a signed evidence bundle | api_key | yes |
| POST | /api/v1/evidence/export/verify | verify a bundle's signature/integrity | api_key | yes |
| GET | /api/v1/evidence/export/status | export subsystem status {operational, crypto_available, compliance_engine_available} | api_key | yes |

Out of scope: report scheduling/delivery infra; the broader evidence/cases surface (SPEC-019);
UI (must follow NO-MOCKS and consume these endpoints).

## 3. Data contracts (honest-empty first-class)
```
GET /api/v1/exec-reporting/?org_id=O        → 200 {"router":"exec-reporting","org_id":"O","items":[...],"count":N}
GET /api/v1/exec-reporting/reports?org_id=O  → 200 [...]   (empty org → [])
GET /api/v1/exec-reporting/kpis?org_id=O     → 200 [...]   (empty → [])
GET /api/v1/exec-reporting/summary?org_id=O  → 200 {"recent_reports":[...],"kpi_summary":{"on_track":N,"at_risk":N,"off_track":N},"top_risks":[...]}
GET /api/v1/evidence/export/status?org_id=O  → 200 {"status":"operational","crypto_available":true,"compliance_engine_available":true,...}
(missing X-API-Key) → 401
```

## 4. Functional requirements
- **REQ-026-01**: Every endpoint requires authentication (api_key). [FIXED 2026-06-03 — the GET
  endpoints previously returned 200 unauthenticated.]
- **REQ-026-02**: Empty org → honest empty (`[]` / zeroed kpi_summary), never fabricated reports/KPIs.
- **REQ-026-03**: All reads/writes are org-scoped; one org never sees another's reports/KPIs.
- **REQ-026-04**: Report/board-presentation creation is tier-gated (`requires_tier` — pro/enterprise).
- **REQ-026-05**: Evidence export produces a cryptographically-signed bundle; `export/verify`
  re-checks integrity; `export/status` reports real subsystem availability (crypto, compliance).

## 5. Non-functional requirements
- Latency: GET reads < 2s; PDF/bundle generation is the heavier path.
- Tenancy: org_id via get_org_id; cross-org → no foreign records.
- Auth: every endpoint requires X-API-Key; missing → 401. (router-level dependency)
- Failure mode: empty/unconfigured → honest empty; export with crypto unavailable → honest
  `crypto_available:false`, never a fake "signed" bundle.

## 6. Acceptance criteria (executable, verified 2026-06-03)
- **AC-026-01**: `GET /api/v1/exec-reporting/summary?org_id=X` → 200 with `recent_reports`,
  `kpi_summary{on_track,at_risk,off_track}`, `top_risks`. (verified)
- **AC-026-02**: `GET /api/v1/exec-reporting/reports?org_id=X` → 200 list; empty → `[]`. (verified)
- **AC-026-03**: `GET /api/v1/exec-reporting/kpis?org_id=X` → 200 list; empty → `[]`. (verified)
- **AC-026-04**: `GET /api/v1/exec-reporting/summary` (and `/reports`, `/kpis`, `/`,
  `/board-presentations`) without `X-API-Key` → **401**. (verified post-fix; was 200 — the bug this spec fixed)
- **AC-026-05**: `GET /api/v1/evidence/export/status?org_id=X` → 200 with `status`,
  `crypto_available`, `compliance_engine_available`. (verified)
- **AC-026-06**: pytest exec-reporting + evidence-export suites pass; Beast smoke green.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Documented exec-reporting + evidence-export surface; routers attributed via runtime `endpoint.__module__` (both clean single-routers). |
| 2026-06-03 | Red-Team (self) | **Found a live auth gap**: all 5 exec-reporting GET endpoints returned 200 to unauthenticated callers (exec report/KPI/board-data leak), while every peer surface (deception/mpte/forensics) 401s. Root cause: the router was declared without `dependencies=[Depends(api_key_auth)]` (unlike deception_router). Fixed by adding the router-level auth dep; verified no-key→401, with-key→200, create_app boots (8357 routes), CISODashboard (sends X-API-Key) unaffected. |

## 8. Implementation notes
This spec backfills governance over the reporting/evidence-export surface AND fixed a real
security gap discovered during authoring (REQ-026-01 / AC-026-04). Code change:
`executive_reporting_router.py` now declares `APIRouter(..., dependencies=[Depends(api_key_auth)])`
(guarded import, mirrors `deception_router`). Closes the named spec backfill backlog — the whole
original API-group surface is now spec-governed in specs/INDEX.md.
