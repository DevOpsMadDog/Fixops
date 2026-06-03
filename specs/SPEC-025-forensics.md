# SPEC-025 — Forensics (Digital Forensics Cases + Forensic Readiness)

- **Status**: BACKFILL
- **Owner family**: Forensics / IR
- **Routers** (attributed via runtime `endpoint.__module__` — both clean single-routers, no collision): `suite-api/apps/api/digital_forensics_router.py` (prefix `/api/v1/digital-forensics`), `suite-api/apps/api/forensics_readiness_router.py` (prefix `/api/v1/forensics-readiness`)
- **Engines**: digital-forensics engine (cases + evidence + analysis + chain-of-custody), forensic-readiness engine (log/telemetry sources + coverage assessment + readiness plans)
- **Stores**: forensics SQLite (cases / evidence / analyses / custody), readiness SQLite (sources / plans), per-org scoped
- **Depends on**: SPEC-019 (Evidence Chain-of-Custody — digital-forensics custody endpoints share the chain-of-custody integrity model), SPEC-001 (TrustGraph — cases correlate findings/incidents)
- **Last updated**: 2026-06-03

## 1. Intent (the why)
Forensics gives a SCIF SOC defensible post-incident investigation: open a **case**, attach
**evidence** with a tamper-evident **chain of custody**, record **analysis**, and close — plus
**forensic readiness** (are the right log/telemetry sources being collected, with what coverage,
under which retention plan, *before* an incident). Honest-empty: a fresh org has zero cases /
sources, never fabricated evidence or invented coverage scores.

## 2. Scope — endpoints (live-verified surface)
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET·POST | /api/v1/digital-forensics/cases | list / open forensic cases | api_key | yes |
| GET | /api/v1/digital-forensics/cases/{id} | fetch a case | api_key | yes |
| POST | /api/v1/digital-forensics/cases/{id}/close | close a case | api_key | yes |
| GET·POST | /api/v1/digital-forensics/cases/{id}/evidence | list / attach evidence | api_key | yes |
| GET·POST | /api/v1/digital-forensics/cases/{id}/analysis | list / record analysis | api_key | yes |
| GET·POST | /api/v1/digital-forensics/evidence/{id}/custody | chain-of-custody read / append | api_key | yes |
| GET | /api/v1/digital-forensics/stats | counts (open_cases, evidence_items, analyses) | api_key | yes |
| GET·POST | /api/v1/forensics-readiness/sources | list / register telemetry sources | api_key | yes |
| POST | /api/v1/forensics-readiness/sources/{id}/assess | assess a source's coverage | api_key | yes |
| POST | /api/v1/forensics-readiness/plans | create a readiness plan | api_key | yes |
| PUT | /api/v1/forensics-readiness/plans/{id}/execute·/complete | plan lifecycle | api_key | yes |
| GET | /api/v1/forensics-readiness/stats | counts (total_sources, coverage, ready) | api_key | yes |

Out of scope: actual disk/memory image acquisition tooling (the API tracks cases/evidence
metadata + custody; acquisition is operator tooling); UI (must follow NO-MOCKS and consume
these endpoints).

## 3. Data contracts (honest-empty first-class)
```
GET /api/v1/digital-forensics/cases?org_id=O   → 200 [...]   (empty org → [])
GET /api/v1/digital-forensics/stats?org_id=O    → 200 {"open_cases","evidence_items","analyses_completed","avg_case_duration_days"}  (empty → zeros)
GET /api/v1/forensics-readiness/sources?org_id=O → 200 [...]  (empty → [])
GET /api/v1/forensics-readiness/stats?org_id=O   → 200 {"total_sources","by_type","avg_coverage_score","ready_sources",...}  (empty → zeros)
(missing X-API-Key) → 401
```

## 4. Functional requirements
- **REQ-025-01**: Empty org → honest empty (`[]` / zeroed stats), never fabricated cases,
  evidence, custody entries, sources, or coverage scores.
- **REQ-025-02**: All reads/writes are org-scoped; one org never sees another's cases/evidence.
- **REQ-025-03**: Evidence custody is append-only / tamper-evident, consistent with SPEC-019's
  chain-of-custody integrity model (re-hash verification).
- **REQ-025-04**: `stats` (case counts, coverage scores) are computed from real records, not invented.

## 5. Non-functional requirements
- Latency: GET reads < 2s.
- Tenancy: org_id via get_org_id; cross-org → no foreign records.
- Auth: every endpoint requires X-API-Key; missing → 401.
- Failure mode: empty/unconfigured → honest empty, never 500/hang/fabricated.

## 6. Acceptance criteria (executable, verified 2026-06-03)
- **AC-025-01**: `GET /api/v1/digital-forensics/cases?org_id=X` → 200 list; empty org → `[]`. (verified)
- **AC-025-02**: `GET /api/v1/digital-forensics/stats?org_id=X` → 200 with `open_cases`,
  `evidence_items`, `analyses_completed`, `avg_case_duration_days`; empty → zeros. (verified)
- **AC-025-03**: `GET /api/v1/forensics-readiness/sources?org_id=X` → 200 list; empty → `[]`. (verified)
- **AC-025-04**: `GET /api/v1/forensics-readiness/stats?org_id=X` → 200 with `total_sources`,
  `avg_coverage_score`, `ready_sources`; empty → zeros. (verified)
- **AC-025-05**: `GET /api/v1/digital-forensics/stats` without `X-API-Key` → 401. (verified)
- **AC-025-06**: pytest forensics suites (`tests/test_*forensic*.py`) pass.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Documented existing digital-forensics + forensics-readiness surface. Routers attributed via runtime `endpoint.__module__` (SPEC-023 lesson) — both confirmed clean single-routers in `suite-api/apps/api/`, no shadow collision. ACs grounded on live TestClient probes (200 honest-empty; no-key 401). |

## 8. Implementation notes
Already implemented; this spec backfills governance over the forensics surface for the Augment
Code intent-IDE map (specs/INDEX.md). The digital-forensics custody endpoints
(`/evidence/{id}/custody`) share the chain-of-custody integrity model specified in SPEC-019.
Both routers are clean single-routers (verified via `endpoint.__module__`). No code change
introduced by this spec.
