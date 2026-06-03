# SPEC-021 — MPTE: Multi-Phase Test & Exploitability Validation

- **Status**: BACKFILL
- **Owner family**: Pentest / Offensive Validation
- **Routers**: `suite-attack/api/mpte_router.py` (prefix `/api/v1/mpte`), `suite-attack/api/mpte_orchestrator_router.py` (prefix `/api/v1/mpte-orchestrator`)
- **Engines**: `suite-core/core/mpte_advanced.py` (AdvancedMPTE + exploitability validation framework + AI-consensus roles), `suite-core/core/mpte_models.py` (ExploitabilityLevel, request/result models), `suite-core/core/mpte_db.py` (store)
- **Stores**: MPTE SQLite DB (requests / results / configs / verifications), per-org scoped
- **Depends on**: SPEC-002 (Nuclei pen-test connector — real exploitability), SPEC-001/005b (TrustGraph correlation of validated findings); env: none required (built-in self-contained scanner)
- **Last updated**: 2026-06-03

## 1. Intent (the why)
MPTE turns raw findings into **proven exploitability**: instead of trusting a scanner's
"critical" label, MPTE re-tests the finding and labels it `confirmed_exploitable`,
`likely_exploitable`, or `unexploitable` — the FP-reduction moat that lets a SCIF customer
prioritise the handful of findings that are *actually* reachable + weaponisable. It runs as
a built-in, self-contained scanner (no external SaaS, air-gap-safe) and an orchestrator that
fuses threat-intel (NVD/CISA-KEV/EPSS/Exploit-DB/MITRE) + business-impact + AI consensus into
a single exploitability verdict and remediation plan.

## 2. Scope — endpoints
| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/mpte/health | engine health + mode (builtin/self-contained) | api_key | n/a |
| GET | /api/v1/mpte/status | engine status + config/scan counts | api_key | yes (org_id) |
| GET | /api/v1/mpte/stats | aggregate scan/verify counts + avg confidence | api_key | yes |
| GET·POST | /api/v1/mpte/requests | list / create pen-test requests | api_key | yes |
| GET·PUT | /api/v1/mpte/requests/{id} | fetch / update a request | api_key | yes |
| POST | /api/v1/mpte/requests/{id}/start·/cancel | lifecycle transitions | api_key | yes |
| GET·POST | /api/v1/mpte/results | list / record results | api_key | yes |
| GET | /api/v1/mpte/results/by-request/{id} | results for a request | api_key | yes |
| GET·POST·PUT·DELETE | /api/v1/mpte/configs[/{id}] | scan config CRUD | api_key | yes |
| POST | /api/v1/mpte/verify | verify a single finding's exploitability | api_key | yes |
| POST | /api/v1/mpte/scan/comprehensive | full multi-phase scan | api_key | yes |
| GET | /api/v1/mpte/findings/{id}/exploitability | exploitability verdict for a finding | api_key | yes |
| GET | /api/v1/mpte/verifications[/{id}] | verification records | api_key | yes |
| GET | /api/v1/mpte-orchestrator/capabilities | declared capabilities + TI sources | api_key | yes |
| POST | /api/v1/mpte-orchestrator/threat-intel·/business-impact·/simulate·/remediation·/run | orchestrated phases | api_key | yes |
| GET | /api/v1/mpte-orchestrator/status/{test_id} | orchestrated run status | api_key | yes |

Out of scope: external SaaS pen-test services; destructive/active exploitation against
non-consented targets; the Nuclei connector internals (SPEC-002); UI rendering (a UI page
must follow the NO-MOCKS rule and consume these endpoints, not fixtures).

## 3. Data contracts
```
GET /api/v1/mpte/health → 200 {"status":"healthy","engine":"builtin","mode":"self-contained","description":"...","configs_count":N,...}
GET /api/v1/mpte/requests?org_id=O → 200 {"items":[{"id","finding_id","target_url","vulnerability_type","status",...}], ...}
GET /api/v1/mpte/stats?org_id=O → 200 {"total_scans","total_requests","total_results","total_findings","verified_vulnerable","not_vulnerable","unverified","avg_confidence"}
GET /api/v1/mpte/findings/{id}/exploitability?org_id=O → 200 {"exploitability":"confirmed_exploitable|likely_exploitable|unexploitable", ...}
GET /api/v1/mpte-orchestrator/capabilities?org_id=O → 200 {"version","capabilities":{"threat_intelligence":{"sources":["NVD","CISA KEV","EPSS","Exploit-DB","MITRE ATT&CK"],"available":true},"ai_consensus":{...}}}
(missing X-API-Key) → 401
```

## 4. Functional requirements
- **REQ-021-01**: Exploitability verdicts use only the honest `ExploitabilityLevel` enum
  (`confirmed_exploitable` / `likely_exploitable` / `unexploitable` / `blocked` / `inconclusive`
  / `unknown`) — never an unqualified "exploitable" without validation, and `unknown`/`inconclusive`
  rather than a fabricated verdict when validation can't decide.
- **REQ-021-02**: The engine runs self-contained (no external service / network required to start);
  `health` reports `engine:"builtin"`, `mode:"self-contained"`.
- **REQ-021-03**: All request/result/config/verification reads are org-scoped via `get_org_id`;
  one org never sees another's MPTE records.
- **REQ-021-04**: `stats` returns real counts derived from the store (not fabricated), including
  `verified_vulnerable` / `not_vulnerable` / `unverified` splits.
- **REQ-021-05**: The orchestrator declares its real TI sources (NVD/CISA-KEV/EPSS/Exploit-DB/MITRE)
  and fuses them with business-impact + AI consensus into a verdict.

## 5. Non-functional requirements
- Latency: GET endpoints (health/status/stats/list) return < 2s; heavy scans run via POST
  request→start lifecycle, not synchronously on a GET.
- Tenancy: org_id from `get_org_id`; cross-org access yields no foreign records.
- Auth: every endpoint requires `X-API-Key`; missing key → 401 (never anonymous data).
- Failure mode: unconfigured/empty → honest empty (`items:[]`, zero counts), never 500/hang/fake.

## 6. Acceptance criteria (executable)
- **AC-021-01**: `GET /api/v1/mpte/health` → 200 with `engine:"builtin"` and `mode:"self-contained"`. (verified 2026-06-03)
- **AC-021-02**: `GET /api/v1/mpte/requests?org_id=X` → 200 `{items:[...]}`. (verified)
- **AC-021-03**: `GET /api/v1/mpte/requests` without `X-API-Key` → 401. (verified)
- **AC-021-04**: `GET /api/v1/mpte/stats?org_id=X` → 200 carrying `total_scans`, `total_requests`,
  `total_results`, `verified_vulnerable`, `avg_confidence`. (verified)
- **AC-021-05**: `GET /api/v1/mpte-orchestrator/capabilities` → 200 with
  `capabilities.threat_intelligence.sources` ⊇ {NVD, CISA KEV, EPSS}. (verified)
- **AC-021-06**: `ExploitabilityLevel` enum in `core/mpte_models.py` = {confirmed_exploitable,
  likely_exploitable, unexploitable, blocked, inconclusive, unknown} — no unqualified "exploitable";
  includes explicit inconclusive/unknown for honest non-verdicts. (verified 2026-06-03, 6 members)
- **AC-021-07**: pytest MPTE suite (`tests/test_mpte*.py`) passes.

## 7. Debate log (Mysti)
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Backfill-author | Documented existing implemented surface (built-in scanner + orchestrator); grounded all endpoints + ACs against live TestClient probes (health/requests/stats/capabilities = 200, no-key = 401). |

## 8. Implementation notes
Already implemented; this spec backfills governance over the existing MPTE surface so it is
visible in the Augment Code intent-IDE map (specs/INDEX.md). Mounted routers resolve to the
`suite-attack/api/` copies (duplicate-router gotcha — verified via runtime `__file__`). No
code change introduced by this spec.
