# SPEC-029 — Analytics endpoints must be org-scoped (ingest-first integrity)

- **Status**: IN PROGRESS (fix landing 2026-06-03)
- **Owner family**: Analytics / Tenancy / Customer-Readiness
- **Routers**: `suite-api/apps/api/analytics_router.py` (`/api/v1/analytics/*`)
- **Engines**: `suite-core/core/analytics_db.py` (`AnalyticsDB`)
- **Stores**: analytics findings/decisions SQLite (`findings`, `decisions` tables, `org_id` column)
- **Depends on**: SPEC-027 (auth), CLAUDE.md "NO MOCKS" + ingest-first positioning
- **Last updated**: 2026-06-03
- **Multica**: #9089

## 1. Intent (the why)
FixOps is an **ingest-first intelligence layer**: a tenant that has ingested nothing must see an
honest-empty posture (zeros / empty lists), never fabricated or another tenant's data. A live probe
of `/api/v1/analytics/*` for a **fresh org** (`fresh-zz9`, zero ingest) returned **fabricated/leaked**
posture:
- `/analytics/risk-overview` → `risk_score:100, total_findings:2000`
- `/analytics/summary` & `/analytics/stats` → `total_findings:10000`
- `/analytics/dashboard/top-risks` → risks tagged `org_id:"default"` (cross-tenant leak)
- `/analytics/risk-velocity` → `daily_risk_velocity:40.5`
- `/analytics/dashboard/trends`, `/coverage`, `/roi`, `/mttr`, `/noise-reduction`,
  `/executive`, `/sla`, `/live-feed`, `/trends/severity-over-time` → global/default-org counts

Root cause: these handlers call `db.list_findings(limit=N)` / `db.list_decisions(limit=N)` /
`db.get_top_risks(limit=N)` / `db.calculate_mttr()` **without `org_id`**, while sibling handlers in
the same file correctly pass `org_id=org_id`. The unscoped query returns ALL orgs' rows (capped at
the limit), which both leaks tenants AND fabricates a non-zero posture for an un-ingested org.

This is simultaneously an **ingest-first violation**, a **NO-MOCKS-class violation** (fabricated
posture), and a **tenant-isolation leak**.

## 2. Scope — the invariant
**Invariant:** every `/api/v1/analytics/*` read that aggregates findings/decisions/risks MUST scope
its query to the caller's `org_id` (via `Depends(get_org_id)`), so a fresh org returns honest-empty.

Handlers to scope (analytics_router.py):
- Class A (had `org_id`, dropped it on the query): `/dashboard/trends`, `/dashboard/top-risks`,
  `/stats` (+ `/summary` alias), `/trends/severity-over-time`, `/risk-velocity`.
- Class B (no `org_id` dependency at all): `/mttr`, `/coverage`, `/roi`, `/noise-reduction`,
  `/executive`, `/risk-overview`, `/sla`, `/live-feed`.

Engine: `AnalyticsDB.calculate_mttr` gains optional `org_id` (subquery filter on `findings.org_id`).

## 3. Contracts
```
GET /api/v1/analytics/<x>?org_id=<fresh>  →  honest-empty (0 / [] / null), NEVER another org's rows
GET /api/v1/analytics/<x>?org_id=<ingested>  →  that org's real aggregates only
```

## 4. Functional requirements
- **REQ-029-01**: Every listed handler resolves `org_id` via `Depends(get_org_id)` and passes it to
  every `db.list_findings` / `db.list_decisions` / `db.get_top_risks` / `db.calculate_mttr` call.
- **REQ-029-02**: A fresh org returns `total_findings:0`, `risk_score:0`, empty lists — no fabricated
  constants, no default-org rows.
- **REQ-029-03**: No behavioural change for an org that HAS ingested data (its own rows still returned).

## 5. Non-functional requirements
- `create_app()` boots; engine + router import sweep green; Beast smoke 13-file green.

## 6. Acceptance criteria
- **AC-029-01**: Re-probe of all listed endpoints for a fresh org returns honest-empty (zeros/[]).
- **AC-029-02**: Engine + router import sweep passes; `create_app()` route count unchanged.
- **AC-029-03**: Beast smoke 13-file suite green (no regressions).
- **AC-029-04**: registered in `specs/INDEX.md`.

## 7. Debate log
| Date | Mode | Verdict / change |
|------|------|------------------|
| 2026-06-03 | Live probe (founder positioning correction) | Found fabricated/leaked posture on 13 analytics endpoints for a fresh org; root-caused to dropped `org_id`; spec authored to govern the org-scoping fix. |

## 8. Implementation notes
Mechanical: add `org_id=org_id` to unscoped `db.*` calls; for Class B handlers add
`org_id: str = Depends(get_org_id)` (replacing/augmenting the bare `request: Request`). `get_org_id`
is already imported. Verify with a fresh-org re-probe, not self-report.
