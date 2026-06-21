# FixOps / ALDECI — System Overview (architecture map)

> **Purpose**: the repo map for a disciplined, spec-driven path to a stable
> first-customer release. Documentation only — no production code changed by this doc.
> **Method**: file-cited claims from direct inspection + a 142-agent capability audit
> (`docs/GAP_MAP.md`, 2026-06-21). Anything not file-verifiable is marked **UNKNOWN**
> (with how to verify) or **ASSUMPTION**.
> **Last updated**: 2026-06-21 · branch `chore/ui-prune-plan-2026-05-24`.

---

## 0. What FixOps is
An ingest-first, self-hosted AI security-intelligence platform (ASPM + CTEM + CSPM).
It **ingests** existing scanner output (61 normalizers) and adds the moat: multi-LLM
council verdicts + TrustGraph correlation + a brain pipeline + MPTE exploitability.
Honest-empty until data is ingested — no fabricated scores. (`CLAUDE.md`; capability
realness confirmed in `docs/GAP_MAP.md` — moats are overwhelmingly *real*, not stubs.)

Deployment model: **on-prem / air-gapped**, NOT SaaS. There is therefore **no vendor
SOC2**; the compliance bar is the customer's ATO (NIST 800-53 / RMF / ICD 503).
(`.github/workflows/air-gapped-test.yml`, `core/fips_boot.py`, memory `feedback_no_soc2_onprem_airgap`.)

## 1. Repo layout (cited)
| Area | Path | Size / count |
|---|---|---|
| API gateway | `suite-api/` | **813** `*_router.py` files (`ls suite-api/apps/api/*_router.py`) |
| Core engines | `suite-core/` | **473** `*_engine.py` (`find suite-core -name '*_engine.py'`) |
| Offensive/MPTE | `suite-attack/` | e.g. `suite-attack/api/mpte_router.py` |
| Threat feeds | `suite-feeds/` | feed importers |
| Evidence/risk | `suite-evidence-risk/` | evidence, compliance |
| Integrations | `suite-integrations/` | MCP, webhooks |
| Active UI | `suite-ui/aldeci-ui-new/` | React 19 + Vite 6 + Tailwind 4, **299** pages (`find .../src/pages -name '*.tsx'`) |
| Legacy UI | `suite-ui/aldeci/` | **FROZEN** — do not modify (`CLAUDE.md`) |
| Tests | `tests/` | **1,457** `test_*.py` |
| Specs | `specs/` | **34** `SPEC-*.md` (SPEC-001…032) |
| CI | `.github/workflows/` | **15** workflows |
| Total Python | `suite-*` | ~**1.04M LOC** (`find suite-* -name '*.py' \| xargs wc -l`) |

Import mechanism: `sitecustomize.py` + `pyproject.toml [tool.pytest.ini_options] pythonpath`
prepend all suite dirs to `sys.path` (so `from core.brain_pipeline import …` resolves).

## 2. Frontend (`suite-ui/aldeci-ui-new/`)
- Stack: **React ^19.0.0, Vite ^6.0.0, Tailwind ^4.0.0** (`package.json`).
- Scripts (`package.json`): `build=vite build`, `typecheck=tsc -b`, `test=vitest run`,
  `test:e2e=playwright test`, `dev=vite`.
- Dev API access: Vite proxy `"^/api/" → http://localhost:8000` (`vite.config.*:65-69`).
  Comment there documents a deliberate narrow `^/api/` match so SPA routes like
  `/api-security` aren't swallowed. Production base URL: **UNKNOWN** — verify how the
  built bundle resolves the API origin (grep `VITE_` / runtime config).
- API layer: central client in `src/lib/api.ts` (apiFetch) attaching `X-API-Key` / org
  headers (`CLAUDE.md`, this session's NO-MOCKS fixes). Whether responses are typed
  contracts vs `any` is the core risk in `api-contracts.md` — **partly UNKNOWN**, verify
  per-page.
- NO-MOCKS posture: enforced by a CI gate (`tests/test_ui_no_mocks_static.py`, SPEC-028)
  + browser-verified for ~8 domains this program. Not exhaustively verified across all 299
  pages — **ASSUMPTION** the gate covers the rest statically.

## 3. Backend / API (`suite-api/apps/api/`)
- App factory `create_app()` in `apps/api/app.py`; **8,357 mounted routes** (verified this
  session: `python -c "from apps.api.app import create_app; print(len(create_app().routes))"`).
- Composed of 813 router files + sub-apps under `apps/api/sub_apps/` (e.g. `grc_app.py`,
  `platform_app.py`).
- Middlewares wired in `app.py` (rate limit `RateLimitMiddleware` + `OrgTierRateLimitMiddleware`,
  org-id `OrgIdMiddleware`, request tracing, `ResponseInterceptorMiddleware` for TrustGraph,
  airgap egress guard). Rate limits enforced (verified tick217: read 200/min + burst 20 → 429).
- **Known debt**: ~740 duplicate `(method,path)` routes incl. 131 different-handler shadow
  collisions (memory `project_duplicate_routes_2026-06-03`) — architecture consolidation item.

## 4. Auth & multi-tenancy
- API-key auth: `apps/api/auth_deps.py::api_key_auth` — validates `X-API-Key` header (or
  `?api_key=`) against `FIXOPS_API_TOKEN`. Applied router-level (`dependencies=[Depends(api_key_auth)]`).
- Org/tenant: `apps/api/org_middleware.py::get_org_id` (re-exported via `apps/api/dependencies.py`).
  Priority: **JWT/middleware contextvar > query param > header > "default"**.
- JWT: validated via middleware → contextvar. Exact JWT verification path: **UNKNOWN** — verify
  in `org_middleware.py` / auth router.
- **Tenancy gaps** (from `docs/GAP_MAP.md`): several routers historically took `org_id` as a
  spoofable client param. **Fixed 2026-06-21** in 5 routers (network_traffic, data_exfiltration,
  data_retention, data_lake_security, ctem_engine → `Depends(get_org_id)`, commit `b9ac25ff`).
  **Still open**: schema-level tenancy — some domain tables lack an `org_id` column
  (`core/network_analyzer.py` zones/flows/violations; SPEC-030) → **founder-gated migration**.

## 5. Data / persistence
- Storage: **SQLite per-domain DBs** (100+; engines call `sqlite3.connect`, files under `data/`
  and some `/tmp`) + **DuckDB** analytics layer + Markdown docs (`CLAUDE.md`, `core/duckdb_analytics_engine.py`).
- **Schema management is hybrid/inconsistent** (real finding):
  - A formal tool exists — `alembic.ini` (`script_location = alembic`) — but only **2 versions**
    (`alembic/versions/001_initial_schema.py`, `002_add_p0_models.py`).
  - Meanwhile **356 engines self-create schema** via `CREATE TABLE IF NOT EXISTS` in
    `_init_db()`/`_init_tables()` (`grep -l "CREATE TABLE IF NOT EXISTS" suite-core/core/*_engine.py`).
  - ⇒ No single source of truth for schema; most tables are created ad-hoc on engine init.
    **Risk** for upgrades/migrations on a customer deployment (see §8 R4).
- Tenancy in schema: partial — `security_findings` carries `org_id`; `network_analyzer` tables
  do **not** (SPEC-030). Per-table audit needed.
- Durability/HA: `core/db_durability.py` **warns** WAL-replication NOT configured (no replica
  snapshots) — a node failure can lose data (verified in boot logs this session). SPEC-008.
- Reference vs tenant data: engine seed-on-init is legit only for **reference catalogs**
  (MITRE/controls/playbooks); fabricated *tenant* data is a NO-MOCKS violation. Swept clean
  2026-06-03 (memory `feedback_autoseed_reference_vs_tenant_data`).

## 6. Integrations / connectors
- `PullConnector` framework (`suite-core/connectors/pull_connector.py`) + `connector_framework`
  (CI-gated: `tests/test_connector_framework.py`). 61 scanner normalizers (ingest-first).
- 11 vendor "live" connectors (CrowdStrike, Okta, Intune, …) — require creds; tests skip without.
- Customer ingest path: `POST /api/v1/scanner-ingest/upload` (multipart) → promote findings →
  `SecurityFindingsEngine` (+ TrustGraph index, org-scoped) → `GET /api/v1/security-findings/`.
  **Verified working end-to-end** this session (upload 10 → org-scoped readback, deduped,
  empty-org=0). Gated by `tests/test_customer_journey_e2e.py` (now blocking CI, commit `b9408c27`).

## 7. Build / test / CI / deploy — commands & status
### Commands (cited)
| Concern | Command | Source |
|---|---|---|
| Python tests | `python -m pytest tests/ -o "addopts="` (override needed — see below) | `pyproject.toml:22` |
| FE build | `cd suite-ui/aldeci-ui-new && npm run build` | `package.json` |
| FE typecheck | `npm run typecheck` (`tsc -b`) | `package.json` |
| FE unit | `npm run test` (vitest) | `package.json` |
| FE e2e | `npm run test:e2e` (playwright) | `package.json` |
| Py lint | `ruff check …` — ruff is on PATH **but unconfigured** (no `[tool.ruff]` in `pyproject.toml`) → **no enforced lint standard**. ASSUMPTION: lint is ad-hoc. |

⚠️ **pytest gotcha**: `pyproject.toml` `addopts` injects `-v --strict-markers --strict-config
--cov=…` (heavy coverage). All real test runs/CI **must** pass `-o "addopts="` (or
`--override-ini`) or runs are slow/over-instrumented. Default `timeout = 10` is **shorter than
`create_app()` boot (~14s)** → any test that boots the full app inside the default timeout is a
**guaranteed false-red** (GAP_MAP #boot-smoke; e.g. `test_trustgraph_correlation.py` boot test,
`test_empty_endpoint_35_ctem.py` — both pass with a longer timeout).

### CI workflows (15) — `.github/workflows/`
- **`regression-gates.yml`** (the real gate, on PR→[main, features/intermediate-stage]):
  blocking pytest steps — owasp-lockdown, engine/router import-sweep, auth-gate, UI-no-mocks
  (SPEC-028), UI-routing (SPEC-031), ingest-first (SPEC-029), real-moat-e2e (SPEC-032),
  customer-journey-e2e — none use `|| echo` except the perf step (`|| echo … skipping`).
- `ci.yml`, `qa.yml`: run the broad `pytest tests/` on PR. **`ci.yml` pip-audit is toothless**
  (`|| true` + `continue-on-error: true`) → CVEs never fail CI (GAP_MAP #3, SPEC-009).
- Others: `air-gapped-test.yml`, `codeql.yml`, `deploy.yml`, `docker-build.yml`, `e2e-tests.yml`,
  `fixops-ci.yml`, `provenance.yml`, `real-moat-live-nightly.yml`, `release-sign.yml`,
  `repro-verify.yml`, `self-scan.yml`, `fixops_pipeline.yml`.

### Test status (directly observed this session — distinguishing pre-existing vs new)
- **Beast smoke (13-file, ~756 tests): green** (no new failures introduced).
- **Core SCIF path** (brain pipeline ×3, connectors ×3, autofix council, cloud findings):
  **429 passed / 0 failed**.
- **Compliance/attack/kev batch**: 346 passed; **1 stale test fixed** (KEV fail-closed auth,
  commit `f852bf13`) — was a test gap, not a product regression.
- **Pre-existing/known reds (NOT new)**: (a) create_app boot-timeout false-reds under the 10s
  default; (b) founder-gated `test_org_id_query_overrides_header` (org-precedence decision);
  (c) `test_tenancy_lint.py` (SPEC-007, 100 untracked V1 violations — founder-gated schema).
- **FE build**: reported live (~3.10s) historically (`CLAUDE.md`); **re-verify** with
  `npm run build` (node_modules state UNKNOWN in this checkout).

### Deploy
- `docker/` + Dockerfiles + `deploy.yml`; air-gap path (`air-gapped-test.yml`). Self-hosted /
  on-prem. Fly recipe exists for staging (memory `project_fly_deploy_recipe`).

## 8. Top 10 risks blocking a customer-deliverable release (+ mitigation)
Ranked by customer/security impact. Severities reconcile with `docs/GAP_MAP.md`.

| # | Risk | Evidence | Mitigation |
|---|---|---|---|
| **R1** | **Schema-level tenancy gaps** — some domain tables have no `org_id` column → cross-tenant data on shared deploys even after the router fixes. | `core/network_analyzer.py` (SPEC-030); GAP_MAP #1 | Add `org_id` columns + backfill via alembic migration; gate with a tenancy integration test. *Founder-gated (DB migration).* |
| **R2** | **Router org_id-spoofing** (now mostly fixed) — any remaining router taking `org_id` as a client param leaks tenants. | 5 fixed `b9ac25ff`; sweep rest | Sweep all 813 routers for `org_id: ... = Query/Body`; convert to `Depends(get_org_id)`; add a lint test. |
| **R3** | **CI gates don't cover the moats** — only ~8/54 capabilities have a blocking gate; real engines can silently regress. | GAP_MAP systemic finding | Add one blocking `regression-gates.yml` step per high-value capability (trustgraph, council, mpte, threat-intel). |
| **R4** | **No single schema source of truth** — 356 engines ad-hoc `CREATE TABLE`; alembic has 2 versions. Upgrades/migrations are unmanaged. | `alembic/versions/` (2), 356 engines | Decide policy: consolidate critical tables into alembic; document the rest as runtime-managed; add a schema-snapshot test. |
| **R5** | **Toothless supply-chain gate** — pip-audit can't fail CI; 251 dependabot vulns on the default branch. | `ci.yml` `|| true`+`continue-on-error`; push warning | Make pip-audit blocking on HIGH/CRITICAL in `regression-gates.yml` (SPEC-009 REQ-009-04); triage the 251. |
| **R6** | **NO-MOCKS residue** — endpoints served fabricated data as real (3 fixed; audit the rest). | GAP_MAP #9/#10/#18 (feed counts, MITRE list, AI advisor) — #9/#18 fixed `fa270b9b`/`19ba54dc` | Finish: `feeds_router.py` MITRE static list (#10); sweep `realness=mixed` capabilities. |
| **R7** | **UI↔API contract is unpinned** — responses largely untyped; FE/BE can drift silently (the churn source). | `src/lib/api.ts`; see `api-contracts.md` | Contract-first: OpenAPI/zod shared types + contract tests on the riskiest endpoints first (Phase 3). |
| **R8** | **create_app 10s-timeout false-reds** — real capabilities show red in gates. | `pyproject.toml timeout=10` vs ~14s boot | Boot-smoke tests should inspect the router object, not build the full app; or set per-test timeout. |
| **R9** | **Main branch is 813 commits stale** — release work lives only on a branch; merge-to-main + repo-of-truth (`aldeci-core` vs `Fixops`) unresolved. | `git rev-list origin/main...HEAD` = 813 | Founder decision on repo-of-truth; then merge with the gates green. *Founder-gated.* |
| **R10** | **HA/durability not configured** — WAL replication off → node failure loses data. | `core/db_durability.py` boot warning; SPEC-008 | Wire litestream per `docker/litestream.yml` for customer deploys; document RPO/RTO. |

Out-of-scope-but-tracked (founder-gated, not release blockers per se): FIPS-CMVP cert, PIV/CAC,
GPU for local distillation, Stripe billing, org-query-vs-header precedence.

## 9. First 5 specs to write before any implementation
Chosen to stop the churn (contracts) and close the top risks. Each follows the
Phase-4 template (objective / current / desired / API-UI-data impact / acceptance / test plan /
out-of-scope).

1. **SPEC-033 — UI↔API contract baseline** (R7). Pin the response schema of the top ~10
   customer-facing endpoints (security-findings, scanner-ingest, analytics summary, council
   verdict, evidence) as OpenAPI/shared types; add contract tests. *Stops the FE/BE breakage.*
2. **SPEC-034 — Tenancy enforcement end-to-end** (R1+R2). Invariant: every `/api/v1` data route
   derives `org_id` from auth context only; every domain table has `org_id`; a fresh org sees 0.
   Includes the founder-gated migration plan.
3. **SPEC-035 — CI gate coverage matrix** (R3+R5). One blocking gate per high-value capability +
   make pip-audit bite. Codifies "a gate that doesn't run doesn't exist."
4. **SPEC-036 — Schema source-of-truth policy** (R4). Decide alembic-managed vs runtime-managed
   per table; add a schema-snapshot/regression test; document upgrade procedure.
5. **SPEC-037 — First-customer release checklist** (R9+R10). The exit criteria: gates green,
   tenancy proven, durability configured, branch merged, scope met (`docs/product/release-scope.md`).

## 10. See also
- `docs/architecture/api-contracts.md` — UI↔API boundary, weak/risky contracts.
- `docs/product/release-scope.md` — strict in/out for first customer.
- `docs/GAP_MAP.md` — full 54-capability audit (status matrix + 170 ranked gaps).
