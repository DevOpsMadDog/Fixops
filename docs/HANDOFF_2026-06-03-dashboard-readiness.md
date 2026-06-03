# HANDOFF — 2026-06-03 — UI customer-readiness + dashboard endpoint sweep

Branch: `chore/ui-prune-plan-2026-05-24` (commit locally; push founder-blocked).

## What shipped this session (11 commits, all verified)

### UI NO-MOCKS + cross-tenant (verified clean)
- **CopilotDashboard.tsx** — removed `DEFAULT_AGENTS` hardcoded 4-agent mock-fallback; agents now come ONLY from `/api/v1/copilot/agents`, empty → branded EmptyState. (`f58fb431`)
- **TrainingCultureHub.tsx** — was the only page hardcoding `X-Org-ID: DEFAULT_ORG_ID`; swapped to `getStoredOrgId()` (authenticated tenant). (`6f0c98ad`)
- **AutomationOrchestrationHub / PolicyLifecycleHub / FindingsExplorer** — 3 more pages used `DEFAULT_ORG_ID` as THE org; swapped to `getStoredOrgId()`. (`7844567b`)
- Static scan now clean: 290 pages all fire an API call; 0 fixture dirs/imports; 0 `?? [{` fabrication fallbacks; 126/126 local apiFetch helpers send X-Org-ID; 0 DEFAULT_ORG_ID misuse.

### LIVE Playwright verification (dev 5173 + backend 8000 up)
- Authenticated tenant = `org-5f4bcda1-e979-4490-85be-2575ccc8e552` (real org).
- training-culture / automation / findings / executive all fire real `/api/v1` on mount, 200, **real tenant org propagating** (proves the org-id fix), 0 console errors.
- `/api/v1/findings` returned real dogfood data (sample: `code-string-concat`, severity high, real uuid).

### Broken dashboard endpoints — found via live dogfood, fixed (code = source of truth; running :8000 was STALE, so verified via TestClient on fresh create_app)
- **sbom_router**: added real `GET /api/v1/sbom/components` (org-wide `engine.list_components`, `{components,count}`, honest empty). (`7cebc04c`)
- **dashboardRoutes.ts**: repointed 18 broken endpoints across 15 domains to real LIST/stats paths (each verified 200+shape). (`197fa904`)
- **upgrade_path_router** `GET /recent` (engine.list_queries) + **servicenow_router** `GET /incidents`+`/stats` (real incidents/counts, honest 503 unconfigured). (`08784f85`)
- All 137 GenericDashboard endpoints now resolve (200 / honest 503), 0 remaining 404.
- **findingsExplorerRoutes.ts**: repointed 8 more verified-shape stats endpoints. (`f90760d8`)

## Gates (every increment)
UI `npm run build` green (~3.8–4.5s) · `create_app()` boots 8353 routes · Beast smoke **756/756** · live API verified.

## PRECISE REMAINING RUNWAY (buildable, not founder-blocked) — for next tick
8 `findingsExplorerRoutes.ts` statsPath/apiPath entries have **no real backend equivalent** — they need NEW real endpoints (do NOT repoint to a wrong-domain path; that shows wrong data). Each: confirm engine has the data → add a real `/stats` (honest empty when none) → verify 200+shape via TestClient → repoint config → build:
- `findings/stats` (lines 56, 680) — findings router (`findings_routes.py`) has no stats GET; `/findings` list works. Add severity/status counts endpoint.
- `findings/drift/stats` (140, 161) — only `cspm/drift` exists (503 unconfigured). Decide: repoint to cspm/drift or add findings-drift stats.
- `security-okrs/stats` (532) — engine in `core/security_metrics.py`; only `/objectives`+`/velocity` lists. Add OKR counts (on-track/at-risk/avg-progress).
- `threat-modeling-pipeline/stats` (744) — engine `threat_modeling_pipeline_engine`; root+`/models`+`/unmitigated`. Add model/threat counts.
- `scoring/stats` (765) — NO `/api/v1/scoring` router (risk-scoring is at `/api/v1/risk-scoring`). Either fix UI path to risk-scoring or add scoring stats.
- `posture-history/domains` (apiPath, 807) + `posture-history/stats` (809) — has `/snapshots`/`/trends`/`/delta`/`/summary`. Pick the correct list + verify `/delta` as the stats dict.
- `risk/heatmap` (apiPath, 829) — no heatmap route on `composite_risk_router`. Add a real risk-matrix endpoint.

## Tick 2 (same day) — dashboard sweep closed + systemic shadowing fix (6 more commits)
- **findings/summary + /sla** — fixed route shadowing (`/{finding_id}` swallowed them → 404) AND wrong data source (read empty in-memory store, not engine). Now real aggregation (1000 findings, 97.2% SLA). (`1a254487`)
- Repointed `scoring/stats→risk-scoring/summary`, `posture-history/domains→/snapshots` (`fc54805d`); added real `threat-modeling-pipeline/stats` + `security-okrs/stats` (`86f199cf`); final 3 `findings/drift/stats→cloud-drift/stats`, `risk/heatmap→risk/top`, `posture-history/stats→/summary` (`2cf97d67`).
- **MILESTONE**: full re-probe of all **208** dashboard endpoints (dashboardRoutes + findingsExplorerRoutes) → **0 remaining 404s**.
- **SYSTEMIC route-shadowing fix** (`1cf9a368`): AST+TestClient sweep found 16 literal GET routes shadowed by an earlier `/{param}`. Shared `apps/api/_route_priority.prioritize_literal_routes(router)`. **Revived 15** across evidence-collector, webhook-subscriptions, exposure-cases, secrets-scanner (7!), findings.

## REMAINING RUNWAY (next ticks)
1. **policies/conflicts + /violations** — cross-router dup-prefix collision: `policies_router.py` AND `policy_router.py` both prefix `/api/v1/policies`; `/{id}` in one shadows `/conflicts` in the other at the app level. Needs the duplicate-prefix consolidation (see memory `project_duplicate_routes_2026-06-03`) or an app-level route reprioritization after all includes — NOT a per-router reorder.
2. The earlier findingsExplorer follow-ups are now ALL DONE (closed this tick).
3. (B) Red-team hardenings (storage-root allowlists, rate-limits) — investigate coverage next.

## Tick 3 (same day) — page-endpoint sweep + vendor-risk endpoints
- **Broad page-endpoint dogfood**: extracted real-fetch `/api/v1` from all 290 pages EXCLUDING doc-comments (the bulk of apparent 404s were stale `* API stubs:` header comments). True result: 348 real-call concrete paths, **339 well-routed**, only 9 genuinely unrouted.
- **policies/conflicts+/violations** investigated → cross-router dup-prefix debt (2 non-UI endpoints) → deferred to consolidation epic.
- **Built 2 real vendor-risk endpoints** (`1bcdc37f`): `/vendor-risk/assessments` (from `get_risk_register`) + `/vendor-risk/risk-domains` (from `VendorScorecard` dimension averages) — fixed 2 dead VendorRiskDashboard mount calls. Real data, honest empty, 0-100 higher=safer.

## REMAINING PAGE-GAP RUNWAY (7 — each a real feature endpoint, NOT a clean repoint; needs per-feature design, verify-shape, no fabrication)
1. `llm/estimate` (POST) — prompt token-cost estimate (`{prompt,model,max_output_tokens}`). Existing `/ai-orchestrator/preflight-estimate` is RULES-based (different). Needs a model-pricing table + token counter — find/confirm a real pricing source (do NOT guess prices).
2. `threat-intel/block-iocs` (POST) — IOC-block action endpoint (threat_intel_router has lookup/refresh, no block).
3. `skills/install` (POST) — `/skills/uninstall` exists; install needs an air-gap install-source design.
4. `local-store/init` (POST, ZeroSetupOnboarding) — `/local-store` has config/acquire-lock; confirm whether `/init` maps to an existing setup or is new.
5-6. `hunting/coverage` + `hunting/iocs` (GET, ThreatHunting) — `/hunting` lacks them; `iocs` may map to `/threat-intel/iocs` (verify shape).
7. `collaboration/activity` (POST) — low value (fire-and-forget, page catches); needs `EntityType.WAR_ROOM` + `ActivityType.CREATED` enum additions + repoint `/activity→/activities`.

## Founder-blocked (record + move on)
push, Postgres, test-infra fixture, org-precedence, FIPS, PIV, GPU, Stripe.
