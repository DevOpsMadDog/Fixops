# HANDOFF — Customer-Ready loop COMPLETE (autonomous backlog exhausted) — 2026-06-02

> Branch `chore/ui-prune-plan-2026-05-24` · all commits **LOCAL (unpushed)** · push blocked (VPN DNS + revoked PAT)
> Session: `359b05e6 → HEAD` (~66 commits) · loop log `docs/ralph_progress.md`

## ADDENDUM 9 — Red-Team path-handling surface HARDENED (2026-06-02 late night)
Item (B). Closed the caller-supplied-path read/write/scan surface with ONE shared
primitive (`apps.api._path_safety.safe_fs_path`: always reject null-byte + `..`; opt-in
allowlist env; passthrough when unset = non-breaking) applied across all 3 classes:
- **code-intel** repo paths (architecture-detect / dca-parse / callgraph py+ts+java) —
  authenticated arbitrary-dir READ — `FIXOPS_ALLOWED_REPO_ROOTS`.
- **air-gap** export/import (output_path WRITE + bundle_path/content_paths READ, highest
  severity) — `FIXOPS_ALLOWED_AIRGAP_ROOTS`.
- **scanners** checkov + bandit `target_path` READ — `FIXOPS_ALLOWED_SCAN_ROOTS`.
Verified-safe (no change): bulk_router download (canonical-containment), import zip-extract
(zipfile sanitizes), container_scanner file_path (reporting label only).
Regression: 11/11 (test_path_safety_airgap + test_code_intel_repo_path_allowlist).
Gates: create_app 8335 · Beast smoke 756/756 · tsc 0. Docs: docs/redteam_path_hardening_2026-06-02.md.
Default behaviour unchanged (envs default-off) so self-scan/USB-export/scan ops still work;
SCIF deployments set the envs to lock the surface down.

## ADDENDUM 8 — config-repoint subset EXHAUSTED + session stop state (2026-06-02 late night)
Completed the clean config-repoint subset: **22 config api-paths** now fire real data
(20 statsPath /X/stats->/X/summary, security-benchmarks /results->/benchmarks, evidence-vault
/items->/search) — each live-verified (200 + 0 console errors). Remaining deferred-endpoint
backlog is now exclusively: (a) dead-config (path shadowed by an App.tsx redirect — repoint is
a no-op), (b) semantic/shape mismatch (no clean existing endpoint — not forced), (c) genuinely
missing engine — FOUNDER-BLOCKED on real data importers (no fabrication).

**Session stop state — UI no-mocks-clean, clean buildable work exhausted:**
- Primary customer pages: real /api/v1 on mount, 0 crashes, no fixtures.
- 0 page crashes across the full 613-route space (enhanced sweep).
- Every real crash/404/422 the sweeps surfaced: FIXED + browser-verified (broken nav, hook
  crashes, fragment keys, BRS, findings, AgeBadge, /hunting x6, /org-hierarchy x3, + 22 repoints).
- Gates green: create_app 8335 · Beast smoke 756/756 · tsc 0 · vitest 135/53 · build ~3.6s.
- Remaining (recorded, not clean one-tick work): deferred-endpoint backend program
  (docs/deferred_empty_endpoints_2026-06-02.md, ~46, partly founder-blocked), cosmetic dev-only
  React key warnings (stripped in prod), and the standing founder-blocked list (push, Postgres,
  org-precedence, FIPS, PIV, GPU, Stripe, test-infra fixture).

## ADDENDUM 7 — deferred-endpoint clean-subset repointed to real data (continued tick, 2026-06-02 late night)
Worked the 66-endpoint deferred backlog (addendum 6), extracting only the clean,
non-fabrication, verifiable subset (NOT stubbing — no-fake-data rule):
- **20 dashboard statsPaths** repointed `/X/stats`(404) → the engines' real `/X/summary`(200,
  object-shaped). GenericDashboard auto-detects KPIs → real stats render. Live-verified
  /access-reviews. (commit 14e98e7d)
- **security-benchmarks** list: apiPath `/results`(404) → real `/benchmarks`(200) + itemsKey
  `results`→`benchmarks`. Live-verified /security-benchmarks fires /benchmarks 200 + /summary 200,
  0 console errors. (commit 77bb4b1e)
- **Trap found + documented**: config-route entries whose path is shadowed by an App.tsx redirect
  (e.g. `/exception-workflow` → `/remediate/exceptions`) are DEAD — the GenericDashboard config
  never renders, so repointing them is a no-op (reverted one). Future backlog work must filter
  these out first.
- **Remaining backlog (~46)** categorized: 15 'router-exists' (engine live but the config's list
  apiPath needs a real list route built or a verified repoint — per-endpoint, moderate value,
  some dead-config), 23 'no-router' (missing engine — FOUNDER-BLOCKED on real data importers),
  plus a few ambiguous-semantic repoints intentionally NOT forced (shape-mismatch risk).
  Updated `docs/deferred_empty_endpoints_2026-06-02.md`.
- **Gates**: build ~3.6s; tsc 0; create_app 8335; Beast smoke 755 + known ingest-timing flake
  (passes isolated 0.60s). 0 page crashes across the whole route space.

## ADDENDUM 6 — deep-route sweep (613) + precise deferred-endpoint backlog (continued tick, 2026-06-02 late night)
Extended the route-sweep harness to multi-segment + config-generated routes (613 vs ~100).
Deep-route sweep: **0 page crashes** — every customer-facing page (incl. all config-driven
FindingsExplorerView/GenericDashboard screens) degrades missing endpoints to a branded
EmptyState, so they are NOT broken, just empty on secondary screens.
- Directly audited all **214 config-driven api-paths** against the live backend WITH the
  `?org_id=` query the real FindingsExplorerView apiFetch sends (corrected a header-vs-query
  methodology false-positive: 97 -> true **66 broken**): 64× 404 (missing/renamed endpoints),
  1× 422 (attack-paths/choke-points needs sources+sinks), 1 honest-503 (cspm/findings — correct).
- Wrote **`docs/deferred_empty_endpoints_2026-06-02.md`** — the precise, route-mapped backlog
  (replaces CLAUDE.md's vague "~12-15 deferred empty-endpoints"). Each needs a per-endpoint
  decision: repoint to an existing endpoint (many engines expose `/summary` not `/stats`), build
  a real stats/list route on an engine that has the data, or **FOUNDER-BLOCKED** on a real data
  source/importer. NOT stubbed (no-fake-data rule); declined a risky batch-repoint that would
  trade honest-empty 404s for 200-but-shape-mismatched data.
- **This is a sustained backend program, partly founder-blocked — recorded + deferred.** Pages
  work (honest-empty), so it is not a customer blocker. Harness improvement committed (75709f0c).

## ADDENDUM 5 — full automated route-sweep + every real failed-API/crash fixed (continued tick, 2026-06-02 late night)
Enhanced the e2e/route-sweep harness (now captures error-boundary + SPA-404 DOM, not just
console/network) and ran it across all top-level routes vs the live app + backend (real auth).
0 crashes/404-DOM. Every REAL failed-API/runtime-crash it flagged is now fixed + live-verified:
- **/brs-executive** 404 (/api/v1/risk/brs/bu/default): the `default` BU sentinel now yields
  honest-empty BRS (engine's documented no-crash contract); explicit unknown BU still 404s.
- **/findings, /cloud-findings, /drift-tracking** crash: null-safe sort comparator
  (localeCompare-on-undefined when a finding lacks the sort field).
- **/issues, /issue-queue, /material-changes** crash: null-safe AgeBadge (getTime-on-undefined
  for findings with no discovered_at) + null-safe discovered_at sort.
- **/hunting** 4×404: added 4 real /api/v1/threat-hunting endpoints (sessions/findings/timeline/
  queries) delegating to the canonical engine; hardened get_all_queries (skip malformed rows);
  fixed 2 latent frontend crashes the real data exposed (PredefinedQueryCard tags.map, TacticBadge
  unknown-tactic). Live: 4 calls 200, 0 console errors.
- **/org-hierarchy** 3×422→404: frontend now sends the required ?org_id= tenant param; backend
  READ endpoints (children/ancestors/effective-policies) return honest-empty [] for unregistered
  nodes (WRITES still raise). Live: 3 calls 200, 0 console errors.
- Required 2 backend restarts (no --reload) to live-verify the new/changed endpoints.
- **Gates after each**: create_app 8335; Beast smoke 756/756; tsc 0; vitest 135/0/53; build ~3.5s.
- **Residual (cosmetic, deferred)**: ~12 routes show dev-only React "missing key" warnings
  (ComplianceDashboard + 5 hub components). All `.map`s are keyed; the keyless source is a
  fragment/array/sub-component that resists static pinpointing, and React 19 omits the component
  stack from console args so the runtime interceptor adds nothing. Zero functional impact,
  stripped from production builds. The pinpointable keyless-Fragment-as-map-child class WAS fixed
  (CodeScanning, AttestationGraphPanel in addendum 4-era commits).

## ADDENDUM 4 — live-browser caught page crashes + nav 404 (continued tick, 2026-06-02 night)
Continued the live-browser gate; surfaced real crashes/404s unit tests miss (they render
components in isolation). 4 verified-local increments:
- **Nav-link audit** (WorkspaceLayout/GlobalSearch vs literal+config-generated routes): the
  main sidebar **Settings button (to=/settings) had no route → 404**. Added /settings →
  /settings/integrations redirect. (24 other flags were false positives — config-generated routes.)
- **Integrations page CRASHED** (error boundary) — Rules-of-Hooks violation: useQuery+useMemo
  then useNavigate+useSyncIntegration+useConfigureIntegration were called AFTER the isLoading/
  isError early returns → hook count changed between renders. Moved all 5 hooks above the returns.
  Live: renders real /api/v1/integrations + /api/v1/webhooks/events (200), 0 console errors.
- **TicketIntegration** (/remediate/tickets) — same hook-after-early-return crash → fixed.
  Found via a static sweep of the class (18 suspects, 16 FPs where the return was inside a
  .map/.filter/helper callback; real ones return JSX from a component guard).
- **Keyless-Fragment-as-map-child key warnings** — CodeScanning (/discover/code) + Attestation
  GraphPanel: a .map returned a keyless `<>` (inner rows keyed, but the Fragment is the list
  child) → `<Fragment key=…>`. Live: /discover/code 0 console errors.
- **Gates after**: create_app 8331; Beast smoke 756/756; tsc 0; vitest 135/0/53; build ~3.5s.
- Residual: ComplianceDashboard's 2 dev-only key warnings (different cause, not pinpointed;
  cosmetic, stripped in prod).

## ADDENDUM 3 — live-browser NO-MOCKS gate caught broken navigation (continued tick, 2026-06-02 evening)
Ran the canonical NO-MOCKS browser gate (Playwright MCP vs the running dev server + backend,
real SCIF auth). Static/test checks had all passed, but the **browser** surfaced a class of
real customer-facing routing bugs (component tests pass because they render components directly,
bypassing the router). 3 verified-local increments:
- **/compliance was 404** — ComplianceDashboard was imported but never given a `<Route>`, and
  ~43 `Navigate to="/compliance"` redirects (the whole Comply nav + mission-control) landed on
  the 404. Wired the route. Live-verified: renders 'Compliance & Governance' (P07), fires real
  /api/v1/compliance-engine/{status,frameworks,gaps} (200).
- **7 more bare consolidated-hub paths 404'd** (/assets /brain /validate /issues /remediate
  /admin /asset-graph) — planned tabbed hubs that were never built; many redirects + direct nav
  hit 404 (/remediate browser-confirmed; 14 redirects). Redirected each to its canonical existing
  real page (no new hubs, no loops). Live-verified /remediate→Exposure Cases, /asset-graph→arch-graph.
- **AttackSimulation** (real 621-LOC BAS page) was imported but never routed = unreachable lost
  feature → wired at /validate/attack-simulation (live: fires /api/v1/mpte/requests?type=attack_
  simulation 200). Removed 3 genuinely-consolidated dead imports (RiskRegister, SLADashboard,
  SecurityChampionsDashboard). Re-audit: 0 broken Navigate targets, 0 imported-but-unrouted.
- **NO-MOCKS spot-check (live, real /api/v1 on mount, 0 mock signatures)**: /executive (20+ calls,
  0 console errors), /compliance, /vendors (no HashiCorp mock), /discover/cloud, /remediate/cases,
  /validate/attack-simulation — all real-data.
- **Gates after**: create_app 8331; Beast smoke 756/756; tsc 0; vitest 135/0/53; build 3.52s.
- Residual (low value): 2 dev-only React missing-key warnings in ComplianceDashboard render
  (cosmetic, stripped in prod; all .map keyed, exact list not pinpointed). Full tabbed-hub
  consolidation for the 7 bare paths remains a design decision.

## ADDENDUM 2 — backend hidden-gate bug sweep (continued tick, 2026-06-02 later)
Found via the same "hidden-red-gate" approach that surfaced the tsc bugs: `ruff check`
was red with genuine runtime bugs that import/boot cleanly but `NameError`/crash on the
code path. 6 verified-local increments:
- **30 F821/F811 fixed**: missing imports (uuid, socket, Any, timedelta×4, Tuple),
  undefined loggers (_logger/logger), undefined thread-local `_tls` (feed_correlator),
  dead shadowed method `get_siem_stats`, duplicate route-handler names renamed (both
  routes kept; 2 were this session's own collisions), `CspmScanResult` TYPE_CHECKING,
  10 llm_guard dead-branch names defined via optional-import+None fallback.
- **5 PLE0704/B018/PLW0127**: bare `raise` outside except (would throw "No active
  exception") → explicit RuntimeError; dead `anomaly.is_anomaly` no-op removed; bare
  `config.data_directories` (allowlist-validation side-effect) made explicit; 2 no-op
  self-assignments removed.
- **B005 real bug**: vendor domain check used `lstrip("https://")` (strips char-SET) →
  mangled `shop.example.com`→`op.example.com`; fixed to `removeprefix` (live-proven).
  B023 dedup union-find closure binding hardened.
- **deduplication root `GET /`** implemented (8 red TDD-spec tests → green): real
  engine-backed summary (cluster/event counts + breakdowns from get_dedup_stats,
  findings from AnalyticsDB.count_findings); test's stale no-auth assumption fixed via
  dependency_overrides (auth stays enforced — SCIF posture).
- **ide_root** batch-403 diagnosed as test pollution (passes 6/6 isolated) → recorded
  as founder-blocked test-infra (cross-module env/auth-cache isolation), not chased.
- **Gates after**: ruff genuine-bug classes (F821/F811/PLE/B005/B006/B023/F823/F706)
  **0**; create_app **8331 routes**; Beast smoke **756/756**; tsc **0**; dedup suite 108/108.

## ADDENDUM — UI test-suite + new-endpoint coverage (continued tick, 2026-06-02 late)
Four more verified-local increments after the "exhausted" mark above:
- **Backend regression coverage** for the 7 org-aggregate engine methods this session wired (SCA org vulns/licenses, chaos observations, incident events/MTTR, SOC alert-queue/snapshots, awareness risk-trend) — `tests/test_new_org_aggregate_methods.py`, 6 tests, real data via engine write-paths (no mocks), asserts honest-empty on unknown org. Previously **zero** coverage. No suite pollution (216 passed w/ smoke files; clean collection).
- **ComplianceDashboard**: stale test asserted 7 hardcoded framework cards "from mock fallback data" on an EMPTY API (failing) → rewrote to real-API-in/honest-empty-out; fixed real empty-org bug (`overallScore = Math.round(sum/0) = NaN` on a fresh-customer KPI → guarded to 0).
- **UI test suite restored 61 fails → 0** across 9 files (was masking whether NO-MOCKS held). 3 test-only classes: prune-orphan `describe.skip` for 11 confirmed-removed pages; stale mock-data → real-data/honest-empty; useQuery/localStorage mount-crash → stubs+waitFor. 5 sonnet agents, each independently verified (only test files touched, no component edits, no re-introduced mocks, no real bugs surfaced).
- **TypeScript type-gate restored 28 → 0 errors** across 8 production components. `vite build` had been GREEN while `tsc -b` was RED (esbuild transpiles without typechecking). All real bugs: wrong API method names that throw at runtime (`networkTopologyApi.listNodes/detectExposure`, `threatModelingApi.listModels/getStrideCategories`, `auditApi.auditFrameworks`), `<EmptyState message=>` dropping text (no such prop → `description`), undefined `arr` helper (ReferenceError in RiskAcceptance), `icon={<El/>}` vs LucideIcon component, an impossible status comparison, etc. 2 sonnet agents, independently verified — no `@ts-ignore`/no `any`-silencing.
- **Gates after**: vitest **135 passed / 0 failed / 53 skipped**; **`tsc -b` 0 errors**; prod build 3.40s; create_app **8330 routes**; Beast smoke **756/756**.

## Autonomous backlog (kick items 1–4): EXHAUSTED
| Item | Status | Evidence |
|------|--------|----------|
| 1. T2 collection health | ✅ DONE | `pytest --collect-only` = **46,896 tests / 0 errors** (was 3) |
| 2. T3 broad-regression triage | ✅ TRIAGED | chunk-1 2056 fails = **test-infra (app-boot>10s timeout) + legacy**, NOT product regressions; details `docs/T3_REGRESSION_TRIAGE_2026-06-02.md` |
| 3. honest-stub sweep | ✅ COMPLETE | 3 real fixes shipped+locked; engines/routers verified no fake-data |
| 4. spec-backfill | ✅ DONE (named groups) | SPEC-018 risk-agg, 019 evidence, 020 council; CTEM/CSPM already 012/013 |

## What shipped this whole session (verified-LIVE, committed)
- **SPEC-016 SCIF stack-fit** (5 increments): WIZ/Prisma/BlackDuck ingest→correlation-brain; closed-loop `/decide`→Jira/ServiceNow/Splunk + ML-DSA-signed append-only evidence; Confluence design-context.
- **SPEC-017 full-pipeline-on-ingest**: gated, non-blocking, air-gap-hard-checked, bounded, rate-limited, observable.
- **GraphRAG→council**: verified already-wired (no redundant build).
- **Tenancy debt 1726 → 0** (16 waves, ~190 routers): every `org_id` default + shadow resolver now canonical.
- **Test health**: T2 0 errors; legacy evidence_chain 14 errors→honest skips.
- **Honest-stub fixes** (the moat-critical ones):
  - cloud-drift `/scan` 500→**honest 503**; deep-code `/analyze` 500→**honest 501**.
  - **evidence `verify_integrity` now does a REAL content re-hash** (was returning `verified:True` for tampered content) + **storage-root allowlist** (anti-spoof). Regression-locked.
- **Specs 018/019/020** backfilled, reconciled to real code (caught + corrected drift).

## Product health (authoritative gates, green)
- `create_app()` boots **8316 routes** (all 3 air-gap modes).
- **Beast smoke 756/756** every run. **T2 collection 0 errors.** `tenancy_lint` **0 violations**.
- No fabricated results in routers/engines (honest 503/501 when unconfigured).

## ── FINAL FOUNDER TASK LIST (only these remain; all need YOU) ──
**A. Ship the work (highest priority)**
1. **GitHub push** — 66 local commits unpushed. Disconnect VPN (DNS hijacks github.com → dead 4.237.22.x) + issue a fresh PAT (`mytoken.txt` is revoked/401), then `gh auth setup-git && git push origin chore/ui-prune-plan-2026-05-24`.

**B. Decisions I won't make autonomously (architecture/semantics)**
2. **Postgres migration approach** — 100+ SQLite DBs → Postgres changes deployment topology; needs your call before I execute.
3. **Test-infra fixture debt** — the broad suite's ~hundreds of "failures" are `create_app` boot (~10.6s) exceeding the default 10s pytest-timeout in function-scoped client fixtures. Approve either a shared/session-scoped app fixture or a higher default timeout, then I'll do the pass (high blast-radius on the test gate, so wants sign-off).
4. **Org-resolution precedence** — `_extract_org_id` (header>query) vs `get_org_id` docstring (query>header) disagree on the tiebreak (JWT always wins; no isolation impact). Pick one order; I'll align both.

**C. External / hardware / accreditation (cannot be done in-repo)**
5. **FIPS-140 CMVP validation** (certified module + lab, 12–18mo).
6. **PIV-CAC smartcard auth** (hardware + PKCS#11 middleware, 4–6mo).
7. **GPU** for the SPEC-003 local-LLM distillation run (path wired; needs your hardware + ≥5k DPO pairs).
8. **Stripe live keys** (billing live path; honest 503 without them today).

**D. Optional next autonomous work (say the word to re-arm a kick)**
9. UI customer-readiness pass (NO-MOCKS rule, Playwright) — not in this session's backend/test/spec scope.
10. Deeper spec-backfill (per-router specs for Augment governance) — low-value, near-infinite.
11. T3 deep regression once (3) is decided (the fixture fix unmasks real signal).

## Loop state
Kick cron retired on this clean exit (backlog exhausted). Re-arm with a new objective (e.g. item 9/11) to resume.

## UPDATE (later 2026-06-02) — UI NO-MOCKS frontier COMPLETE (build-verified)
- Fixed every page serving fabricated data: ComplianceDashboard, AttackSurface, ThreatIntelDashboard,
  api-hooks (MOCK_->EMPTY_). ~700 lines of fabricated UI data deleted. `npm run build` green; full
  `src/` scan CLEAN (no MOCK_/generateMock/sampleData outside tests + generated graphify cache).
- v2/S* (30) pages are composition shells (no hardcoded data); only ApiReference + Pricing are legit-static.
- Backend hardenings verified already-correct: SPEC-018 risk POST org-scoped (no body spoof);
  /convene economic-DoS covered by OrgTierRateLimitMiddleware; evidence verify_integrity real re-hash + storage-root allowlist.
- ~80 local commits now (still unpushed).

### Remaining for FULL UI real-data (founder go-ahead or running-stack needed)
3 honest-empty UI sections can be upgraded to REAL data — endpoints EXIST:
`/api/v1/mitre/coverage` (ThreatIntel MITRE), `/api/v1/audit/compliance/controls` (Compliance controls),
+ a compliance-evidence endpoint. Per CLAUDE.md this wiring MUST be browser-verified (dev server :5173 +
backend :8000 + Playwright MCP). That's the next step — needs the running stack brought up (the 5-min
cron will attempt it; or run it yourself). Until then those sections honestly show empty, never fake.

## UPDATE (2026-06-02 ~10:20) — FOUNDER REPORT: tab clicks fixed across 49 hubs

Founder: "all screens tabs are mostly not usable" (named Secrets Scanner Scanner/Rotation, Supply Chain, Cloud). VERIFIED REAL by browser dogfooding.

**Root cause:** a copy-pasted URL↔tab `useEffect` in 49 hub pages reverted state to the stale URL on every click (`if (isTabKey(urlTab)) setTab(urlTab)` ran on the [tab,params] effect, so a fresh click snapped back to the first tab). Deep-links (`?tab=`) worked; clicks did not. The tab PANELS were already wired to real /api/v1 data — only the switch was broken (so "functions not working" was the unreachable-tab symptom).

**Fix (commit 1ddb957f):** split the one effect into two trigger-keyed effects — URL→state on `[params.toString()]` (deep-link/back-forward) and state→URL on `[tab]` (clicks), with equality guards (no ping-pong). Applied to all 49 hubs (48 via exact-block script + ThreatActorsHub by hand). The 2 other tab hubs (AuditorEvidenceHub, DeveloperSecurityHub) already used the correct URL-derived pattern.

**Browser-verified (real Playwright clicks, not synthetic):** DetectAndRespondHub ITDR→XDR→EDR and SupplyChainHub Security→Vendor Risk all switch active tab + panel content + URL with no revert. All 106 hub panels confirmed real-data-wired (0 stubs).

**Also this session (all committed, build+tsc+smoke 756 green, browser-verified):** AdminUsersPage 401 (missing X-API-Key) → 200 [5710eade]; route-sweep API failures webhooks-out 404 + agentless-scan 404 [bc601386], attack-paths 422 + air-gap-bundles 404 [faf33b58], compliance-frameworks 404 [cb8469c9]; ComplianceDashboard keyless-rows/Unknown-data → rich /compliance/status [c08028f6] (cleared the shared React key warning behind 14 routes). Full route-sweep with real SCIF token: 0 API failures, 0 crashes, 0 console errors across all routes.

## UPDATE (2026-06-02 ~11:30) — Tab-panel sweep: every hub tab now real-data clean

Built a new e2e gate `e2e/tab-panel-sweep.spec.ts` that clicks EVERY tab on all 52
hubs (route-sweep only loads each route's default tab, so broken NON-default panels
were invisible). Ran it with the real SCIF token; it surfaced a systemic class:
**frontend TS interfaces / fetch paths drifted from backend API field names**, plus a
few missing endpoints and bare fetches without auth. All fixed + browser-verified:

Interface/key drift (undefined or duplicate React keys + blank cells):
  • FAIRQuantPanel  scenario.id  → scenario_id            (85364163)
  • PostureScorePanel  component.name → id + component    (85364163)
  • GRCAssessment  control_ref/title empty → control_id/risk_id/framework_id (6c770060)
  • ModelingPipeline  model_id → id                       (6c770060)
  • CyberInsurance  policy.id/claim.id → policy_id/claim_id (2364c180)
  • ContainerImage  ScanRecord remapped to /containers/history shape (2364c180)
  • ZeroTrustPolicy  policy.id → policy_id                (f418ebc7)

Wrong path / missing param / missing auth:
  • posture-trends + program-maturity 422 → pass org_id   (9ba5ca75)
  • threat-response/playbooks 404 → /playbooks/performance (f418ebc7)
  • knowledge-graph/ 404 → /export + graph.nodes normalise (f418ebc7)
  • integrations/status 404 → /integrations/health        (2364c180)
  • compliance-frameworks/agentless/air-gap/webhooks-out/attack-paths 404/422 (earlier batch)
  • /discover/architect code-to-runtime + knowledge-graph 401 → bare fetch()
    now sends auth headers                                  (26e35435)

Net-new REAL backend endpoints (wired to existing engines, NO MOCKS):
  • GET/PUT /api/v1/policy-enforcement/hooks/policy + GET /hooks/status
    → DevSecOpsEngine.get_active_hook_policy / apply_hook_policy (81cbc484)
  • GET /api/v1/autofix/fixes → AutoFixEngine.list_fixes()+to_dict()
    (curl-verified real SQL-injection fix data)             (6edccf50)

create_app boots 8339 routes. Beast smoke 756 (lone fail = known
test_100_findings_ingest flake, passes isolated ~0.6s). Final tab-panel sweep: 0
hubs with issues across all 52 hubs × every tab. All 106 hub panels are real-data
wired (audited). Deferred (none — every sweep finding resolved this session).

## UPDATE (2026-06-02 ~12:32) — Tab-panel sweep VERIFIED COMPLETE (52/52, 184 tabs)

Correction to the earlier "all 52 clean" note: those runs had TIMED OUT at
Playwright's 600s globalTimeout (and one HUNG on a real InvestmentPanel crash), so
coverage was partial. Fixed the harness (dialog auto-dismiss, per-hub progress log,
700ms default pacing) and the InvestmentPanel crash, then ran a genuinely complete
sweep: **52 hubs, 184 tabs clicked, 1 issue found** (/remediate/exceptions Workflow
request_id→id keyless), now fixed + browser-verified. The Investment & ROI tab crash
(fmt$ .toFixed on undefined → RouteErrorBoundary blanked the page) was a real
customer-facing defect the sweep's "hang" had been masking — also fixed (3e73969e).

RESULT: every one of the 52 hubs × every tab fires real /api/v1 calls (or honest
EmptyState) with 0 API failures, 0 crashes, 0 React key warnings. Commits this
campaign: 3e73969e (Investment crash), cb2231f3 (Exception workflow), 489b37f6 +
fcc2c804 (sweep hardening), plus the earlier panel/endpoint batch.

## UPDATE (2026-06-02 ~13:50) — Backend bulk-corruption sweep (~107 real runtime 500s fixed)

A fresh T3 test slice (router + engine, run PER-FILE in isolation to filter FastAPI
TestClient cross-file pollution — the batch run is ~28% false-fail) exposed a repo-wide
bulk stray-auto-edit corruption that the smoke gate entirely missed (only fails at
request/runtime). Two systemic classes, now SWEPT CLEAN (AST + bidirectional grep):

1. **95 `org_id: str = Depends(get_org_id)` Pydantic FIELD defaults across 41 routers**
   → every affected POST 500'd on omitted org_id. AST-targeted fix → `= "default"`. (64bf56dc)
2. **12 SQL keyword-concatenation runtime errors** (table/col glued to FROM/WHERE/SET):
   log_management, security_training, api_abuse_detector, security_registry,
   deduplication(core,×3), anomaly_ml, vulnerability_analytics, threat_hunting,
   trustgraph/maintenance. (c7ab0b91, 53eaf240)
Plus: gap_router /changes/sla-impact ImportError 500 (real accessors added, 9e26eccd),
mlops /analyze KeyError 500, anomaly_ml `.anomaly_id`→`.id` AttributeError, + 4 test-rot.

Verified per-file (post-fix, isolation): questionnaire 58, security_registry 62,
api_abuse 58, deduplication 36, log_management 40, anomaly_ml 29, vulnerability_analytics
57, threat_hunting 67, intelligent_security 34, gap 31, mlops 14. create_app 8339; smoke 756.

Detection recipe (for the test-infra follow-up) + remaining founder-blocked test-infra
backlog (~25 connector-router auth-fixture files, checkov/env/missing-table fixtures,
stale stub-assertions) are in docs/router_test_triage_2026-06-02.md.

---

## Addendum 2026-06-03 — UI NO-MOCKS verified clean + lazy-import 500 swept

- **monte-carlo /cvss 500 fixed** (commit 5f74ee8d): bare lazy `from core.monte_carlo import simulate_risk_for_cve` (never existed) → repointed to real `MonteCarloRiskEngine.simulate_from_cvss().to_dict()`. **Live-verified POST /api/v1/risk/simulate/cvss → 200** with real output (mean_annual_loss 4.5M, VaR). Refined try/except-aware AST scan proved this was the *only* real bare-lazy-import 500 (gap_router already fixed); the other 20 candidates are intentional graceful fallbacks.
- **UI NO-MOCKS pass (item A) VERIFIED CLEAN**: 290 pages, 0 `src/data|fixtures|mocks` dirs, 0 fixture imports, 0 MOCK_/lorem/sample literals. 7 "static" candidates triaged → 3 legit marketing pages, 4 data-pages all fetch real `/api/v1` via typed clients. `npm run build` green 3.76s.
- **SQL-concat class confirmed FULLY swept**: VALUES/JOIN/ORDER BY/LIMIT/INSERT adjacency scan clean (FTS5 `table(cols)` is valid syntax, not a bug).
- **Three static-findable backend bug classes all swept clean**: Depends-in-Pydantic (95), SQL-concat (12), bare-lazy-import (2). ~110 real runtime-500s total this campaign.
- **Terminal state**: UI no-mocks-clean; all statically-findable real-bug classes swept; remaining work is founder-blocked test-infra (auth fixtures) proven to hide zero product bugs. Gates green (create_app 8339, smoke 756, build 3.76s). Push blocked — all committed locally.

---

## Addendum 2026-06-03 (tick 2) — live endpoint-health sweep + routing dead-ends

Method: live-curled 183 UI-documented GET endpoints + Playwright browser nav (real /api/v1
on mount, no self-reports). Found + fixed (all build-green 3.6s, smoke 755/756 known-flake,
browser/curl-verified):

- **hunting/sessions 500** — NULL-id legacy rows → pydantic ValidationError; list_sessions now
  skips malformed rows (+regression test). Live 200. (6b3cf2be)
- **GET /api/v1/local-store/status** — was 404 → page ErrorState; added real disk-scan endpoint;
  page renders real status. (97cbc02e)
- **5 shadowed pages un-shadowed** (App.tsx duplicate-route bug: a never-built "/admin?tab= hero"
  redirect declared before the real same-path page → page unreachable, dead-ended at audit-log):
  /capacity-planning /ai/mcp-registry /skills /system-health /organizations. (40924ea0)
- **3 wrong-endpoint pages repointed**: CapacityPlanning /plans+/stats→/teams+/summary;
  ContainerSecurity /summary→/stats; OrgHierarchyExplorer /organizations→/orgs (+array normalize,
  browser-verified 273 real rows). (40924ea0)
- **14 dead-end /admin?tab= redirects repointed** to real pages (airgap→AirGapHub browser-confirmed,
  fips-status→/fips-compliance, tokens→/admin/api-keys, integrations→/integrations, etc.). (86a468e9)

**PRODUCT-BLOCKED follow-ups (documented, not fixed — need founder direction):**
- **/brain?tab= dead-end class (23 routes)**: /ai/brain, /ai/consensus, /verification, /brain/mpte,
  /brain/fail, /mitre, /attack-chains, /ai-governance, /code-intel, etc. ALL land on /brain/neural
  (BrainVisualization, 0 tabs) — the tabbed Brain hero was never built and no standalone pages exist
  for pipeline/consensus/lab/ml/predictions/mpte/fail. Needs a Brain-hero build or content relocation.
- **/billing**: no internal billing page exists (only public PricingPage) — real product gap.
- Some **/compliance?tab=** redirects may share the pattern (ComplianceDashboard tab-read unconfirmed).

---

## Addendum 2026-06-03 (tick 3) — high-fidelity real-call sweep + ContainerSecurity panels

- **High-fidelity real-call endpoint sweep**: extracted 390 ACTUAL apiFetch/api.get string-literal
  GET paths from page source (vs tick-2's header-doc paths) + curled all vs live backend.
  **0 5xx** (backend runtime-500 frontier fully clean — hunting was the last), **0 hard-broken-on-mount
  pages** (OrgHierarchyExplorer-class exhausted). 23 404s all triaged: POST action endpoints,
  graceful allSettled degraders, or param-needing template literals.
- **MCPToolRegistry** dead fallback fixed: /api/v1/agents (404) → /api/v1/copilot/agents (200).
- **ContainerSecurity** 3 dead panels wired to real backends (page called non-existent
  /container-security/{k8s-posture,policy-violations,registries}; real data lives under
  /container-posture/clusters+findings and /container-registry-security/allowlist). Browser-verified:
  posture cards show real scores (100%/86% from 22 clusters), violations populated, 0 console errors.
- **brain?tab= dead-end class (23)** verified as legacy bookmark aliases NOT in the live nav (low
  customer impact) + core tabs product-blocked (no destination hero). Documented, not mass-touched.

UI customer-readiness frontier (this session, 3 ticks): NO-MOCKS clean + 0 runtime-5xx + 0 hard-broken
pages + admin-routing dead-ends repointed + 4 wrong-path pages (org/capacity/container/mcp) wired to
real backends — all browser/curl-verified. Remaining: product-blocked (brain hero, /billing page) +
founder-blocked. Build green; backend smoke 755/756 (known flake) from tick 2 holds (tick 3 UI-only).

---

## Addendum 2026-06-03 (tick 4) — typed-client coverage sweep + 503-semantics audit

- **Typed-client coverage sweep (the gap)**: prior sweeps covered page-header docs + apiFetch
  string literals; this swept the 401 /api/v1 paths DEFINED in src/lib/api*.ts typed clients
  (apiKeysApi/sbomApi/etc.) that pages call indirectly. 184 ok(2xx/422), **1 real 5xx**.
- **sbom/export false-503 → 200 empty-state** (gap_router.py): GET /api/v1/sbom/export raised
  503 Service Unavailable when no SBOM was persisted yet — wrong semantic (trips health
  checks/LB alarms/retries, misleads external consumers). Now returns 200 + empty payload
  (component_count=0, sbom=null, generate hint). Live-verified. (0 UI callers today, but a real
  ops/correctness bug.)
- **503-semantics audit**: scanned all 302 router 503-raises — the other 301 are CORRECT
  (engine/module/registry "not available" = genuine dependency-down, + the connector honest-stub
  "NO MOCKS → 503 when env unset" pattern). No systematic false-503 class; sbom/export was unique.

**Frontier fully verified clean across 4 call-path dimensions** (page-header docs, apiFetch literals,
typed-client lib defs, 503 semantics): 0 runtime-5xx, 0 hard-broken pages, correct status semantics.
Remaining UI work product-blocked (Brain hero, /billing page) + founder-blocked. smoke 755/756 (flake).

---

## Addendum 2026-06-03 (tick 5) — red-team path-traversal hardening (item B)

- **Typed-client coverage sweep** (401 lib paths) → fixed `GET /api/v1/sbom/export` false-503
  → 200 empty-state (was Service-Unavailable for a no-data-yet state; trips health checks).
- **Storage-root allowlist guard** (local_file_store_engine._store_dir, the chokepoint for
  save/config/clear/lock): caller-supplied repo_path via /api/v1/local-store/* was unvalidated →
  arbitrary JSON write + subtree DELETE (clear_store) to /etc, ~/.ssh, / etc. Now (1) always
  rejects filesystem-root + system dirs (literal+symlink-resolved), (2) strict
  FIXOPS_LOCAL_STORE_ALLOWED_ROOTS allowlist when set, (3) rejects empty. +6 regression tests;
  clear() router maps ValueError→400.
- **Airgap sneakernet/apply-update**: closed 4 unguarded operator paths (export payload_files READ
  + output_path WRITE; import package_path READ + extract_dir WRITE/zip-slip; apply-update
  package_path READ) — wrapped in the existing _guard_airgap_path() (null-byte/.. + allowlist).
- Verified: traversal/null-byte/outside-allowlist all rejected→400. Beast smoke **756/756**.
  create_app 8340. (2 TestWebhookDispatchBlocked batch failures are pre-existing test-pollution —
  pass in isolation with edits present, verified via stash A/B — founder-blocked test-infra.)

Item B (red-team hardenings: storage-root allowlists) — DONE for the two API-reachable
write/delete path surfaces (local-store, airgap). UI frontier remains verified-clean (4 dims).
Remaining: product-blocked (Brain hero, /billing) + founder-blocked (push, test-infra, FIPS, etc.).

---

## Addendum 2026-06-03 (tick 6) — red-team rate-limits (item B cont'd)

- **Auth rate-limit coverage audit + gap fix**: /api/v1/auth/* is exempt from the global
  RateLimitMiddleware (auth carries its own purpose-built limiters via _rl_enforce). Audited
  every auth POST: login(10/min)+per-email lockout, signup(5), forgot-password(5),
  reset-password(10), dev-token(10) all guarded — but **/refresh had NONE**. Since /refresh
  mints access tokens from a refresh token (runs jwt.decode on caller input), it was an
  unbounded grind/DoS surface. Added `_rl_enforce(auth:refresh, 30/min)` before any crypto.
  +1 regression test (45 rapid calls → ≥1 429, re-enabling the conftest-disabled limiter).
  keys/disposable-token/sso are Depends(api_key_auth)-gated (acceptable). Beast smoke 756/756.

Item B (red-team hardenings) status: storage-root allowlists (local-store + airgap, tick 5)
+ rate-limits (auth/refresh gap, tick 6) — DONE for the identified high-value surfaces.
Frontier: UI verified-clean (4 call-path dims); backend runtime+status+path+rate-limit hardened.
Remaining: product-blocked (Brain hero, /billing) + founder-blocked (push, test-infra, FIPS, etc.).

---

## Addendum 2026-06-03 (tick 7) — dispatch-time SSRF (DNS-rebinding) hardening (item B cont'd)

- **DNS-rebinding SSRF closed on BOTH outbound-webhook routers**: both validated the target
  URL against private/reserved/metadata IPs ONLY at /subscribe, then POSTed the stored URL at
  dispatch without re-resolving — a TOCTOU window (register a public host, later rebind it to
  169.254.169.254 / 127.0.0.1, dispatch exfils the HMAC-signed payload internally). Fix: re-run
  the existing SSRF validator immediately before the POST in each delivery loop
  (outbound_webhooks_router.dispatch_outbound + webhook_subscriptions_router._deliver_webhook);
  blocked → marked failed → existing failure-count auto-disable. +1 regression test (metadata-IP
  sub → requests.post NOT called). Beast smoke 756/756; 49 webhook + 163 adjacent tests green.

Item B (red-team hardenings) cumulative: storage-root allowlists (tick 5) + auth/refresh
rate-limit (tick 6) + dispatch-time SSRF/DNS-rebinding (tick 7). The three classic
server-side attack surfaces (path-traversal, rate-limit/brute-force, SSRF) are now hardened
on the API-reachable write/delete/fetch paths. UI frontier remains verified-clean (4 dims).
Remaining: product-blocked (Brain hero, /billing) + founder-blocked (push, test-infra, FIPS, etc.).

---

## Addendum 2026-06-03 (tick 8) — red-team audit complete (item B closed)

Completed a 6-class server-side attack-surface audit (artifact: `docs/red_team_audit_2026-06-03.md`):
- **VERIFIED CLEAN** (no real vuln — only the scanner's own detection-patterns/templates matched):
  insecure deserialization (real code uses `yaml.safe_load`; `joblib.load` loads only server-internal
  model artifacts, not user paths), XXE, command-injection (no real `shell=True`; scanners invoked
  via arg lists).
- **INTENTIONAL non-fix**: connector `base_url` SSRF is deliberately NOT blocked — on-prem/air-gapped
  connectors legitimately target internal RFC-1918 infra (self-hosted Jira/ES), unlike outbound
  webhooks which are exfil channels (correctly blocked). Admin/auth-gated; documented design choice.

Item B (red-team hardenings) is now **closed**: 3 classes fixed (path-traversal tick 5, rate-limit
tick 6, SSRF/DNS-rebinding tick 7) + 3 verified-clean (this tick) + 1 documented by-design. No new
code vuln remains on the API-reachable surface.

**Session-wide frontier status:** UI verified-clean (4 call-path dims, NO-MOCKS, 0 runtime-5xx,
0 hard-broken pages); backend hardened+verified across runtime, status-semantics, path-traversal,
rate-limits, SSRF, deserialization, XXE, command-injection. Beast smoke 756/756. All committed
locally. Remaining work is product-blocked (Brain hero, /billing) or founder-blocked (push,
test-infra fixtures, Postgres, FIPS, PIV, GPU, Stripe) — nothing buildable-and-unblocked remains.

---

## Addendum 2026-06-03 (tick 9) — T3 triage: auth-fixture-rot cluster fixed (item C)

- **T2 collection health PASS**: 46,931 tests collected, 0 errors (whole suite imports clean).
- **T3 [a-f] router slice triaged**: 30-file batch = 272 failed/83 passed, but isolation proved
  ZERO product bugs — failures are (a) cross-file TestClient pollution (braintrust: 22/22 pass
  isolated) and (b) auth-fixture rot.
- **Auth-fixture-rot cluster fixed (24 files, ~314 tests)**: connector/scanner router tests that
  build an isolated FastAPI()+include_router(router) where the router enforces router-level
  Depends(api_key_auth), but set no token → every data endpoint 401'd before the handler. Added
  `app.dependency_overrides[api_key_auth]` (standard pattern, same as the passing braintrust) so
  the tests exercise real router/engine behaviour. bitbucket(14) + 23 connector files now green;
  **the routers were all correct — 0 product bugs**, the connector routers are now actually tested
  (were 401-stubbed). Test-only changes; smoke 178/178 (subset) green, product code untouched.
- **Recorded (founder-blocked test-infra, not fixed)**: ws_events_router (10 fails = stale
  reference to the removed `_EXPECTED_TOKENS` global → needs a WS-auth-test rewrite); nuclei/zap
  use a different app-build helper (patcher skipped).

Frontier: UI verified-clean (4 dims); backend hardened+verified (runtime/status/path/rate/SSRF/
deser/XXE/cmdi); T3 connector-router slice now actually-tested + triaged (0 product bugs). Beast
smoke green. Remaining: product-blocked (Brain hero, /billing) + founder-blocked (push, deeper
test-infra like ws_events/Postgres, FIPS, PIV, GPU, Stripe).
