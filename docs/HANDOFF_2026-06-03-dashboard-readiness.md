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

## Tick 4 (same day) — clean page-gap fixes
- **ThreatHunting hunting/iocs → /threat-intel/iocs** (`b1f0657b`) — real endpoint (verified 200 `{iocs:[...]}`).
- **collaboration/activity** (`3fc99ce4`) — added `EntityType.WAR_ROOM/INCIDENT` + `ActivityType.CREATED/RESOLVED`, repointed UI → `/activities`; POST verified 200 `recorded` (real persistence, was dead).
- **local-store/init** — confirmed NOT a bug (page is intentionally 501-tolerant).

## REMAINING 4 page-gaps — all feature-build w/ design (pages handle absence gracefully; LOW impact). Real-backing notes for next tick:
1. **threat-intel/block-iocs** (POST `{ioc_ids}`, fire-and-forget/optimistic) — DESIGN-BLOCKED: `/threat-intel/iocs` reads `feodo_c2_cache` which has NO stable `id` (keyed by `ip_address`) → the page's `iocs.map(i=>i.id)` sends `undefined`s. A real block-by-id needs an IOC-identity model (add ids to the feed) OR redesign to block-by-value. Real blocklist target exists when resolved: `ip_reputation_engine.add_to_blocklist(org_id, ip, reason)`. Page is optimistic (handles absence).
2. **llm/estimate** (POST `{prompt,model,max_output_tokens}`) — INVESTIGATED: `ai_governance_engine.estimate_llm_cost` exists but is rules/TIER-based (`_TIER_COST_PER_1M_USD` is per-tier, NOT per-model); `openrouter_provider` cost is an explicit `# Placeholder`. NO real per-MODEL price table exists. Blocked on real per-model pricing data (founder/config input) — do NOT guess model prices (fabrication on a cost-estimate feature). Page handles absence (shows err).
3. **skills/install** (POST) — `/skills/uninstall` exists (wave_c_router, loader.skills + skills_dir); install needs an air-gap install-SOURCE (bundled-skill catalog) design.
4. **hunting/coverage** — DONE (tick116): repointed to `/mitre-attack-coverage/coverage` + transform `tactic_breakdown` DICT → `[{name,covered}]` array (shape from engine code). Real data.

## ⚠️ DUPLICATE ROUTER FILES gotcha (found tick118 — important for ALL future route work)
Some routers exist in MULTIPLE suite dirs (`suite-attack/api/`, `suite-core/api/`, `suite-api/apps/api/`).
`app.py` mounts many via `from api.X import router` — which resolves (via sitecustomize sys.path) to
the **suite-attack/ or suite-core/** copy, NOT `suite-api/apps/api/`. ALWAYS confirm the mounted file at
runtime before editing: `python -c "import api.<name> as m; print(m.__file__)"`. tick109's secrets/cases
shadow-fix initially edited the wrong (apps.api) duplicates; the mounted suite-attack/suite-core copies
were fixed in tick118 (verified). This is part of the duplicate-prefix/duplicate-file debt
(see memory `project_duplicate_routes_2026-06-03`).

## Page-gap frontier status (tick113-118)
DONE: hunting/iocs→threat-intel/iocs, collaboration/activity (enum+/activities), hunting/coverage
(→mitre-attack-coverage + transform), vendor-risk/assessments+risk-domains, secrets/cases shadow-fix
on mounted files. CONFIRMED-NOT-A-BUG: local-store/init (501-tolerant). BLOCKED (3): llm/estimate
(no per-model pricing — founder data), threat-intel/block-iocs (no stable IOC id — model redesign),
skills/install (air-gap install-source design).

## FRONTIER STATUS (end of 2026-06-03 multi-tick session — ~22 commits)
- **UI NO-MOCKS (item A): COMPLETE + verified** — no fixtures/fabrication; all pages fire real /api/v1; live Playwright-confirmed real tenant data.
- **Dashboard + page endpoints: COMPLETE** — all 208 GenericDashboard/FindingsExplorer endpoints resolve; broad page sweep 339/348 routed; remaining 9 fixed or triaged.
- **Route-shadowing bug class: VERIFIED CLEAN codebase-wide** (tick119: all 4 remaining candidates false positives; 15+ revived earlier).
- **Hardenings (item B): no gap** — all 22 specs IMPLEMENTED/BACKFILL (egress-guard, crypto, airgap, tenancy all done).
- **T3 (item C): healthy** — hardening slice 133/134; lone failure = stale-:8000 env artifact (current code all 200).

### Remaining = founder-blocked / architectural-epic only (NOT in-context buildable):
- 3 page-gaps: llm/estimate (per-model pricing data), threat-intel/block-iocs (IOC-id model), skills/install (air-gap install-source).
- Restart the stale dev :8000 server (env).
- Duplicate-prefix/duplicate-router-file consolidation (architectural epic; see tick118 gotcha + memory project_duplicate_routes_2026-06-03).

## (B) RED-TEAM HARDENING SWEEP (tick123-127) — 4 real arbitrary-file-read defenses + rate-limit verified
The "exhaustion" calls were premature: a storage-root audit of path-handling engines found 4 real
arbitrary-file-read vulns (caller-supplied root_path/file_path → os.listdir/rglob/read_text with
file-within-root containment but NO bound on the root itself → read /etc/passwd, ~/.ssh, secrets):
- **ide_backend_engine** (build_repo_tree/get_file_content) — gated (GAP-014). FIXED tick123.
- **deep_code_analysis_engine** (analyze_repo) — gated. FIXED tick124.
- **DLP /scan-file** (dlp_engine.scan_file) — **LIVE/mounted, info-disclosure** (returns matched sensitive content). FIXED tick126.
- **secrets_manager** (scan_filesystem/scan_git_history via mounted secrets-scanner /scan) — **LIVE/mounted, secrets disclosure**. FIXED tick127.
Each: per-engine storage-root allowlist (FIXOPS_<X>_ALLOWED_ROOTS env + tempdir/fleet defaults),
verified /etc blocked + tmp works + tests green + Beast 756/756.
Already-covered: local_file_store (FIXOPS_LOCAL_STORE_ALLOWED_ROOTS), evidence_chain (is_relative_to).
Safe (content-based, no FS read): secret_scanner_router /scan.
Rate-limits: VERIFIED live (260 reqs → 25×429; global RateLimitMiddleware + auth brute-force guard).
**LIVE arbitrary-file-read API surface now fully closed.**

### tick128 — shared util + shell-out scanners DONE:
- Created **`core/storage_root_guard.py`** (reusable `assert_path_allowed`); default scratch = tempdir+/tmp+/private/tmp + fleet, blocks /etc,/home,/root.
- Guarded **semgrep/bandit/checkov/gitleaks** `queue_scan` (FIXOPS_SCANNER_ALLOWED_ROOTS) — shell-out scanners on caller target_path. All block /etc; tests green.
- Audited safe: secret_scanner (content-based), malware_detector/sast_engine (content dicts), error_audit (fixed internal dirs), ide_router (content).
- **8 path-handling engines now guarded** (4 native-read tick123-127 + 4 shell-out tick128); local_file_store + evidence_chain pre-existing.

### tick129 — STORAGE-ROOT FRONTIER COMPLETE:
- Guarded the last 3: config_benchmark + compliance_scanner (mounted shell-out checkov, target_path) + function_reachability (gated, 4 parse methods, root_path). security_dependency_mapping audited safe (no FS read).
- **11 path-handling engines now guarded**: DLP + secrets_manager (LIVE-fixed), ide_backend + deep_code + function_reachability (gated), semgrep + bandit + checkov + gitleaks + config_benchmark + compliance_scanner (shell-out) — all via FIXOPS_*_ALLOWED_ROOTS. Plus local_file_store + evidence_chain (pre-existing). Rate-limits verified live.
- **(B) red-team hardening frontier: DONE.** All caller-supplied filesystem paths are allowlist-confined; all arbitrary-file-read surfaces (live + gated + shell-out) closed.

### Remaining (low priority, optional):
- DRY migration of the 4 native-read per-engine copies onto core/storage_root_guard.py: **DECIDED AGAINST** (tick130). The shared util's default is /tmp-inclusive (scanner test-friendliness), but DLP + secrets_manager (LIVE high-severity raw-read) intentionally use a tighter default (gettempdir+fleet, no bare /tmp). Migrating would broaden their allowlist = minor security regression. The per-engine "duplication" is intentional per-surface tuning. Leave as-is.

### (B) egress / SSRF posture (tick130):
- 145 outbound-fetch engines; SPEC-005 socket egress guard covers all BUT is opt-in (FIXOPS_AIRGAP_MODE=enforced; OFF by default). Added a fail-loud startup WARNING when not enforced.
- **FOUNDER DECISION**: make enforced-airgap the fail-secure DEFAULT (ALDECI is on-prem/airgap per memory). Blast radius: blocks outbound LLM/feeds/connectors unless explicitly opted out — needs founder sign-off on the deployment-mode default + how connected-mode features opt out.

## (B) RED-TEAM INJECTION/RCE SWEEP (tick131) — comprehensive, verified
- **Command injection**: CLEAN — no real `shell=True`/`os.system`; scanner engines (semgrep/bandit/checkov/gitleaks/trivy) use argv lists with target_path as a discrete arg.
- **Unsafe deserialization**: FIXED — bn_lr + zero_gravity pickle loads hash-verify a `.sha256` sidecar, but the SAVE paths never wrote it → verification was DEAD CODE (false tamper-protection). Both save paths now write the sidecar; tampered model files are rejected (verified).
- **XXE**: CLEAN — real XML parsers (SARIF scanner_parsers, SAML sso_provider, auth_router) use `defusedxml`; no raw etree on input.
- **JWT/auth** (tick132): CLEAN — every `jwt.decode` specifies `algorithms=[...]`, requires exp/iat/sub, verifies signature (sso adds audience+iss); no alg=none / verify_signature=False.
- **Secrets-in-logs** (tick132): CLEAN — 27 candidate log lines emit metadata/status/lengths/str(exc), not secret values (deliberate `# nosemgrep` annotations). Minor low-sev obs: auth_router:1314 logs the user's own email in a password-reset error (PII-in-log, not fixed).
- These verified-negatives + the storage-root/rate-limit/egress work = a thorough red-team pass; the evidence is exactly what a SCIF procurement scanner checks.

### RED-TEAM FRONTIER STATUS: comprehensively audited (OWASP-class complete).
Classes covered — storage-root/path-traversal (FIXED 11 engines), command-injection (clean), unsafe-deserialization (FIXED pickle integrity), XXE (clean/defusedxml), JWT/auth (clean), secrets-in-logs (clean), CORS (clean/env-driven/no-wildcard), security-headers (clean — CSP/HSTS/COOP/CORP/X-Frame/etc all set), rate-limits (verified live), egress/SSRF (fail-loud warning + founder fail-secure-default decision). 2-3 real gaps found+fixed; all subsequent audit angles return clean — the codebase is well-hardened. Further security work needs a founder decision (fail-secure airgap default) or a fundamentally novel angle.

## EventBus correctness fixes (tick136-137) — RESOLVED (was a deferred "large pass")
- **GC-dropped events FIXED**: emit() + ResponseInterceptorMiddleware used bare `asyncio.ensure_future` (weakly held) → tasks could be garbage-collected before running = silently dropped TrustGraph events. Added `EventBus._spawn` (instance `_bg_tasks` + done-callback discard) + module `_track_bg_task`. Bounded fix (one method + one helper), NOT the 100s-of-sites change I'd feared.
- **Handler-coverage FIXED**: 18/29 declared event types had no default handler → emit() queued them forever; `evidence.collected` + `threat.detected` were actually emitted (silent queue bloat). Added generic drain-ack + `setdefault` loop keeping `_DEFAULT_HANDLERS` in lockstep with `ALL_EVENT_TYPES`.
- **Real correlation for the 2 emitted types (tick138-139)**: `threat.detected` (GNN attack paths, finding-shaped) → `_handle_finding_created`; `evidence.collected` → new `TrustGraphBackbone.index_evidence` (Evidence node + `supports`→control + `part_of`→framework edges = SPEC-019 chain-of-custody). Both now index into TrustGraph instead of drain-acking. (16 remaining drain-ack types are declared-but-unemitted future types — correct.)
- **Bonus**: this also resolved the tick134 brain_pipeline `TestEdgeCases` capture flake (now 7/7) — same root cause.

## Architect decision (tick141): TrustGraph correlation-event allowlist scope
116 distinct event-type strings are emitted across the codebase; only 29 are in `ALL_EVENT_TYPES`
(the bus's curated correlation allowlist) — the other 110 are recorded as dropped. This is a
deliberate design (curated correlation set + best-effort `engine.action` telemetry via `_emit_event`,
metric-tracked, no crash/data-loss), NOT a bug. DECISION NEEDED: which granular engine events
(e.g. `self_scan.completed`, `pipeline_orchestrator.finding_processed`, `vendor_risk.assessed`)
should be promoted to canonical TrustGraph correlation vs remain telemetry. Mass-promotion would
flood the graph or just drain-ack; per-event correlation handlers need design. Architect/founder call.

## Founder-blocked (record + move on)
push, Postgres, test-infra fixture, org-precedence, FIPS, PIV, GPU, Stripe.

---

## NO-MOCKS UI sweep (tick140–144, 2026-06-03 — appended)

**Outcome:** 3 genuine NO-MOCKS violations found + fixed + browser-verified; UI confirmed clean.

The CLAUDE.md "every page fires a real /api/v1 call on mount, no fixtures" rule had
3 dashboards that *looked* wired (they had a fetch) but rendered hardcoded module
fixtures while ignoring (or discarding) the API response. A plain `MOCK_` grep missed
them because the arrays were named plainly (`reviews`, `accounts`, `EVENTS`).

| Page | Was | Now | Commit |
|------|-----|-----|--------|
| `ArchReviewDashboard` | 3 mock arrays (rev-001/Alice Chen/JWTValidator) rendered; liveReviews/liveFindings set-but-unused | live /reviews+/summary+/control-gaps + per-review detail fan-out; real POST add/complete; EmptyStates | `f3e13a11` |
| `IdentityLifecycleDashboard` | 3 mock arrays; loadData did `void d`; frozen `daysSince(2026-04-16)`; no-op buttons | live /accounts+/orphans+/summary + per-account fan-out (active_entitlements+events); real Date.now(); all lifecycle buttons real POSTs | `0f50bee7` |
| `ComplianceCalendar` | EVENTS fixture rendered; calEvents set-but-unused; /overdue discarded; pinned April-2026 calendar | live /upcoming+/overdue+/reminders.due+/summary merged; real current month; real POST add | `2b7b10ef` |

**Verification (all live, not self-report):**
- TestClient on fresh `create_app()`: full CRUD on all 3 routers returns 200 with response
  keys matching every render reference (note: arch detail nests `findings`/`controls`;
  identity detail key is `active_entitlements` not `entitlements`; calendar field is `owner`).
- `npm run build` green after each (3.7–4.1s).
- Playwright MCP (vite:5173 + api:8000): each page fires its real /api/v1 calls (all 200)
  on mount with **zero** mock signatures in the DOM; compliance calendar shows the real
  current month (June 2026). Browser proof commit `1b3ddf9d`.
- Exhaustive sweep proving no other violations: 0 pure-static feature pages, 0 lowercase
  module data-arrays in render, 0 fetch-then-discard, 0 fallback-to-mock (`data || CONST`);
  remaining `MOCK_`/`example.com` hits are form placeholders + editor/tester defaults (legit).
- Beast smoke 756/756 green (backend untouched).

**Open (founder-blocked, unchanged):** push (VPN DNS + revoked PAT), org-precedence,
TrustGraph correlation-allowlist scope, duplicate-prefix consolidation epic, FIPS/PIV/GPU/Stripe.

### NO-MOCKS sweep — round 2 (tick146–147, components + deep variants)

A second sweep targeted patterns the first round structurally couldn't see:
in-component (not module-level) data arrays in files that DO call an API, and
hub child components. Found + fixed 2 more:

| Page | Was | Now | Commit |
|------|-----|-----|--------|
| `mission-control/ThreatIntelDashboard` | hardcoded `THREAT_ACTORS` (APT28/REvil + fabricated campaigns) rendered by child `ThreatActorProfiles`; **3 endpoint bugs**: CVEs hit `/cve/search` (dict→always empty), IOCs hit `/threat-intel/actors` (wrong) never unwrapped | live `/threat-intel/{cves/recent,actors,iocs}` normalized onto view models; actors passed as prop; EmptyState | `b8a4cf58` |
| `ai/CopilotDashboard` | hardcoded "Linked Findings" chips `[CVE-2024-1234, FIND-0042, FIND-0078]` | branded EmptyState (no conversation-linked-findings source exists); page already fires real `/api/v1/agents` | `f725213e` |

Browser-verified ThreatIntelDashboard live: all 3 corrected endpoints 200 on
mount, real actors render (APT29/APT28/Lazarus/Cozy Bear/FIN7), old fixture gone,
0 console errors (caught+fixed a ReferenceError — `actors` state was in the main
component but rendered in child `ThreatActorProfiles`; passed as a prop).

Cleared as legit in the deep sweep: hub `TABS`/`COLS`/`TIERS` configs,
`BinaryFingerprintPanel` (uses typed `binaryFpApi.stats()` + EmptyState),
`RiskOverview.impactAreas` (values from the `ov` query), MITRE technique catalogs,
input placeholders, `"CVE-0000"` sentinel fallbacks, editor/tester default inputs.

**Session NO-MOCKS total: 5 dashboards made real** (ArchReview, IdentityLifecycle,
ComplianceCalendar, ThreatIntelDashboard, CopilotDashboard) + rate-limit coverage
confirmed already-global (no router gap).

### Mission-control / executive suite — NO-MOCKS verified clean (tick149)

The highest customer/investor-visibility surface audited end-to-end. All active
(non-redirect) routes confirmed firing real `/api/v1` calls on mount with no
fabricated data:
- `/executive` → **CISODashboard** — 6 real `apiFetch` endpoints; every fallback
  is honest `?? 0` / `?? "—"`; no static data arrays. Gold standard.
- `/mission-control/live-feed` → **LiveFeed** — react-query + WebSocket
  `/ws/events` + EventSource SSE. Genuinely live.
- `/mission-control/risk` → **RiskOverview** — `impactAreas` values from the `ov`
  query (labels static, values live).
- `/mission-control/ctem` → **ComplianceDashboard** — 4 react-query endpoints
  (ctem/cycles, compliance/frameworks, compliance-scanner/results+profiles).
- `/mission-control/threat-intel` → **ThreatIntelDashboard** — fixed tick146.
`RiskRegister` / `SLADashboard` files exist but their routes redirect (`/compliance`).

### Item (C) T3 hardening/lockdown slice — GREEN (tick150)

Ran a fresh non-blast-radius T3 chunk validating the SCIF hardening surface:
`storage_root_guard`, `trustgraph_backbone` + `event_bus`, dlp/secrets/deep-code/
ide-backend engine hardening, `health`, `no_unsafe_asyncio_run`,
`no_unawaited_coroutines_at_import`, `engine_router_import_sweep` (parametrized
across all engines + routers), `owasp_regression_lockdown` (subprocess-timeout
coverage, no hardcoded JWT secret, no credential in exception chain).
**Result: 1769 passed / 0 failed (58s)** — prior ticks' hardening is live + guarded.

UI NO-MOCKS confirmed clean by the directive's own grep: zero
`src/data|fixtures|mock|sample|seed` imports, zero `MOCK_`/`lorem`/`Acme`/`John Doe`
displayed values across `src/`.

### Item (C) T3 ingest/normalizer slice — GREEN (tick151)

Second non-blast-radius T3 chunk validating the ingest-first core (FixOps' primary
value prop): commercial DAST parsers, connector unit/coverage/router, cross-scanner
dedup, container/DAST/dep/AI/CLI scanners, CSPM connector, design-doc ingest
(real `/api/v1/design-doc` ingest+extract+stride+auto-model with 401-on-missing-key
+ org isolation). **Result: 723 passed / 0 failed (38s).** Non-live slice (`*_live.py`
excluded — those need founder-blocked external creds).

**Session T3 cumulative: 2492 tests green** (1769 hardening + 723 ingest) + Beast
smoke 755 + 1 known flake. Zero regressions. UI component layer also confirmed
NO-MOCKS clean (0 void-discard, 0 useState(MOCK), 0 no-api module data arrays).

### Item (C) Augment-governance spec-backfill — COMPLETE (tick152-153)

The `specs/INDEX.md` governance map (the Augment Code intent-IDE source of truth)
was only 8/22 specs registered and carried stale statuses. Synced to **22/22**:
- Added the 14 missing rows (SPEC-002..010, 012..015) with Status sourced from each
  spec file header + verified router/engine mappings.
- Fixed stale `PLANNED`→`IMPLEMENTED` on 002/003/004 (files said IMPLEMENTED).
- Marked the original 8-group backfill backlog DONE (all authored: 011/012/013/014/
  015/018/019/020) and listed verified-real next-candidate groups (MPTE/attack-sim,
  threat-intel+IOC, SOAR/playbooks, deception, forensics, exec-reporting).
- Verified: 22 files = 22 rows, 0 broken links, 0 unregistered, all spot-checked
  routers exist on disk. Docs-only (no code/build/test impact).

**Next buildable thread**: author a NEW spec for one next-candidate group (each is a
standalone effort like SPEC-011..020 — read router+engine, write intent/scope/
contracts/acceptance-criteria). Best done one-per-tick with fresh context to avoid
PRD-theater.

### New governance spec — SPEC-021 MPTE (tick154)

Authored SPEC-021-mpte (Multi-Phase Test & Exploitability Validation — the
FP-reduction moat), the first of the next-candidate groups. Grounded in the real
mounted surface (`suite-attack/api/mpte_router` /api/v1/mpte +
`mpte_orchestrator_router` /api/v1/mpte-orchestrator, verified via runtime
`__file__`): 20+ endpoints, contracts, REQs/NFRs, and 7 **executable** acceptance
criteria all verified live (health=builtin/self-contained, requests=200 items,
no-key=401, stats real counts, orchestrator TI sources {NVD,CISA-KEV,EPSS,...},
210 mpte tests pass). Caught + corrected a self-introduced inaccuracy pre-commit
(ExploitabilityLevel enum is 6 members, not 3). **INDEX now 23/23 specs.**

Remaining next-candidate groups (each a standalone one-per-tick authoring effort):
threat-intel feeds + IOC, SOAR/playbooks, deception, forensics, exec-reporting.

### New governance spec — SPEC-022 Threat Intelligence Layer (tick155)

Authored SPEC-022-threat-intel (feeds + actors + IOC enrichment, ingest-first /
honest-empty), the second next-candidate group. Grounded in live TestClient
probes (threat-intel/actors = 10 real, /iocs = {total,iocs[]}, feeds/status +
nvd/recent honest-empty count:0, ioc-enrichment stats zeroed, no-key = 401).
7 executable ACs; feed+ioc suites 428 passed / 1 skipped (org-isolation included).
Per no-fabrication, guessed feed paths that 404'd (`/feeds/epss/scores`,
`/feeds/mitre/techniques`) were EXCLUDED. **INDEX now 24/24 specs.**

Remaining next-candidate groups: SOAR/playbooks, deception, forensics,
exec-reporting/evidence-export (one verified spec per tick).

### New governance spec — SPEC-023 SOAR/Playbooks (tick156)
Authored SPEC-023 (IR automation: playbooks, execute, trigger, MTTR/stats; honest-empty).
Grounded in live probes (soar/ + soar/playbooks + soar/stats + soar/mttr + playbooks/ +
playbooks/executions all 200, honest zeros/empties; no-key 401). 8 ACs; playbook+SOAR
suites 125 passed. Per no-fabrication, found+recorded a minor route-shadow
(`/playbooks/builtin` 404s, shadowed by `GET /{playbook_id}`) — excluded from ACs, logged
as a follow-up. **INDEX now 25/25 specs.** Remaining candidates: deception, forensics,
exec-reporting/evidence-export.

### SPEC-023 self-correction (tick157) — no-fabrication catch
Chained a self-red-team on SPEC-023 and caught a fabricated diagnosis. Runtime
`endpoint.__module__` attribution revealed: app mounts `playbook_routes.py` (not
`playbook_router.py`), and `/api/v1/playbooks` is a **live shadow-collision zone** —
`gap_router` (list), `ir_playbook_runner_router` + `playbook_router` (both register
`/executions`), `playbook_routes.py` (CRUD). `/playbooks/builtin` 404s because `/builtin`
exists only in the unmounted file. Corrected the spec's Routers/debate/impl + INDEX row;
SOAR (`soar_router`) confirmed clean; all 8 ACs remain valid (200/401 verified live).
Reinforced lesson: attribute routers via runtime `__module__`, never by filename. The
playbooks collision is a concrete instance for the founder router-consolidation epic.

### New governance spec — SPEC-024 Deception (tick158)
Authored SPEC-024 (canaries/honeypots + decoy-asset analytics, honest-empty). Applied the
SPEC-023 lesson — routers attributed via runtime `endpoint.__module__` from the start; both
`deception_router` + `deception_analytics_router` are clean single-routers (no collision). 8 ACs
grounded on live probes (all 200 honest-empty; no-key 401); deception suites 80 passed.
**INDEX now 26/26 specs.** Remaining candidates: forensics, exec-reporting/evidence-export.

### New governance spec — SPEC-025 Forensics (tick159)
Authored SPEC-025 (digital-forensics cases + evidence custody + forensic readiness,
honest-empty). Routers attributed via runtime `endpoint.__module__` — both clean
single-routers. 6 ACs grounded on live probes (200 honest-empty zeroed stats; no-key 401);
forensics suites 120 passed. Custody endpoints share the SPEC-019 chain-of-custody model.
**INDEX now 27/27 specs.** Named next-candidate backlog down to ONE: exec-reporting/evidence-export.

### SPEC-026 + AUTH-GAP FIX — named backlog COMPLETE (tick160)
Authoring SPEC-026 (exec-reporting + evidence-export) surfaced a **live auth gap**: all 5
exec-reporting GET endpoints returned 200 unauthenticated (report/KPI/board-data leak). Root
cause: `executive_reporting_router` lacked the router-level `dependencies=[Depends(api_key_auth)]`
that peers (deception_router) have. **Fixed** (guarded import + router-level dep); verified
no-key→401 / with-key→200 on all 5, create_app 8357, CISODashboard unaffected, **Beast smoke
756/756**. INDEX now **28/28** — the named spec-backfill backlog is COMPLETE (SPEC-021..026:
MPTE, threat-intel, SOAR, deception, forensics, exec-reporting).

Next threads (no named backlog left): (1) audit other routers for the same missing-router-auth
pattern; (2) router-consolidation epic (`/api/v1/playbooks` collision + 740-dup-route debt);
(3) new specs as the API surface grows. All other backlog founder-blocked.

### Systematic auth-gap sweep — 8 unauthenticated routers fixed (tick161)
The exec-reporting finding (tick160) generalized: swept all 692 mounted `/api/v1` GET prefixes
no-key → 8 returned 2xx unauthenticated (api-discovery, asset-inventory, autonomous-remediation,
cloud-native, container-runtime, container-security, data-classification, vuln-correlation —
sensitive tenant data). 3 root causes fixed across 6 files: missing router-level `dependencies=`
(4 routers); a `def api_key_auth(): return True` placeholder (cloud_native); and a circular-import
NO-OP fallback that silently disabled auth (ui_alias, 3 alias prefixes — now fail-CLOSED).
Re-swept → **GAPS=0**; all 8 verified no-key=401/with-key=200; create_app 8357; Beast smoke 756/756.
Reusable detector + pattern saved to memory (feedback_router_auth_gap_pattern).

### Mutating-endpoint auth sweep — 8 more fixed (tick162)
Swept 701 POST/PUT/DELETE endpoints no-key → 14 candidates. FIXED 8 zero-auth data/action
routers with the router-level dep (secrets-management [created secrets unauthed — critical],
secrets/scan, k8s/scan, deployment/initialize, event-correlation/events, log-management/sources,
threat-intel-fusion/sources, tour/start) — all verified no-key=401/with-key=200|422; smoke
755+1-flake (0 regressions). EXCLUDED intentional-public: oauth2/token, slack/commands.
DEFERRED partial-auth (per-endpoint fix needed): nuclei/scan, threat-modeling-pipeline/models,
vuln-remediation/tasks. **Session auth-hardening total: 17 endpoints/routers closed.**

### Auth sweep COMPLETE (tick163) — 21 endpoints/routers closed this session
Fixed the 3 deferred partial-auth routers (nuclei/scan, threat-modeling-pipeline/models,
vuln-remediation/tasks — router-level dep covers flagged + path-param endpoints) + the inline
app.py POST /system/openapi-refresh (admin action, was unauthed). Caught + fixed a boot-crash
mid-fix (referenced a create_app local defined later → UnboundLocalError; switched to a guarded
inline import). Verified all 4 no-key=401/with-key=200; create_app 8357; smoke 755+1-flake.
**Both sweeps now GAPS=0** except oauth2/token + slack/commands (verified intentional-public —
token issuance + Slack signing-secret auth). **Session total: 21 unauthenticated endpoints
closed** (1 exec-reporting + 8 GET routers + 8 mutating routers + 3 partial-auth + 1 inline).

### Permanent auth regression guard + 2 final gaps (tick164)
Added `tests/test_no_unauthenticated_endpoints.py` — probes one endpoint per (prefix,method)
no-key, asserts 401/403, with a documented allowlist (oauth2/token, slack, health, trust-center
public spec, scif posture, git-sha, openapi, generic probes). Writing it surfaced 2 more gaps the
per-prefix sweeps missed (malware-analysis + network-forensics root GET) — fixed. Iterated the
allowlist via direct gap-probe (7→0), confirming each remaining 200 intentional-public per source
comments (NOT silently passed). FOUNDER-DECISION noted in-test: scif posture endpoints expose
audit-entry counts + HSM key labels unauthed — review for the SCIF threat model. Test PASSES (40s);
smoke 755+1-flake. **Session auth total: 23 endpoints closed + a permanent regression guard so
they can't silently revert.**

### Exhaustive auth guard + webhooks-management fix (tick165)
Upgraded the regression test to probe EVERY no-path-param endpoint (4975, not one per prefix).
This caught the webhooks MANAGEMENT router (mappings/drift/events/outbox/alm — incl
`POST /outbox/{id}/execute` triggering OUTBOUND webhooks unauthenticated) — fixed with a
router-level dep on the management `router` only (the `receiver_router` inbound webhooks stay
public/signature-verified, per their own design). Allowlist now covers the intentional-public
categories (auth-flow, inbound provider webhooks, billing/servicenow webhooks, */health).
**Exhaustive test PASSES (88s, 0 gaps); smoke 755+1-flake.** Auth epic complete + exhaustively
guarded — 24 router/surface fixes this session.
