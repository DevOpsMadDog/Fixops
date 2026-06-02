# HANDOFF — UI NO-MOCKS / Customer-Readiness Frontier (2026-06-02, updated PM)

Branch `chore/ui-prune-plan-2026-05-24`. All commits LOCAL (push founder-blocked).
Session commits: 136 (since 359b05e6). Stack live: backend :8000 (8319 routes, rate-limit RESTORED),
dev :5173. Final gate: create_app boots 8319 routes; Beast smoke 756/756.

## Key process learning this session
The route-sweep's 429s were MASKING real per-route bugs. A "class-clean" build is NOT
"customer-ready" — only a CLEAN sweep (rate-limit disabled, then restored) reveals the truth.
Reproduce: restart backend with FIXOPS_DISABLE_RATE_LIMIT=1, run e2e/route-sweep, RESTORE after.

## DONE (all build-green; representative routes browser-verified 0 console errors)
- **All white-screen crashes** (≈13): non-array .map/.filter (devsecops, regulatory-tracker,
  security-chaos, security-health, vuln-correlation, container, deception, + 51-site arr() class);
  .toFixed/.replace/.slice undefined (cyber-insurance fmt$, security-posture, certificates);
  <div>-in-<tbody> (firmware, security-chaos, security-tabletop); EmptyState icon element->component
  (prowler/servicenow/siem targets tabs).
- **All 401 auth**: wrong localStorage keys (apiKey x6, aldeci_api_key x15 -> aldeci.authToken);
  api-config static empty API_KEY -> getApiKey() runtime resolver (4 hub consumers); ChangelogPage.
- **Mock data / security**: 36 dead mock consts removed; hardcoded API-key fallback removed (19 files).
- **~22 endpoint repoints/fixes** to real existing paths (ai-advisor, api-threat-protection,
  digital-identity<->identity-analytics, gap-analysis, dast, data-pipeline, patch-priority, incident,
  event-timeline, ir, rules/dsl, cloud-iam, cost-optimization, security-investment, threat-response,
  soc-metrics root+analysts, feeds/kev->threat-intel/kev, ti-confidence/iocs->high-confidence,
  security-kpis 5->1 /executive).
- **Honest empty-200** (not 404) for empty/air-gapped cache: threat-intel cves/recent + kev.
- **Tenancy**: 34x hardcoded org_id=default -> real getStoredOrgId() (14 dashboards).
- **awareness-metrics 422** -> metric_type optional.
- **Infra**: vite /api proxy collision fixed; container-registry /images + sbom-export /diff added;
  CNAPP/cloud-posture/SBOM authed real-org; e2e/route-sweep.spec.ts harness built.

## REMAINING — buildable, next sessions (resilient pages: allSettled + EmptyStates, NO crashes)
Genuine missing GET endpoints (need real backend construction or page rework; engine support varies):
- soc-metrics/queue (+ queue/{id}/ack,/resolve) — SOC triage queue, no backend.
- sca/vulns, sca/licenses — only scan-level /scans/{id}/vulnerable-deps + /license-report exist;
  need org-level aggregate endpoints.
- hunting/iocs, hunting/coverage — threat_hunting has /ioc-correlate (POST) only.
- awareness-score/orgs/{org}/risk-trend — has /scores + /stats; add risk-trend or repoint.
- feed-subscriptions/logs, incident/stats, incident-timeline/events, security-chaos/observations.
React key warnings (cosmetic, non-blocking): competitive-comparison, compliance-calendar,
cross-domain-analytics, exception-workflow, firewall-policy, grc-assessment, risk-quantification,
cyber-insurance.
Possible empty-404 anti-patterns to verify-then-convert IF hit on mount (sweep didn't flag, so
verify first): attack_sim breach-impact, micro_pentest scan-data, security_telemetry datapoints.

## Founder-blocked (unchanged): push, Postgres, test-infra fixture, org-precedence, FIPS, PIV, GPU, Stripe.

## Watch-outs
- A background process leaves BROKEN auto-edits (Depends-in-Pydantic) in tracked source mid-session.
  ALWAYS `git status --porcelain` + inspect/revert before finishing. (Caught cspm/dedup this session.)
- src/lib `git add <dir>` warns "ignored" (a subpath is ignored) but the actual .ts files ARE tracked —
  add by explicit file path; verify with `git show HEAD:<file>`.

---
## UPDATE 2 (PM, late) — missing-endpoint cluster built (real, engine-backed)
Added REAL engine-backed endpoints for nearly the whole genuine-missing-404 cluster (no stubs;
each: new engine list/aggregate method + router GET + browser/curl-verified 200 + Beast smoke 756):
- sca: GET /vulns + /licenses (org-level aggregate over latest scan per project)
- security-chaos: GET /observations (list_all_observations)
- incident-timeline: GET /events (list_all_events, registered before /{id}) + /incident/stats repoint
- soc-metrics: GET /queue (list_alerts) + GET /snapshots (list_snapshots) + guarded toFixed crash
- feed-subscriptions: GET /logs (list_deliveries over feed_deliveries)
- threat-intel: cves/recent + kev now honest empty-200 (air-gapped cache)
- security-kpis -> /kpis/executive (5 missing -> 1 real); feeds/kev + ti-confidence/iocs repoints
- removed dead unrouted ThreatHuntingPage (its /hunting/iocs+coverage never fired live)

### Last remaining (truly needs new feature, not wiring)
- awareness-score/orgs/{org}/risk-trend — needs a historical score-snapshot (time-series) table;
  the engine only has current scores/stats. Page is resilient. Build it when score-history is in scope.
- soc-metrics queue ack/resolve actions — engine has acknowledge_alert/resolve_alert but no routes
  (button actions, not page-mount; add /queue/{id}/ack + /resolve when wiring the buttons).
- Cosmetic React key warnings (~8 pages) — non-blocking.

Session total: 149 commits. create_app 8319 routes; Beast smoke 756/756; rate limiter restored.
