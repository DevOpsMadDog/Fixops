# HANDOFF — UI NO-MOCKS Frontier (2026-06-02)

Branch: `chore/ui-prune-plan-2026-05-24`. All commits LOCAL (push founder-blocked).
Session commits: 120 (since 359b05e6). Stack live: backend :8000 (8319 routes), dev :5173.
Final gate: **create_app boots 8319 routes; Beast smoke 756/756 passed.**

## What shipped this session (every fix browser- or curl-verified on the live stack)

### Mock data removed (NO-MOCKS rule)
- 36 dead unused mock-data consts across 9 dashboards (pages already render real liveData).
- **SECURITY**: hardcoded 43-char API-key fallback removed from 19 files (was a universal
  auth-bypass credential shipping in the client bundle).

### Crashes (white-screen) fixed
- `.map`-on-non-array class: 51 sites / 21 files wrapped with `arr()` coercion.
- CertificatesPanel `.slice` on undefined `cert_id` guarded.
- firmware-security invalid `<div>` inside `<tbody>` → proper `<TableRow><TableCell colSpan>`.
- BUHeatmapPanel React key fallback.

### Auth (401) fixed
- 6 files read the WRONG localStorage key `apiKey` → corrected to `aldeci.authToken`.
- ChangelogPage raw fetch had no auth header → added.

### Endpoint mismatches (404) — 10 groups repointed to real existing endpoints
ai-advisor/advisories→recommendations, api-threat-protection/threats→events,
digital-identity/identities→profiles, identity-analytics/profiles→identities,
gap-analysis analyses→assessments + stats→summary, dast/scans→findings,
data-pipeline/sources→pipelines, patch-priority/→stats, incident/incidents→incident-triage/incidents,
event-timeline/timelines→summary, ir/stats→metrics, rules/dsl/rules→rules/dsl (+POST→publish),
cloud/principals→cloud-identity/identities.

### Validation (422) fixed
- awareness-metrics /metrics/latest + /trend: `metric_type` made optional (router + engine).

### Tenancy
- 34× hardcoded `org_id=default` across 14 dashboards → real `getStoredOrgId()`.
  (Uses the real stored org; independent of the founder-flagged org-PRECEDENCE decision.)

### Infra / proxy
- vite `/api` proxy prefix collision → `^/api/` (unblocked the `/api-security*` SPA route family).
- container-registry real `GET /images`; sbom-export real `GET /diff` endpoints added.
- CNAPP + 3 cloud-posture panels + SBOM: authed real-org fetch.
- Built `e2e/route-sweep.spec.ts` — automated all-routes NO-MOCKS/runtime gate (real authed
  session; records console errors + failed /api/v1 per route → /tmp/route_sweep_report.json).

## Remaining (NOT founder-blocked but needs product/backend design — see UI_SWEEP_REMAINING_2026-06-02.md)
- `risk/brs/bu/default` — endpoint is correct; "default" isn't a real BU. UI should pick a real
  BU or show an onboarding empty-state (product decision).
- threat-hunting `/findings` + `/timeline` (the `/hunting` page) — no backend endpoints exist;
  page is resilient (Promise.allSettled, loads fine). Needs real aggregate endpoints to populate
  those two tabs (feature scoping).
- 2 cosmetic React key warnings (competitive-comparison marketing page, compliance-calendar) —
  warnings only, no functional impact.

## Founder-blocked (recorded, unchanged)
push (VPN-off + fresh PAT), Postgres migration, test-infra fixture, org-PRECEDENCE order,
FIPS-CMVP, PIV-CAC, GPU, Stripe.

## Notes for next session
- A background process intermittently leaves BROKEN auto-edits (e.g. `Depends()` inside Pydantic
  models) in tracked source. ALWAYS `git status --porcelain` and inspect/revert stray edits before
  committing. (Caught + reverted cspm_router.py + deduplication_router.py this session.)
- The route-sweep trips the backend 429 rate limiter (a real feature) — filter 429s when triaging.
