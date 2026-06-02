# UI Route-Sweep — Remaining Work (2026-06-02)

Source: automated `e2e/route-sweep.spec.ts` (real authed session, records console errors +
failed `/api/v1` per route → `/tmp/route_sweep_report.json`). Run:
```
FIXOPS_API_TOKEN="$(cat /tmp/scif_key.txt)" FIXOPS_ORG_ID="$(cat /tmp/scif_org.txt)" \
  npx playwright test route-sweep --workers=1 --timeout=0 --global-timeout=0
```

## Sweep caveat — rate limiter
The sweep hammers 354 routes back-to-back and trips the backend **429 rate limiter** (a real,
working feature — good for SCIF). ~90% of "failures" in the raw report are 429 artifacts, NOT
bugs. **Filter out 429** when triaging. The non-429 findings below are the real actionable set.

## DONE this session (browser-verified)
- malformed `?org_id=default` double-append (18 pages)
- vite proxy `/api` prefix collision → `^/api/` (unblocked /api-security* route family)
- container-registry real `GET /images`; sbom-export real `GET /diff`
- CNAPP + 3 cloud-posture panels + SBOM authed real-org fetch
- 36 dead mock-data consts removed (9 dashboards)
- **SECURITY**: hardcoded API-key fallback removed from 19 files
- `.map`-on-non-array crash class: 51 sites / 21 files wrapped with `arr()` coercion
- CertificatesPanel `.slice` crash guarded
- 401 wrong-localStorage-key (`apiKey`→`aldeci.authToken`) in 6 files + ChangelogPage auth

## REMAINING (next increments)

### 422 missing-param (backend validation) — RESOLVED / triaged
- ✅ `/awareness-metrics/metrics/latest` + `/trend` — FIXED (metric_type made optional, router+engine; live 200)
- ⚠️ `/orgs/{id}/children`, `/ancestors`, `/effective-policies` — returns **404** "org not found in tenant": the managed org has no row in the org-hierarchy table. Should return self/empty for a valid authed org rather than 404, but this touches **founder-flagged org-precedence/tenancy logic** — defer until org-precedence decided.
- ✅ `/posture-trends/velocity-summary`, `/program-maturity/summary`, `/program-maturity/domains` — FALSE POSITIVES: all 200 now with real empty data (sweep transient/rate-limit adjacent). No action.

### 404 missing endpoints — all 15 confirmed real (clean curl). FIX-MAP (existing router endpoints surveyed):
Prefer **repoint UI → existing endpoint** (no backend restart) unless a real new endpoint is warranted.
- `/ai-advisor/advisories` → router has `/recommendations` — repoint UI (advisories→recommendations) or drop the extra call.
- `/api-threat-protection/threats` → router has `/events` — repoint threats→events.
- `/digital-identity/identities` → router has `/profiles` — repoint identities→profiles.
- `/identity-analytics/profiles` → router has `/identities` — repoint profiles→identities (mirror of above; also /identity-governance uses same).
- `/gap-analysis/analyses` → router has `/assessments`; `/gap-analysis/stats` → `/summary` — repoint.
- `/rules/dsl/rules` → dynamic_rule_dsl router list is `""` (root) — repoint /rules→root.
- `/dast/scans` → router has `/` + `/scans/{id}` but no list `/scans` — add GET `/scans` (list) backed by engine, or repoint to `/`.
- `/data-pipeline/sources` → router has `/pipelines` only — repoint sources→pipelines OR add `/sources`.
- `/patch-priority/` (root) → patch_prioritizer has `/plans`,`/stats`,`/score` but no index — repoint to `/stats` or add index.
- `/event-timeline/timelines` → file security_event_timeline_router.py HAS `/timelines` — **PREFIX MISMATCH**: verify the router prefix (likely `/api/v1/security-event-timeline` not `/event-timeline`). Repoint UI prefix or reconcile.
- `/threat-hunting/sessions`+`/queries` EXIST in threat_hunting_router; `/findings`+`/timeline` do NOT. The `/hunting` page calls all 4 — repoint findings→(sessions/{id}/results?) + drop /timeline, or add. (Re-curl: /sessions itself 404'd — recheck for prefix/rate-limit.)
- `/cloud/principals` → cloud_access_security router (/apps,/events,/policies) has no /principals. IAM principals likely belong to a cloud-iam/cloud-identity router — locate correct router or add.
- `/incident/incidents` → incident_lessons_router has /lessons, no /incidents — locate incident router or repoint.
- `/ir/stats` → **no router with /ir prefix** — find the IR router (maybe /incident-response) and repoint, or add.
- `/risk/brs/bu/default` → brs-executive; `default` is a hardcoded BU id in the UI — repoint to a real BU or add a default-BU rollup endpoint.

### Crashes / warnings
- `/firmware-security` — HTML hydration: `<div>` nested in `<tbody>` (invalid table markup) — fix the table structure
- React key warnings (low pri): `/bu-dollar-heatmap`, `/competitive-comparison`, `/compliance-calendar`

### Tenancy class (34× hardcoded `org_id=default`, 14 files) — pages WORK (200) but query wrong tenant
AISecurityAdvisor, ThreatExposureDashboard, SecurityMetricsDashboard(+2), NetworkAnalysis,
CyberInsurance, ThreatVectorDashboard, ThirdPartyVendorDashboard, SecurityTelemetryDashboard,
SaasSecurityPostureDashboard, RiskTreatmentDashboard, ComplianceCalendarDashboard,
ArchReviewDashboard, IdentityLifecycleDashboard. Replace literal `org_id=default` →
`org_id=" + (getStoredOrgId() ?? "default")` (string-concat, no quote flip). NOTE: org-precedence
is a **founder-blocked** decision — in single-tenant SCIF "default" may be acceptable; confirm
before bulk-changing, or do it since real-org is strictly more correct.

## Method note
Backend endpoint additions require a uvicorn restart (no --reload):
`PYTHONPATH="$(ls -d /Users/devops.ai/fixops/Fixops/suite-*|tr '\n' ':')" python -m uvicorn apps.api.app:create_app --factory --host 127.0.0.1 --port 8000`
Do NOT restart while the sweep is running. Managed key: `/tmp/scif_key.txt`, org `/tmp/scif_org.txt`.

---
## UPDATE — clean (rate-limit-OFF) re-sweep, 2026-06-02 PM

The first sweep's 429s MASKED real per-route bugs. Re-ran with FIXOPS_DISABLE_RATE_LIMIT=1
(restored after). Real state was worse than "class-clean". Now fixed:

### DONE this session (all build-green; representative routes browser-verified 0 errors)
- ALL crashes (white-screens): devsecops, container-security, cyber-insurance(fmt$), deception,
  regulatory-tracker, security-chaos, security-health, vuln-correlation (non-array map/filter);
  security-chaos + security-tabletop + firmware (<div>-in-<tbody>); prowler/servicenow/siem
  (EmptyState icon element->component); security-posture (.replace); certificates (.slice).
- 401 class: 15 files wrong key aldeci_api_key->aldeci.authToken; api-config static empty API_KEY
  -> getApiKey() runtime resolver in 4 hub consumers.

### REMAINING — buildable, next ticks (from /tmp/route_sweep_report.json)
404 (repoint to real endpoint or add): cost-optimization/stats, feeds/kev, event-timeline/stats,
feed-subscriptions/logs, incident/stats, sca/vulns+licenses, awareness-score/orgs/{org}/risk-trend,
security-chaos/observations, security-investment/stats, kpis/{scorecard,categories,strengths,
weaknesses,trends}, soc-metrics{,/snapshots,/analysts,/queue}, incident-timeline/events,
hunting/iocs+coverage, threat-intel/cves/recent, threat-response/stats+playbooks, ti-confidence/iocs.
403: ti-confidence/sources. 422: posture-trends/{velocity-summary,trends,targets},
program-maturity/{summary,domains}, sql/queries.
React dup/missing-key warnings (cosmetic): competitive-comparison, compliance-calendar,
cross-domain-analytics, exception-workflow, firewall-policy, grc-assessment, risk-quantification,
cyber-insurance.

### Method to reproduce a CLEAN sweep
Restart backend with FIXOPS_DISABLE_RATE_LIMIT=1 (CI/test knob, app.py:2530), run route-sweep,
then RESTART WITHOUT the flag to restore prod rate-limiting. Don't leave it disabled.
