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

### 422 missing-param (backend validation)
- `/awareness-metrics/metrics/latest` + `/trend` (MetricsPanel passes org_id; backend wants something else — inspect awareness router signature)
- `/orgs/{id}/children`, `/ancestors`, `/effective-policies` (org-hierarchy page)
- `/posture-trends/velocity-summary`
- `/program-maturity/summary` + `/domains`

### 404 missing endpoints (add real endpoint backed by engine, or repoint UI to existing) — verify each with `curl -H "X-API-Key:$K"`:
- `/ai-advisor/advisories` (router has /recommendations,/sessions,/stats — alias or add)
- `/api-threat-protection/threats` (router has /rules,/events,/stats — "threats"≈events?)
- `/risk/brs/bu/default` (brs-executive; "default" likely a hardcoded BU id)
- `/cloud/principals` (cloud-iam)
- `/dast/scans`, `/data-pipeline/sources`, `/digital-identity/identities`
- `/rules/dsl/rules` (dynamic-rule-dsl), `/event-timeline/timelines`+`/stats`
- `/gap-analysis/analyses`+`/stats`, `/identity-analytics/profiles` (identity-analytics + identity-governance)
- `/incident/incidents` (incident-timeline), `/ir/stats` (ir-playbook)
- `/threat-hunting/sessions`+`/findings`+`/timeline`+`/queries` (the `/hunting` page — distinct from threat-hunting-dashboard which works)
- `/patch-priority/` + `/plans` + `/stats` (patch-prioritizer)

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
