# UX Fold — DataDiscoveryHub (Phase 3 Data Discovery / DSPM cluster)

**Date:** 2026-05-02
**Branch:** features/intermediate-stage
**Plan source:** `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` (Data Discovery / DSPM sub-cluster)

## Hub
`suite-ui/aldeci-ui-new/src/pages/DataDiscoveryHub.tsx` mounted at **`/discover/dspm`**.

## Folded source pages

| tab            | Source page                  | Old route             | Endpoint                                            |
|----------------|------------------------------|-----------------------|-----------------------------------------------------|
| discovery      | DataDiscoveryDashboard       | `/data-discovery`     | `/api/v1/data-discovery/datastores`                 |
| classification | DataClassificationDashboard  | `/data-classification`| `/api/v1/data-classification/{stats,items,violations}`|
| exfiltration   | DataExfiltrationDashboard    | `/data-exfiltration`  | `/api/v1/data-exfiltration/{stats,incidents}`       |

All three source pages now carry `// FOLDED into DataDiscoveryHub at /discover/dspm?tab=<key>` markers and are reachable via `<Navigate replace>` redirects from their old paths in `App.tsx`.

## Verification

Playwright (CJS) headless, viewport 1440×900, `domcontentloaded` + 2.5s settle:

- `nav_ok=true`
- `api_call_count=5` — first real call: `/api/v1/data-discovery/datastores?org_id=juice-shop-corp` (followed by `…/stats`)
- `mocks_found=[]` — no MOCK_/lorem ipsum/sample-/demo-org/Acme Corp/John Doe in DOM
- Screenshot: `docs/ui-snapshots/ux-consolidation-data-discovery-2026-05-02.png`

Personas: GRC Analyst (#12), Compliance Manager (#13), DPO, Security Architect (#11).
