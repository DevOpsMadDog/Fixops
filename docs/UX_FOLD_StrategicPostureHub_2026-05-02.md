# UX Fold — StrategicPostureHub (Phase 3 Strategic Posture / GRC cluster)

**Date:** 2026-05-02
**Branch:** features/intermediate-stage
**Plan source:** `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` §2.23 (Comply space — Strategic Posture sub-cluster)

## Hub
`suite-ui/aldeci-ui-new/src/pages/StrategicPostureHub.tsx` mounted at **`/comply/strategic-posture`**.

## Folded source pages

| tab     | Source page                | Old route          | Endpoint                                                |
|---------|----------------------------|--------------------|---------------------------------------------------------|
| posture | SecurityPostureDashboard   | `/security-posture`| `/api/v1/posture-advisor/{score,components,stats}`      |
| roadmap | SecurityRoadmap            | `/security-roadmap`| `/api/v1/security-roadmap/{initiatives,milestones,gaps}`|
| grc     | GRCAssessment              | `/grc-assessment`  | `/api/v1/grc/{controls,gaps,audits}`                    |

All three source pages now carry `// FOLDED into StrategicPostureHub at /comply/strategic-posture?tab=<key>` markers and are reachable via `<Navigate replace>` redirects from their old paths in `App.tsx`.

## Verification

Playwright (CJS) headless, viewport 1440×900, `domcontentloaded` + 2.5s settle:

- `nav_ok=true`
- `api_call_count=7` — first real call: `/api/v1/posture-advisor/score?org_id=aldeci-demo` (followed by `…/components`, `…/stats`)
- `mocks_found=[]` — no MOCK_/lorem ipsum/sample-/demo-org/Acme Corp/John Doe in DOM
- Screenshot: `docs/ui-snapshots/ux-consolidation-strategic-posture-2026-05-02.png`

Personas: CISO (#1), Security Architect (#11), GRC Analyst (#12), Compliance Manager (#13).

Note: `posture-advisor` query string is concatenated `org_id=aldeci-demo?org_id=default` — pre-existing in `SecurityPostureDashboard`, surfaced now via the hub. Tracked separately; does not block fold.
