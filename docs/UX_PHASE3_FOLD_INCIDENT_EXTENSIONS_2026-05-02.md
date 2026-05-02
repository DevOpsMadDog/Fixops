# Phase 3 Fold — Incident Extensions Hub (S22)

**Date**: 2026-05-02
**Cluster**: S22 — Incident Response (Extensions sub-cluster)
**Plan**: `docs/UX_CONSOLIDATION_PLAN_2026-04-26.md` §2.22
**Commit**: `ff14482a`
**Status**: SHIPPED

## Fold Summary

3 standalone IR-extension dashboards merged into a single tabbed hero,
complementing the main S22 IR Console and the previously-folded ForensicsHub
(at `/remediate/forensics`).

| Tab    | Source page (kept on disk)        | Endpoint                                  |
|--------|-----------------------------------|-------------------------------------------|
| cloud  | `CloudIRDashboard.tsx`            | `/api/v1/cloud-ir/*`                      |
| breach | `BreachResponse.tsx`              | `/api/v1/breach-response/{stats,cases}`   |
| comms  | `IncidentCommsDashboard.tsx`      | `/api/v1/incident-comms/{communications,stats}` |

**Hub route**: `/remediate/incidents/extensions`
**Deep-link**: `?tab=cloud|breach|comms`

## Legacy Route Redirects

| Legacy path        | Redirects to                                        |
|--------------------|-----------------------------------------------------|
| `/cloud-ir`        | `/remediate/incidents/extensions?tab=cloud`         |
| `/breach-response` | `/remediate/incidents/extensions?tab=breach`        |
| `/incident-comms`  | `/remediate/incidents/extensions?tab=comms`         |

## Files Changed

- **NEW** `suite-ui/aldeci-ui-new/src/pages/IncidentExtensionsHub.tsx` — tabbed hero (lazy imports + ?tab= sync)
- `suite-ui/aldeci-ui-new/src/App.tsx` — hub route + 3 Navigate redirects
- `suite-ui/aldeci-ui-new/src/pages/CloudIRDashboard.tsx` — FOLDED marker
- `suite-ui/aldeci-ui-new/src/pages/BreachResponse.tsx` — FOLDED marker
- `suite-ui/aldeci-ui-new/src/pages/IncidentCommsDashboard.tsx` — FOLDED marker
- `docs/ui-snapshots/ux-consolidation-incident-extensions-2026-05-02.png` — Playwright screenshot

## Verification (NO MOCKS rule)

- Playwright `domcontentloaded` navigation to `http://localhost:5173/remediate/incidents/extensions`
- Hero `Incident Extensions` rendered — title `ALDECI | Enterprise Security Intelligence`
- 3 real `/api/v1/` calls fired on mount (`/api/v1/cloud-ir/incidents`, `/api/v1/alert-triage/alerts`)
- Full-page screenshot captured (87.6 KB)

## Persona Coverage

- IR Lead (#7) — primary owner of all 3 tabs
- SOC T2 (#6) — cloud + breach triage
- Crisis Comms (#13) — comms tab for stakeholder updates

## Page-Count Impact

3 pages → 1 hero (kept on disk for lazy-import; not removed from FS).
Phase 3 progress: continues collapse from ~370 → 25-40 enterprise screens.
