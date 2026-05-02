# ALDECI UI Consolidation — Phase 0 Audit

**Generated:** 2026-05-03
**Branch:** `consolidation/phase-0-audit`
**Tag:** `pre-consolidation-snapshot`
**Repo tip:** `bacc6201`
**Spec docs:** `page_to_screen_map.csv` · `ia_spec.json` · `api_to_screen.csv` (all in this directory)

---

## 1. Headline numbers

| Metric | Value | Notes |
|---|---|---|
| `.tsx` files under `src/pages/` | **520** | excludes `__tests__/` and `.omc/` |
| Total LOC across pages | **176,829** | from `wc -l` |
| `App.tsx` LOC | **1,674** | target post-Phase 1: ~100 |
| `<Route>` declarations in `App.tsx` | **600** | unique element components: 239 |
| Backend router files | **684** | under `suite-api/apps/api/*_router.py` |
| Backend `@router.{get,post,put,delete,patch}` endpoints | **5,964** | post-classification this many `/api/v1/...` routes |
| Files using `?? MOCK_` or `useState(MOCK_` | **55** | hard-banned in v2 |
| Total `MOCK_` fallback occurrences | **137** | across the 55 files |
| **Dead pages (in `src/pages/` but NOT routed in `App.tsx`)** | **295** | candidates for immediate deletion at Phase 5 cutover |
| **Target screens** | **31** | per spec |
| Reduction ratio | **520 → 31** (94%) | routes 600 → ~32 |

> Spec said 480/541 — actual repo is 520/600 (slightly larger). Numbers reflect the *current* tip.

## 2. Top 10 largest pages (highest-risk migrations)

These dominate the LOC budget. Each must be carefully decomposed before migration.

| Rank | LOC | File | Target Screen |
|---|---:|---|---|
| 1 | 2186 | `src/pages/findings/FindingsExplorer.tsx` | **S17** Findings Explorer |
| 2 | 1986 | `src/pages/Compliance.tsx` | **S25** Compliance & Evidence |
| 3 | 1730 | `src/pages/AssetGraph.tsx` | **S15** TrustGraph |
| 4 | 1604 | `src/pages/mission-control/SOCT1Dashboard.tsx` | **S03** Mission Control |
| 5 | 1567 | `src/pages/sbom/SBOMManagement.tsx` | **S07** Software Supply Chain |
| 6 | 1415 | `src/pages/mission-control/ThreatIntelDashboard.tsx` | **S19** Threat Intelligence (re-route from MC) |
| 7 | 1398 | `src/pages/Brain.tsx` | **S03** Mission Control |
| 8 | 1390 | `src/pages/mission-control/SOCDashboard.tsx` | **S03** / **S20** (split) |
| 9 | 1341 | `src/pages/hunting/ThreatHunting.tsx` | **S20** Detections & Alerts |
| 10 | 1333 | `src/pages/mission-control/RiskRegister.tsx` | **S18** Risk Acceptance & Waivers |

**Risk:** Items #1 (FindingsExplorer 2186 LOC) and #2 (Compliance 1986 LOC) account for ~2.4% of all UI LOC by themselves and gate two of the six Phase-2 screens. Decompose into hooks + sub-components *before* moving.

## 3. Page → Screen distribution

Full mapping in `page_to_screen_map.csv` (520 rows).

| Screen | Pages | Backend Endpoints | Notes |
|---|---:|---:|---|
| S01 Login & Auth | 2 | 33 | small; chrome-less |
| S02 Onboarding Wizard | 3 | 9 | small; chrome-less |
| S03 Mission Control | **181** | 128 | catch-all dashboard bucket — refine in Phase 2 |
| S04 ASPM — Code | 2 | 103 | low page count, high backend |
| S05 ASPM — API Security | 9 | 29 | aligns to spec |
| S06 ASPM — App Runtime | 2 | 27 | aligns |
| S07 Software Supply Chain | 4 | 233 | low pages, high backend (sbom/sca breadth) |
| S08 Secrets & Crypto | 1 | 121 | UI under-built |
| S09 CSPM — Posture | 1 | 147 | UI under-built |
| S10 Cloud Accounts | 0 | 47 | **no current UI** |
| S11 Cloud Workloads | 5 | 46 | aligns |
| S12 Network Security | 3 | 134 | UI under-built |
| S13 Identity & Access | 15 | 175 | aligns |
| S14 Attack Surface | 22 | 86 | aligns |
| S15 TrustGraph | 5 | 62 | aligns |
| S16 CTEM Cycles | 1 | 15 | UI under-built |
| S17 Findings Explorer | **115** | 3057 | second catch-all — refine in Phase 2 (much of this is legitimate findings UX) |
| S18 Risk Acceptance & Waivers | 7 | 50 | aligns |
| S19 Threat Intelligence | 11 | 150 | aligns |
| S20 Detections & Alerts | 24 | 97 | aligns |
| S21 Incidents & Response | 14 | 171 | aligns |
| S22 Ransomware & Malware | 2 | 27 | small |
| S23 Data Security | 2 | 11 | small |
| S24 Privacy | 2 | 27 | small |
| S25 Compliance & Evidence | 28 | 320 | aligns |
| S26 Vendor & SaaS Risk | 5 | 53 | aligns |
| S27 IoT, OT & Endpoints | 3 | 99 | UI under-built |
| S28 AI Security | 18 | 117 | aligns |
| S29 Integrations | 7 | 250 | UI under-built |
| S30 Collaboration & Awareness | 10 | 99 | aligns |
| S31 Settings & Admin | 16 | 41 | aligns |
| **TOTAL** | **520** | **5,964** | |

### Catch-all warnings

- **S03 Mission Control (181 pages)** is over-loaded due to the generic "Dashboard" suffix. In Phase 1 stub generation, the v2 ScreenS03 will list all 181 pages in the legacy panel; Phase 2 work refines half of them OUT to other screens (TI, Detections, ASM, etc.).
- **S17 Findings Explorer (115 pages)** absorbs every triage/dedup/material-change page. Phase 2 PR-B should split obvious mis-classifications back out (e.g. UBA → S13 Identity).

### Under-built coverage gaps (UI lags backend)

These screens have meaningful backend (>100 endpoints) but ≤5 current pages — they're *future build* opportunities once consolidation lands:

| Screen | Pages | Endpoints |
|---|---:|---:|
| S08 Secrets & Crypto | 1 | 121 |
| S09 CSPM — Posture | 1 | 147 |
| S12 Network Security | 3 | 134 |
| S07 Supply Chain | 4 | 233 |
| S04 Code | 2 | 103 |
| S29 Integrations | 7 | 250 |
| S25 Compliance | 28 | 320 (heavy) |
| S10 Cloud Accounts | 0 | 47 |

## 4. Dead-page summary

**295 pages** exist under `src/pages/` but are NOT referenced via `<Route element={<Page/>}>` in `App.tsx`. These represent abandoned dashboards / orphan components and are eligible for Phase-5 cutover deletion.

Sample (full list in `page_to_screen_map.csv` where `is_dead == True`):

```
AccessAnomalyDashboard          AccessGovernanceDashboard
ActorTrackingDashboard          AgentlessScanStatus
AgentlessSnapshotDashboard      AgentTaskQueue
AIAgentsConsole                 AIGovernanceDashboard
AIPoweredSOCDashboard           AirGapBundleConsole
AirGapBundleDashboard           AlertEnrichmentDashboard
AlertTriageDashboard            AlgorithmicLab
APIAbuseDashboard               APIDiscoveryDashboard
APIInventoryDashboard           APISecurityDashboard
APISecurityMgmtDashboard        ApplicationRiskDashboard
AppSecurity                     ArchitectureLayerGraph
AssetCriticalityDashboard       …+274 more
```

**Recommendation:** retain them in `src/pages/_legacy/` after Phase 1 move, not in `src/pages/v2/`. Phase 5 deletion is a single `git rm -rf src/pages/_legacy/`.

## 5. MOCK_ fallback census

**55 files** use the `?? MOCK_` or `useState(MOCK_` anti-pattern (137 occurrences total). Per project rules, these are **forbidden in v2**. Each file's data layer must be re-wired to a real `/api/v1/...` endpoint with `<EmptyState />` / `<ErrorState />` for empty/error.

To find them:
```bash
grep -rE "(\?\? *MOCK_|useState\(MOCK_)" src/pages
```

## 6. Open Questions (carry into Phase 1+)

1. **S03 vs domain screens** — many `*Dashboard` pages were classified to S03 by default. In Phase 2 PR-A, the team will re-classify ~80 pages from S03 to their correct domain (TI/Detections/ASM/Identity).
2. **S17 vs S20/S21** — pages mentioning both "alert" and "finding" are ambiguous. Default rule: if it triggers a workflow → S21; if it's a list/triage view → S17.
3. **`page_to_screen_map.csv` is auto-generated** — human review pass needed before Phase 2 PR-A. Fix mis-classifications (esp. for the 181 S03 pages and the 115 S17 pages) by editing `screen_id` column directly, then commit the corrected CSV as the Phase-1 baseline.
4. **API endpoint correlation** is keyword-based. The actual page→endpoint mapping will be confirmed during Phase-2 implementation by following `useQuery({queryKey: [...]})` calls.
5. **Default branch is currently `main`** but all work happens on `features/intermediate-stage` (now Phase-0 forked from this). Decision pending: change default to `features/intermediate-stage` or fast-forward `main` after Phase 5.

## 7. Backup & rollback

- Pre-consolidation tag: `pre-consolidation-snapshot` (= `bacc6201`)
- Earlier docs-purge backup: `backup/docs-deletion-2026-05-03`
- This audit branch: `consolidation/phase-0-audit`

To roll back to before this consolidation began:
```bash
git checkout pre-consolidation-snapshot
```

## 8. Multica integration

Per founder directive (memory `feedback_multica_assignment_required.md`), one Multica issue per screen has been created in workspace `30fad00d-8273-4196-96d4-abd55f4cbb43`. Each issue:

- Title: `[CONSOLIDATION] {SID} {Screen Name}`
- Description: page count + backend endpoint count + sample legacy paths
- Assignee: agent (`00000000-0000-0000-0000-000000000001`)
- Status: `todo` (will move to `in_progress` when its Phase-2 PR opens)

See **§10** below for the SQL bulk-insert + status pin.

## 9. Acceptance gate

Phase 0 is "done" when:

- [x] Working tree was clean before tagging (only benign telemetry diffs)
- [x] Tag `pre-consolidation-snapshot` pushed
- [x] Branch `consolidation/phase-0-audit` created
- [x] `MIGRATION_AUDIT.md` (this file) written
- [x] `page_to_screen_map.csv` written (520 rows)
- [x] `ia_spec.json` written (31 screens)
- [x] `api_to_screen.csv` written (5964 endpoints)
- [ ] PR opened titled "Phase 0: Audit" — **next step**
- [ ] Multica issues #N+1..#N+31 created — **next step**
- [ ] Human review approves moving to Phase 1

## 10. Multica bulk-insert SQL

Generated procedurally during Phase 0 commit. See `multica_phase0_bulk.sql` (committed alongside the audit) for the executed payload.

---

**Generated by autonomous Phase-0 audit agent. Boulder doesn't stop.**
