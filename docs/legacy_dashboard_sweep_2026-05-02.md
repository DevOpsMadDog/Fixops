# Legacy Dashboard Sweep — 2026-05-02

Audit follow-up #3 to commit `030ddb90`. READ-ONLY scan, no `.tsx` files modified.

## Section 1 — Page Inventory

| Metric | Count |
|--------|-------|
| Total `.tsx` pages in `src/pages/` | **431** |
| `*Dashboard.tsx` pages (total) | 254 |
| Dashboards already FOLDED into hubs | 135 |
| Dashboards NOT yet folded (candidates) | **119** |
| All pages marked FOLDED (any name) | 181 |
| Hub pages live (`*Hub.tsx`) | 48 |
| Routes registered in `App.tsx` | 605 |

Methodology: count = `grep <PageName> App.tsx`. Count of 2 = lazy import + Route element (ACTIVE). Count of 1 = lazy import only, no Route (ORPHAN). Count of 0 = absent (full ORPHAN). API call presence verified via `apiFetch|useQuery|fetch(` grep.

## Section 2 — 20 Non-Hub Dashboard Candidates

| # | Page | Refs | API Calls | Status | Recommendation |
|---|------|------|-----------|--------|----------------|
| 1 | AgentlessSnapshotDashboard | 2 | 5 | ACTIVE | Fold into AssetInventoryHub (snapshot tab) |
| 2 | AccessRequestManagementDashboard | 2 | 4 | DUPLICATE | Fold into IdentityGovernanceHub (already hosts access flow) |
| 3 | AISecurityAdvisorDashboard | 2 | 4 | DUPLICATE | Fold into AICopilotAgentsHub |
| 4 | AirGapBundleDashboard | 1 | 5 | ORPHAN | Fold into AirGapHub OR delete (lazy import, no Route) |
| 5 | AIPoweredSOCDashboard | 1 | 4 | ORPHAN | Fold into DetectAndRespondHub OR delete |
| 6 | APIThreatProtectionDashboard | 2 | 4 | DUPLICATE | Fold into APISecurityHub |
| 7 | CloudAccessSecurityDashboard | 2 | 4 | DUPLICATE | Fold into CloudPostureUnifiedHub |
| 8 | ArchReviewDashboard | 2 | 2 | ACTIVE | Cluster candidate (Architecture hub — see Section 3) |
| 9 | CCMDashboard | 2 | 5 | ACTIVE | Fold into ComplianceCoverageHub |
| 10 | CloudIdentityDashboard | 2 | 4 | DUPLICATE | Fold into IdentityGovernanceHub |
| 11 | CISOReportDashboard | 0 | 4 | ORPHAN | Delete — no import, no Route, fully unreferenced |
| 12 | CloudSecurityAnalyticsDashboard | 2 | 4 | DUPLICATE | Fold into CloudPostureUnifiedHub |
| 13 | ArchAwareGraphDashboard | 2 | 4 | ACTIVE | Cluster candidate (Architecture hub) |
| 14 | CloudCostOptimizationDashboard | 2 | 4 | ACTIVE | Cluster candidate (FinOps mini-hub) |
| 15 | CapacityPlanningDashboard | 2 | 4 | ACTIVE | Cluster candidate (FinOps mini-hub) |
| 16 | CMDBDashboard | 2 | 5 | DUPLICATE | Fold into AssetInventoryHub |
| 17 | ChokePointDashboard | 1 | 3 | ORPHAN | Fold into PostureMetricsHub OR delete |
| 18 | AssetRiskDashboard | 2 | 5 | DUPLICATE | Fold into AssetInventoryHub |
| 19 | CloudResourceInventoryDashboard | 2 | 4 | DUPLICATE | Fold into AssetInventoryHub |
| 20 | ComplianceCalendarDashboard | 2 | 2 | ACTIVE | Fold into ComplianceCoverageHub |

**Tallies:** 11 ACTIVE wired, 4 ORPHAN (no/partial Route), 8 DUPLICATE-of-existing-hub, plus 5 cluster candidates within ACTIVE rows.

## Section 3 — 3 Potential New Hub Clusters

### Cluster A — `ArchitectureIntelligenceHub` (3 pages)
- ArchReviewDashboard
- ArchAwareGraphDashboard
- (companion) Existing `ThreatModelingHub` — already a hub; merge ArchReview + ArchAwareGraph as tabs under it OR spin a dedicated Architecture hub if breadth grows. Cohesive "design-time security" theme.

### Cluster B — `FinOpsHub` (2 pages — needs 1 more to qualify)
- CloudCostOptimizationDashboard
- CapacityPlanningDashboard
- Below 3-page threshold; recommend folding both into existing `FinanceHub` instead of creating new hub.

### Cluster C — `AssetInventoryHub` consolidation target (5 absorbable pages)
- CMDBDashboard
- AssetRiskDashboard
- CloudResourceInventoryDashboard
- AgentlessSnapshotDashboard
- (existing) CloudAccountsDashboard (also in inventory family)
- Not a "new" hub — these all collapse INTO the live `AssetInventoryHub`. Highest-impact single-hub absorption identified in this sweep (5 pages → 1 hub tabset).

## Net Recommendation
- **Delete outright (4):** CISOReportDashboard, AirGapBundleDashboard, AIPoweredSOCDashboard, ChokePointDashboard (orphans; absorb data via existing hubs if needed).
- **Fold into existing hubs (8):** AccessRequestManagement, AISecurityAdvisor, APIThreatProtection, CloudAccessSecurity, CloudIdentity, CloudSecurityAnalytics, CMDB, CloudResourceInventory, AssetRisk, AgentlessSnapshot, CCM, ComplianceCalendar.
- **New hubs:** None warranted (Cluster A folds into ThreatModelingHub, Cluster B into FinanceHub, Cluster C into AssetInventoryHub).

Net page reduction projection if executed: ~16 of 20 → ~4-page floor (cluster anchors). 431 → ~415. Hub count stable at 48.

## Source SHA
`5767c2049ca83432fd18a7d7fa2c1f4911c60577`
