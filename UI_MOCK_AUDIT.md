# UI Mock Data Audit — 2026-05-27

**Scope:** `suite-ui/aldeci-ui-new/src/pages/**/*.tsx` (268 files; 11 test files excluded → **257 pages scanned**)

**Method:** Detect module-level uppercase `const SYMBOL = [...]` or explicit `MOCK_*` arrays that are rendered
via `.map()` without being derived from `apiFetch()`/`useQuery()`/`fetch()`, OR that serve as nullish fallbacks
(`liveData?.x ?? HARDCODED`) when the API returns empty. Static config arrays (nav menus, enum option lists,
column headers, colour palettes, filter label arrays) are explicitly excluded.

---

## Summary Counts

| Bucket | Count |
|--------|-------|
| ❌ MOCK — renders hardcoded fabricated data, zero or non-wired API call | **17** |
| 🟡 PARTIAL — has real API fetch but also renders hardcoded arrays as primary or fallback | **28** |
| 🟢 REAL — all display data from real API; only legit static config hardcoded | **212** |
| **Total pages scanned** | **257** |

---

## ❌ MOCK Pages (17) — renders fabricated data, no working API integration

| # | Page path | Hardcoded symbols | Suggested real endpoint |
|---|-----------|-------------------|------------------------|
| 1 | `VulnerabilityScanner.tsx` | `VULNS`, `SCAN_SCHEDULES`, `SEVERITY_TREND`, `SCANNERS` | `/api/v1/vuln-scans/scans`, `/api/v1/vuln-scans/schedules` |
| 2 | `VulnerabilityScannerPage.tsx` | `FINDINGS`, `SCHEDULES`, `SEVERITY_TREND`, `SCANNERS` | `/api/v1/vuln-scans/scans`, `/api/v1/vuln-scans/schedules` |
| 3 | `CyberInsurance.tsx` | `POLICIES`, `RISK_SCORES`, `CLAIMS`, `GAPS` | `/api/v1/cyber-insurance/policies` |
| 4 | `SecurityMetricsDashboard.tsx` | `TREND_DATA`, `TOP_METRICS`, `CATEGORIES`, `THRESHOLDS` | `/api/v1/security-metrics/metrics` |
| 5 | `SecurityMetricsDashboard2.tsx` | `ALERTS`, `AGGREGATES`, `METRICS` | `/api/v1/security-metrics/metrics` |
| 6 | `NetworkAnalysis.tsx` | `PROTOCOLS`, `REGIONS`, `HOURLY` (magic numbers) | `/api/v1/network-analysis/flows`, `/api/v1/network-analysis/stats` |
| 7 | `AISecurityAdvisor.tsx` | `QA_EXCHANGES` (fake CVE answers), `RECOMMENDATIONS`, `SESSIONS` | `/api/v1/ai-advisor/stats`, `/api/v1/ai-advisor/recommendations` |
| 8 | `VulnScoringDashboard.tsx` | `MODEL_WEIGHTS` | `/api/v1/vuln-scoring/vulns` |
| 9 | `CyberResilienceDashboard.tsx` | `LESSONS`, `HISTORY` | `/api/v1/cyber-resilience/score` |
| 10 | `mission-control/ComplianceDashboard.tsx` | `MOCK_FRAMEWORKS`, `MOCK_CONTROLS`, `MOCK_TIMELINE`, `MOCK_GAPS` | `/api/v1/compliance-scanner/stats`, `/api/v1/ccm/orgs/{org}/stats` |
| 11 | `mission-control/RiskRegister.tsx` | `MOCK_RISKS` (fake org names, scores) | `/api/v1/risk-register-engine/risks` |
| 12 | `risk/RiskAcceptance.tsx` | `MOCK_RECORDS` (fake finding IDs, requester names) | `/api/v1/risk-acceptance` |
| 13 | `comply/Analytics.tsx` | `SCANNER_ROI_DATA`, `HEATMAP_DATA` (fabricated scanner ROI/utilisation) | `/api/v1/analytics-engine/executive`, compliance trends endpoint |
| 14 | `comply/SLSAProvenance.tsx` | `BUILD_PROVENANCE_STEPS` rendered as live provenance timeline | `/api/v1/sbom/provenance`, `/api/v1/slsa/builds` |
| 15 | `remediate/TicketIntegration.tsx` | `AVAILABLE_INTEGRATIONS` (hardcoded Jira/ServiceNow/GitHub/Slack rows rendered as connected integrations) | `/api/v1/integrations/ticketing` |
| 16 | `discover/CloudPosture.tsx` | `FRAMEWORK_DATA` (hardcoded CIS/NIST/PCI posture framework rows) | `/api/v1/cloud-posture/frameworks` |
| 17 | `discover/IaCScanning.tsx` | `CIS_CONTROLS` (hardcoded CIS control pass/total counts all zero) | `/api/v1/config-benchmark/stats` |

---

## 🟡 PARTIAL Pages (28) — real API fetch exists but hardcoded arrays also rendered (primary or fallback)

All 28 pages have an `apiFetch()`/`useQuery()` call. The hardcoded arrays serve either as:
- **Fallback** (`liveData?.x ?? HARDCODED`) — shown when API returns empty/error, polluting real tenants
- **Primary** (rendered unconditionally alongside API data, or in tabs the API doesn't cover)

| # | Page path | Hardcoded symbols (role) | API endpoint wired |
|---|-----------|--------------------------|-------------------|
| 1 | `ThreatHuntingDashboard.tsx` | `CAMPAIGNS`/`FINDINGS` (fallback), `PLAYBOOKS`/`QUERIES` (primary) | `/api/v1/threat-hunting/stats` |
| 2 | `SecurityHealthDashboard.tsx` | `CHECKS`/`INCIDENTS` (fallback), `TREND`/`DOMAINS` (primary) | `/api/v1/security-health/stats` |
| 3 | `SecurityChampionsDashboard.tsx` | `CHAMPIONS`/`CAMPAIGNS` (fallback), `ACTIVITIES`/`CERTIFICATIONS`/`LEVEL_DISTRIBUTION` (primary) | `/api/v1/security-champions/stats` |
| 4 | `CCMDashboard.tsx` | `FAILURES`/`CONTROLS` (fallback), `TEST_HISTORY`/`FRAMEWORKS` (primary) | `/api/v1/ccm/orgs/{org}/stats` |
| 5 | `ConfigBenchmarkDashboard.tsx` | `PROFILES` (fallback), `CHECK_RESULTS`/`SCORE_BY_STANDARD`/`FAILED_CHECKS` (primary) | `/api/v1/config-benchmark/stats` |
| 6 | `VulnTrendDashboard.tsx` | `COHORTS`/`WEEKLY_TREND`/`SLA_ROWS` (fallback), `TREND_ANALYSIS` (primary) | `/api/v1/vuln-trends/stats` |
| 7 | `ComplianceScannerDashboard.tsx` | `TASKS`/`SCAN_RESULTS`/`PROFILES` (fallback), `FRAMEWORK_SCORES` (primary) | `/api/v1/compliance-scanner/stats` |
| 8 | `MobileSecurity.tsx` | `THREATS`/`DEVICES` (fallback), `PLATFORMS`/`MDM_POLICIES`/`COMPLIANCE_TREND` (primary) | `/api/v1/edr/stats` |
| 9 | `NDRDashboard.tsx` | `TOP_TALKERS`/`ALERTS` (fallback), `SEGMENTS`/`ANOMALIES` (primary — fake IPs 10.x/192.168.x) | `/api/v1/ndr/stats` |
| 10 | `DevSecOpsDashboard.tsx` | `PIPELINES`/`FINDINGS` (fallback), `GATE_POLICIES`/`BUILD_HISTORY` (primary) | `/api/v1/devsecops/stats` |
| 11 | `PasswordPolicy.tsx` | `VIOLATIONS`/`AUDITS` (fallback), `STRENGTH_DIST`/`POLICIES` (primary) | `/api/v1/password-policy/stats` |
| 12 | `VulnRiskQueue.tsx` | `QUEUE` (fallback), `RISK_ACCEPTANCE`/`DISTRIBUTION`/`TEAMS` (primary) | `/api/v1/vuln-prioritization/scored` |
| 13 | `RegulatoryTrackerDashboard.tsx` | `UPCOMING_CHANGES` (fallback), `ASSESSMENTS`/`CATALOG`/`OBLIGATIONS` (primary) | `/api/v1/regulatory/stats` |
| 14 | `ThreatCorrelation.tsx` | `RULES`/`EVENT_STREAM`/`ALERTS` (fallback) | `/api/v1/incident-timeline/events` |
| 15 | `DataGovernanceDashboard.tsx` | `POLICIES`/`VIOLATIONS`/`ASSETS` (fallback), `FLOWS` (primary) | `/api/v1/data-governance/stats` |
| 16 | `GRCDashboard.tsx` | `FRAMEWORKS`/`RISKS`/`ASSESSMENTS` (fallback), `CONTROLS` (primary) | `/api/v1/grc/stats` |
| 17 | `NetworkTrafficDashboard.tsx` | `ANOMALOUS_FLOWS`/`TOP_TALKERS`/`TRAFFIC_RULES` (fallback), `PROTOCOLS` (primary — fake IPs) | `/api/v1/network-traffic/stats` |
| 18 | `CrossDomainAnalytics.tsx` | `ASSET_VULN`/`DOMAINS` (fallback), `IOC_RESULTS`/`EXEC_SUMMARY`/`TREND` (primary — fake CVEs) | `/api/v1/analytics-engine/executive` |
| 19 | `discover/ContainerSecurity.tsx` | `REGISTRIES` (primary — hardcoded Docker Hub/ECR/GCR rows) | `/api/v1/container-security/registries` |
| 20 | `discover/CorrelationEngine.tsx` | `VULN_GROUPS` (primary) | `/api/v1/findings/correlate` |
| 21 | `discover/SBOMInventory.tsx` | `LICENSE_TYPES`/`LICENSE_COLORS` used to label chart slices from API data | `/api/v1/sbom/inventory` — partial |
| 22 | `ai/Copilot.tsx` | `SAMPLES` — legit UI prompt suggestions; borderline | `/api/v1/copilot` — real |
| 23 | `mission-control/RiskOverview.tsx` | `HEATMAP_ROWS`/`HEATMAP_COLS` — static axis labels; borderline config | `/api/v1/risk-scoring/summary` |
| 24 | `comply/AuditorEvidenceHub.tsx` | `FRAMEWORK_LABELS` used to synthesise placeholder rows when API returns fewer frameworks | `/api/v1/compliance-scanner/evidence` |
| 25 | `comply/EvidenceExportCenter.tsx` | `FRAMEWORKS`/`INCLUDE_OPTIONS`/`FORMATS`/`GENERATION_STAGES` — form config; primarily legit | `/api/v1/compliance-scanner/evidence` |
| 26 | `comply/Reports.tsx` | `REPORT_TEMPLATES`/`FRAMEWORKS`/`FORMATS` — template config, borderline | `/api/v1/reports` |
| 27 | `findings/FindingsExplorer.tsx` | `SCANNERS` — filter label list (legit config); real data from API | `/api/v1/findings` |
| 28 | `VulnScanDashboard.tsx` | `SCANNER_TYPES` — scanner filter chips (legit config); real trigger from API | `/api/v1/vuln-scans/scans` |

---

## Top 15 ❌ Evidence Samples

1. **VulnerabilityScanner.tsx** — `VULNS` = 8+ hardcoded CVE rows with fake asset names (`web-frontend-01`, `prod-db-02`), fake IPs, fake dates; `SCAN_SCHEDULES` = 8 fabricated scan jobs with CIDR ranges like `10.0.0.0/8`. Rendered unconditionally on `.map()`. API fetch only loads on mount but state is never seeded from it.

2. **VulnerabilityScannerPage.tsx** — Identical structure to VulnerabilityScanner.tsx; separate duplicate page with same `FINDINGS`, `SCHEDULES`, `SEVERITY_TREND`, `SCANNERS` arrays.

3. **CyberInsurance.tsx** — `POLICIES` has carrier names, policy numbers, premiums. `CLAIMS` has 6 fabricated claim records (`CLM-2024-001` through `CLM-2026-006`) with dollar amounts, adjuster names (Marsh & McLennan, Aon Cyber). `RISK_SCORES` and `GAPS` also hardcoded. All four rendered via `.map()`.

4. **mission-control/ComplianceDashboard.tsx** — Explicit `MOCK_FRAMEWORKS`, `MOCK_CONTROLS`, `MOCK_TIMELINE`, `MOCK_GAPS` with `alice@corp.com`, `bob@corp.com` owner emails, fabricated compliance percentages. useQuery fires but on error/empty the mock arrays are returned directly: `return { frameworks: MOCK_FRAMEWORKS, controls: MOCK_CONTROLS, ... }`.

5. **mission-control/RiskRegister.tsx** — `MOCK_RISKS` with fake owner names (`Sarah Chen`), fake SQL-injection/supply-chain descriptions, fabricated likelihood/impact scores. State initialised to `MOCK_RISKS`; API result replaces it but falls back to `MOCK_RISKS` on failure.

6. **risk/RiskAcceptance.tsx** — Explicit `MOCK_RECORDS` with fake requester names (`Jordan Lee`), fake finding IDs (`FND-1892`), fake expiry dates. `useState(MOCK_RECORDS)` as initial state; API result replaces on success, `setRecords(MOCK_RECORDS)` on any error.

7. **AISecurityAdvisor.tsx** — `QA_EXCHANGES` contains pre-scripted question/answer pairs with hardcoded CVE-2024-3400 advisories ("847 expired service account credentials across cloud workloads", "41% risk reduction"). Rendered as chat placeholders. Real recommendations also have a `RECOMMENDATIONS` fallback array.

8. **SecurityMetricsDashboard.tsx** — `TREND_DATA`, `TOP_METRICS`, `CATEGORIES`, `THRESHOLDS` all rendered unconditionally. `TREND_DATA` has 12 months of fabricated percentages. Despite an `apiFetch` call, `TOP_METRICS` only falls back to live data (`liveTopMetrics`); three other arrays are always primary.

9. **comply/Analytics.tsx** — `SCANNER_ROI_DATA` fabricates ROI numbers (Snyk 4.2x, SonarQube 3.1x, etc.). Used as `trends.scanner_roi_data ?? SCANNER_ROI_DATA` — if real API returns anything in that field it shows real data, but the comment says "Replace with real utilization metrics when available". `HEATMAP_DATA` similarly fabricated.

10. **discover/CloudPosture.tsx** — `FRAMEWORK_DATA` = 6 hardcoded framework name/key pairs; `FRAMEWORK_DATA.map()` drives the framework comparison table unconditionally. The API only provides posture resource data; framework rows are always fake.

11. **NDRDashboard.tsx (PARTIAL)** — `SEGMENTS` contains real-looking network segments with CIDRs (`192.168.50.0/24`, `10.4.0.0/16`). `ANOMALIES` has fabricated IPs with deviation scores. Rendered as primary (not behind `??` fallback) even when `liveData` exists.

12. **NetworkAnalysis.tsx** — `HOURLY = [12,8,6,5,7,10,18,34,52,61,68,74,71,65,69,72,78,85,91,88,76,58,34,20]` magic number array for traffic chart. `PROTOCOLS` and `REGIONS` also hardcoded with counts. Rendered as primary chart data.

13. **remediate/TicketIntegration.tsx** — `AVAILABLE_INTEGRATIONS` lists Jira, ServiceNow, GitHub, GitLab, PagerDuty, Slack rows. These are rendered as the integration catalogue; user sees these as "available connectors" without any API call confirming which are actually configured.

14. **comply/SLSAProvenance.tsx** — `BUILD_PROVENANCE_STEPS` defines the 5-step provenance pipeline diagram. Rendered as a live timeline but the steps are static and the diagram shows a fake build flow rather than real build attestation data.

15. **discover/IaCScanning.tsx** — `CIS_CONTROLS` has 4 hardcoded CIS controls with `pass: 0, total: 0` — clearly a placeholder that will always show 0/0 counts regardless of what the API returns. The real `pass`/`total` values should come from `/api/v1/config-benchmark/stats`.

---

## Pages Confirmed 🟢 REAL (selected)

`APISecurityPage.tsx` (comment: "zero hardcoded arrays"), `ArchReviewDashboard.tsx`, `findings/FindingsExplorer.tsx` (SCANNERS is legit filter config), `hunting/ThreatHunting.tsx` (TACTIC_OPTIONS/DATA_SOURCES are legit filter enums), `validate/AttackSimulation.tsx` (KILL_CHAIN_PHASES are legit phase-label config), `remediate/ExposureCases.tsx` (LIFECYCLE_STATES/DECISION_OPTIONS are enum config), `discover/SBOMInventory.tsx` (LICENSE_COLORS/LICENSE_TYPES are chart palette config), `admin/WebhooksOutboundPage.tsx` (TOPICS is event-type enum), `ai/CopilotDashboard.tsx` (QUICK_ACTIONS are prompt shortcuts, MODEL_OPTIONS are mode selector config), `AICopilotAgentsHub.tsx` (AGENT_ROLES is enum/type list), `AdminUsersPage.tsx`/`AdminApiKeysPage.tsx` (ROLES are enum lists), all ~195 remaining pages with no uppercase const arrays and real API calls.

---

## Notes

- **VulnerabilityScanner.tsx and VulnerabilityScannerPage.tsx are near-identical duplicates** — both are ❌ MOCK. One should be deleted as part of the UX consolidation.
- **Fallback pattern (`liveData?.x ?? HARDCODED`)** is the dominant issue in PARTIAL pages — these will show fake data any time the API returns `null`/`undefined`/empty array, which is common in a fresh tenant.
- **Suggested fix pattern:** Replace `?? HARDCODED` with `?? []` and add a branded `<EmptyState>` component instead of silently showing fabricated rows.
