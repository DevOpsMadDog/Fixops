# UX Consolidation Plan — Phase 3 (89→30 Screens)

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Author:** ux-architect agent (Phase 3 planning)
**Inputs:**
- `docs/competitive_validation_2026-04-26.md` (Phase 2 — 83% WIN/MATCH gate, hybrid Wiz+Apiiro shape recommended)
- `suite-ui/aldeci-ui-new/src/App.tsx` (470 routes covering ~375 page files)
- `docs/ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md` (25 enterprise personas, tiered roles)
- 15 sample page reads (`IssueQueue`, `SecurityGraph`, `BrainVisualization`, `ChokePointDashboard`, `WaiversExplorer`, `ToxicCombinationIssueView`, `MainOverviewDashboard`, `CISOReportDashboard`, `AttackPathInteractiveGraph`, `CNAPPDashboard`, `SBOMContinuousMonitoring`, `MaterialChangeDashboard`, `CopilotGraphChat`, `ConnectorMappingUI`, `CrownJewelConfigurator`)

> **Mandate:** Stop building new pages. Collapse 89 unique frontend screens into 25–35 cohesive enterprise screens with 8 top-level nav items. Zero functionality loss, zero endpoint disconnection. Each existing page → reborn as tab / drill-down / widget / modal / split-pane in a target screen.

---

## 0. TL;DR

- **Target:** 30 cohesive screens, 8 top-level nav items.
- **Source surface:** 470 declared routes, 89 distinct logical screens after dedup (the rest are alias routes, redirects, or modal sub-routes already nested).
- **Phase split:** P0 = 6 screens (hero + Issues + Graph + Brain + Compliance + Settings), P1 = 14 screens (per-domain tabbed dashboards), P2 = 10 screens (deep moats + admin tail).
- **Persona-regression risk:** 0/25 personas lose a workflow — every persona's primary workflow has a target landing screen + drill-in path mapped below.
- **Migration:** every retired route gets a `<Navigate>` redirect to its target screen + tab anchor for 90 days.
- **Implementation discipline:** NO new `.tsx` files — all consolidation is *route collapse + tab composition* of existing pages, reusing the shared `PageHeader / KpiCard / EmptyState / ErrorState / Tabs / Card` library already shipped.

---

## 1. Target Shape — 30 Screens, 8 Nav Items

```
┌─ Top-level navigation (8) ────────────────────────────────────────────────┐
│ 1. Mission Control     2. Issues       3. Discover      4. Attack         │
│ 5. Brain (Hero)        6. Remediate    7. Comply        8. Connect        │
│                                                                  + Admin  │
└──────────────────────────────────────────────────────────────────────────┘
```

`Admin` is a settings cog in the top bar (not a nav item) per Wiz/Apiiro convention.

### 1.1 Mission Control (4 screens)

| # | Screen | Tabs / sub-views | Hero data | Primary persona |
|---|---|---|---|---|
| **S1** | **Command Dashboard** (route `/`) | All Roles · CISO · CTO · Engineering · SOC | Posture score gauge + KPIs + Live event feed + critical findings table | All execs (1–4), Vuln Mgr (9) |
| **S2** | **Executive Brief** (route `/mission-control/executive`) | Risk Overview · BRS Heatmap · ROI · Investment | Dollar-risk by BU + ROI-of-fixes + scheduled reports | CISO (1), CFO (4), CTO (3) |
| **S3** | **SOC Operations** (route `/mission-control/soc`) | Live Feed · Triage Queue · T1 Console · T2 Deep · KPIs | Real-time SIEM/UBA/IOC feed + alert triage | SOC T1 (5), SOC T2 (6), IR (7) |
| **S4** | **SLA & Risk Register** (route `/mission-control/sla`) | SLAs · Register · Acceptance · Treatment · Scenarios | SLA breach burn-down + risk register + acceptance workflow | Vuln Mgr (9), Sec Architect (11) |

### 1.2 Issues — Hero (Wiz pattern) (3 screens)

| # | Screen | Tabs | Source pattern |
|---|---|---|---|
| **S5** | **Issues Queue (HERO)** (route `/issues`) | All · Critical · High · Toxic Combos · KEV-Active · Drift · Material Changes · PR Risk | Wiz single Issues hero — collapses 18+ existing dashboards into one queue with severity/source filters |
| **S6** | **Issue Detail** (route `/issues/:id`) | Overview · Reachability Proof · Toxic Combo Graph · AutoFix · Waiver · Audit | Drill-down from S5; combines Snyk Issue page + Apiiro DCA panel |
| **S7** | **Findings Explorer** (route `/findings`) | Findings · Drift · Stale Baselines · Snapshot Findings · Cloud Findings · Security Findings | Power-user table view (Snyk-style projects/findings split) for deep filtering |

### 1.3 Discover — Graph-as-Substrate (Apiiro pattern) (4 screens)

| # | Screen | Side panels |
|---|---|---|
| **S8** | **Asset Graph (HERO)** (route `/discover`) | Side panels: Architecture Layers · Components · Reachability · DCA · Subsidiaries · Crown Jewels · DB Connections |
| **S9** | **Inventory** (route `/discover/inventory`) | Tabs: Assets · Apps · Cloud Resources · APIs · Containers · SBOM · Components · Org Hierarchy · CMDB |
| **S10** | **Code Intelligence** (route `/discover/code`) | Tabs: Code Scan · Semantic · Call Graph · Arch Layers · Component Identity · PII Inventory · Deep Code Analysis · Code-to-Runtime |
| **S11** | **Cloud Posture** (route `/discover/cloud`) | Tabs: CSPM · CWPP · CIEM · CNAPP · IaC · Containers · K8s · SaaS Posture · Cloud Compliance · Cost · Inventory · Identity · Accounts |

### 1.4 Attack (XM Cyber pattern) (3 screens)

| # | Screen | Tabs |
|---|---|---|
| **S12** | **Attack Paths (HERO)** (route `/attack`) | Graph · Choke Points · Blast Radius · Attack Chains · Threat Vectors · Attack Surface · EASM (Subsidiaries + Domain Seed) |
| **S13** | **MPTE Console** (route `/attack/mpte`) | Run · 19-Phase Trace · Reachability Proof · Simulation Library · Red Team Status |
| **S14** | **Threat Intel** (route `/attack/intel`) | Feeds · Actors · Indicators · Confidence · Geolocation · Dark Web · Zero-Day · Briefs · Landscape · Attribution · IOC Hunter |

### 1.5 Brain — Unique Moat Hero (4 screens)

| # | Screen | Tabs |
|---|---|---|
| **S15** | **Brain Pipeline (HERO)** (route `/brain`) | Pipeline (12-step viz) · Multi-LLM Consensus · Algorithmic Lab · Predictions · ML Dashboard · NL Trace · Score Transparency · Factor Weights |
| **S16** | **MPTE Verification** (route `/brain/mpte`) | (alias of S13 deep-dive surface — exposed both under Attack and Brain because it serves Sec Analyst + Threat Hunter equally) |
| **S17** | **FAIL Chaos** (route `/brain/fail`) | Campaigns · Playbook Library · Editor · Security Chaos · Tabletop · Deception · Deception Analytics |
| **S18** | **AI Copilot** (route `/brain/copilot`) | Chat · Graph NL Query · Traversal Trace · Shadow AI · AI Agents Console · Agent Tasks · Copilot Dashboard · LLM Cost Tier · Pre-Flight Estimate · Rule Editor |

### 1.6 Remediate (Sonatype + Snyk pattern) (4 screens)

| # | Screen | Tabs |
|---|---|---|
| **S19** | **Remediation Center** (route `/remediate`) | Open · AutoFix · Bulk · Workflows · Tickets · Cases · Collaborate · Autonomous · Patch Mgmt · Patch Prioritizer · Posture Advisor |
| **S20** | **Waivers & Exceptions** (route `/remediate/waivers`) | Explorer · Auto Rules · Request Modal · Risk Acceptance · Exceptions · Exception Workflow |
| **S21** | **Upgrade Paths** (route `/remediate/upgrade`) | Resolver · Component Version Graph · Dependency Mapping · Dependency Risk · Upgrade Explorer · Binary Fingerprint |
| **S22** | **Incident Response** (route `/remediate/incidents`) | IR Console · Playbooks · IR Playbook Library · Timeline · Comms · Costs · Lessons · KB · Metrics · Breach Response · Forensics · Malware Analysis · Cloud IR |

### 1.7 Comply (Sonatype/Veracode pattern) (4 screens)

| # | Screen | Tabs |
|---|---|---|
| **S23** | **Compliance Dashboard** (route `/comply`) | Frameworks · SOC2 · SLSA · FIPS · GRC · Cloud Compliance · Endpoint Compliance · Privacy/GDPR · Calendar · Gaps · Mapping · Workflows · Automation · Regulatory Tracker · Maturity · Scorecard · Benchmarks · CCM · Questionnaires |
| **S24** | **Evidence Vault** (route `/comply/evidence`) | Vault · Bundles · Export Center · Audit Trail · Audit Explorer · Reports · Scheduled Reports · Posture Reports |
| **S25** | **SBOM & Provenance** (route `/comply/sbom`) | Inventory · Continuous Monitoring · Export · Pipeline BOM · PBOM Propagation · Attestation · Sign · SLSA Provenance |
| **S26** | **Policies & Rules** (route `/comply/policies`) | Stage Matrix · Stage Editor · Inheritance · Library · Hooks Policy · Hooks Status · Rules Catalog · Rule DSL Author · DSL Validator · Rule Taxonomy · Dynamic DSL · Violation Lifecycle |

### 1.8 Connect (Cycode ConnectorX pattern) (2 screens)

| # | Screen | Tabs |
|---|---|---|
| **S27** | **Integrations Hub** (route `/connect`) | Marketplace · Active Connectors · Health · Mapping · Mapping Dry-Run · Universal Tester · Webhooks · Event Catalogue · Retry Queue · GitHub App · API Explorer · Developer Portal · ServiceNow · Splunk/Sentinel · Prowler · Snyk · IDE Backend |
| **S28** | **MCP Gateway (HERO)** (route `/connect/mcp`) | Tool Registry (650+) · Skills Registry · Skills Install · OpenClaw · Claude Skills · Air-Gap Bundle · Air-Gap Feeds · Update Status · Local Store |

### 1.9 Admin (top-bar cog, 2 screens)

| # | Screen | Tabs |
|---|---|---|
| **S29** | **Admin Console** (route `/admin`) | Users · Teams · Tokens · RBAC · Org Hierarchy · Scopes · Tenant Settings · Pricing |
| **S30** | **System Health** (route `/admin/system`) | Health · Logs · Capacity · Telemetry · Tool Inventory · System Status · FIPS Status · Local Store Status |

**Screen total = 30. Top-level nav = 8. Below the nav-item budget cap.**

---

## 2. Source-to-Target Merge Map

89 unique logical screens (after collapsing 470 routes through dedup of duplicates, alias redirects, and same-component-different-path entries). For each, the column "as" specifies the rendering pattern: **tab** (peer view inside target), **drill** (linked detail page), **widget** (composited block within target screen), **modal** (overlay), **split-pane** (side-panel inside graph canvas), **CTA** (empty-state action).

### 2.1 → S1 Command Dashboard
| Source page | Existing endpoint | As |
|---|---|---|
| `CommandDashboard` (root) | `/api/v1/posture-score/current` + `/api/v1/alert-triage/stats` | hero |
| `MainOverviewDashboard` | `/api/v1/posture-score/current`,`/api/v1/compliance/status`,`/api/v1/vuln-intel/stats`,`/api/v1/incident-orchestration/incidents`,`/api/v1/feeds/config` | widget (replaces hero gauge) |
| `LiveFeed` | `/api/v1/streaming/events` (SSE) | widget (right rail) |
| `RiskOverview` | `/api/v1/risk/overview` | tab |
| `BRSExecutiveDashboard` | `/api/v1/brs/executive` | tab |
| `SecurityKPIDashboard` / `SecurityMetricsDashboard` / `SecurityMetricsDashboard2` | `/api/v1/metrics/kpis` | widget (KPI strip) |
| `MissionControlComplianceDashboard` | `/api/v1/compliance/status` | widget |
| `DevSecurityDashboard` | `/api/v1/devsec/overview` | tab |
| `SecurityHealthDashboard` / `SecurityHealthScorecardDashboard` | `/api/v1/health/scorecard` | widget |
| `SecurityScorecardDashboard` | `/api/v1/scorecards` | widget |
| `PostureScoringDashboard` / `SecurityPostureDashboard` / `SecurityPostureMaturityDashboard` | `/api/v1/posture-score/*` | widget |
| `ProgramMaturityDashboard` | `/api/v1/maturity/program` | widget |

### 2.2 → S2 Executive Brief
**Finance/Investment sub-cluster: DONE-2026-05-02 SHA=852c7805** — 5 pages folded into FinanceHub.tsx at `/mission-control/finance` (BUDollarRiskHeatmap, SecurityInvestmentDashboard, SecurityBudgetDashboard, IncidentCostsDashboard, CyberInsuranceDashboard). Old routes redirect with `?tab=`.

| Source | Endpoint | As |
|---|---|---|
| `ExecutiveView` | `/api/v1/executive/view` | hero |
| `CISODashboard` / `CISOReportDashboard` | `/api/v1/ciso-report/sections` | tab |
| `ExecutiveBriefing` / `ExecutiveReportingDashboard` / `ExecutiveRiskReport` | `/api/v1/executive/*` | tab |
| `BUDollarRiskHeatmap` | `/api/v1/risk/by-bu` | widget (heatmap) |
| `SecurityInvestmentDashboard` / `SecurityBudgetDashboard` / `IncidentCostsDashboard` | `/api/v1/finance/*` | tab (Investment) |
| `CapacityPlanningDashboard` | `/api/v1/capacity/plan` | widget |
| `SecurityOKRDashboard` | `/api/v1/okrs` | widget |
| `SecurityRoadmap` | `/api/v1/roadmap` | tab |
| `CyberInsuranceDashboard` / `CyberInsurance` (legacy) | `/api/v1/cyber-insurance` | widget |
| `ScheduledReportsDashboard` | `/api/v1/reports/scheduled` | tab |

### 2.3 → S3 SOC Operations
| Source | Endpoint | As |
|---|---|---|
| `SOCDashboard` / `SecurityOperationsCenter` | `/api/v1/soc/overview` | hero |
| `SOCT1Dashboard` | `/api/v1/soc/t1` | tab |
| `SOCTriageDashboard` / `AlertTriageDashboard` | `/api/v1/alert-triage/*` | tab |
| `AlertEnrichmentDashboard` / `IntelEnrichmentDashboard` | `/api/v1/alerts/enrich` | widget |
| `IncidentResponse` / `IncidentResponseDashboard` | `/api/v1/incidents` | drill (→ S22) |
| `IncidentTimeline` / `IncidentTimelineDashboard` / `EventTimelineDashboard` | `/api/v1/incidents/timeline` | tab |
| `SecurityOperationsMetricsDashboard` / `SOCMetrics` | `/api/v1/soc/metrics` | tab |
| `IOCHunter` / `EndpointHuntingDashboard` / `ThreatHunting` / `ThreatHuntingPage` / `ThreatHuntingDashboard` / `HuntingPlaybookDashboard` / `HuntingAutomationDashboard` | `/api/v1/hunting/*` | tab (Hunt) |
| `UBADashboard` / `BehavioralAnalyticsDashboard` / `InsiderThreatMonitor` | `/api/v1/uba/*` | tab |
| `WatchlistManager` | `/api/v1/watchlist` | widget |
| `NetworkMonitoringDashboard` / `NetworkAnomalyDashboard` / `NetworkThreatsDashboard` / `NetworkTrafficDashboard` / `NetworkForensicsDashboard` / `NetworkAnalysis` / `NetworkTopology` | `/api/v1/network/*` | tab (Network) |
| `NDRDashboard` / `XDRDashboard` / `EDRDashboard` / `ITDRDashboard` | `/api/v1/{ndr,xdr,edr,itdr}` | tab (Detect & Respond) |
| `MITREAttackDashboard` | `/api/v1/mitre/attack` | widget |
| `DigitalForensicsDashboard` | `/api/v1/forensics` | tab |

### 2.4 → S4 SLA & Risk Register
| Source | Endpoint | As |
|---|---|---|
| `SLADashboard` / `SLADashboardPage` | `/api/v1/sla/*` | hero |
| `RiskRegister` / `RiskRegisterPage` / `RiskRegisterDashboard` | `/api/v1/risk-register` | tab |
| `RiskAcceptance` | `/api/v1/risk/acceptance` | tab |
| `RiskTreatmentDashboard` | `/api/v1/risk/treatment` | tab |
| `RiskScenarioDashboard` | `/api/v1/risk/scenarios` | tab |
| `RiskQuantification` / `RiskQuantDashboard` | `/api/v1/risk/quant` | tab |
| `ApplicationRiskDashboard` / `AssetRiskDashboard` / `IdentityRiskDashboard` / `VendorRiskDashboard` / `SupplyChainDashboard` / `SupplyChainSecurity` / `SecurityDependencyRiskDashboard` | `/api/v1/risk/{app,asset,identity,vendor,supply}` | tab (By Domain) |

### 2.5 → S5 Issues Queue (HERO)
| Source | Endpoint | As |
|---|---|---|
| `IssueQueue` | `/api/v1/findings?status=new` | hero |
| `FindingExplorer` / `FindingsExplorer` / `SecurityFindingsDashboard` / `CloudSecurityFindingsDashboard` | `/api/v1/findings` | tab (All) |
| `VulnRiskQueue` | `/api/v1/vuln-risk/queue` | tab (Critical) |
| `VulnPrioritizationDashboard` / `VulnScoringDashboard` / `VulnHeatmap` / `VulnTrendDashboard` / `VulnerabilityAgeDashboard` | `/api/v1/vuln-prioritization/*` | tab (Prioritized) |
| `ToxicCombinationIssueView` | `/api/v1/issues/toxic` | tab (Toxic Combos) |
| `MaterialChangeDashboard` | `/api/v1/changes/material` | tab (Material Changes) |
| `PRChangeRiskPanel` | `/api/v1/pr/change-risk` | tab (PR Risk) |
| `DriftTrackingPanel` / `StaleBaselineBanner` | `/api/v1/drift/*` | tab (Drift) |
| `VulnLifecyclePage` / `VulnLifecycle` / `VulnWorkflowDashboard` / `ViolationLifecycleDashboard` / `ViolationLifecycleTimeline` | `/api/v1/vuln/lifecycle` | tab (Lifecycle) |
| `VulnerabilityCorrelationDashboard` / `ThreatCorrelation` / `CorrelationEngine` | `/api/v1/correlation/*` | widget (group rail) |
| `AlertEnrichmentDashboard` (cross-link) | shared | widget |
| `SecurityExceptionDashboard` | `/api/v1/exceptions` | drill (→ S20) |

### 2.6 → S6 Issue Detail
| Source | Endpoint | As |
|---|---|---|
| `Reachability` / `ReachabilityProof` | `/api/v1/reachability/{id}` | tab |
| `RuntimeCodeTrace` | `/api/v1/runtime/trace` | tab |
| `AutoFix` | `/api/v1/autofix/{id}` | tab |
| `WaiverRequestModal` | `/api/v1/waivers/request` | modal CTA |
| `ScoreTransparencyPanel` / `FactorWeightsView` | `/api/v1/scoring/transparency` | widget (right rail) |
| `BinaryFingerprintDashboard` | `/api/v1/binary/fingerprint` | widget |

### 2.7 → S7 Findings Explorer
| Source | Endpoint | As |
|---|---|---|
| `FindingsExplorer` | `/api/v1/findings` | hero (table) |
| `SnapshotFindingsView` | `/api/v1/snapshot/findings` | tab |
| `AgentlessScanStatus` / `AgentlessSnapshotDashboard` | `/api/v1/agentless/*` | widget |
| `VulnIntelligenceDashboard` / `VulnIntelFusionDashboard` | `/api/v1/vuln-intel/*` | tab |
| `CVESearch` | `/api/v1/cve/search` | tab |
| `IPReputation` / `IPReputationDashboard` | `/api/v1/ip-reputation` | widget |
| `ThreatGeolocationDashboard` | `/api/v1/threats/geo` | widget |

**Vuln Intelligence sub-cluster: DONE-2026-05-02 SHA=a205bbc8** — 4 pages folded into `VulnIntelHub.tsx` at `/discover/vuln-intel` (VulnIntelligenceDashboard, CVESearch, IPReputationDashboard, ThreatGeolocationDashboard). Old routes redirect with `?tab=`. Verified: 9 real `/api/v1/vuln-intel/*` calls, 0 mock signatures, 0 page errors. Screenshot: `docs/ui-snapshots/ux-consolidation-vuln-intel-2026-05-02.png`.

### 2.8 → S8 Asset Graph (HERO)
| Source | Endpoint | As |
|---|---|---|
| `KnowledgeGraph` / `SecurityGraph` | `/api/v1/graph/query/*` | hero canvas |
| `BrainVisualization` | `/api/v1/brain/{stats,nodes}` | split-pane (Neural overlay toggle) |
| `ArchitectureLayerGraph` / `ArchAwareGraphDashboard` / `ArchReviewDashboard` | `/api/v1/graph/arch-layers` | side-panel (Architecture) |
| `CallGraphExplorer` | `/api/v1/graph/callgraph` | side-panel (Call Graph) |
| `CodeSemanticExplorer` | `/api/v1/code/semantic` | side-panel (Semantic) |
| `DiffModeGraphCanvas` | `/api/v1/graph/diff` | mode toggle |
| `GraphPerfDashboard` | `/api/v1/graph/perf` | widget (perf badge) |
| `DBConnectionOverlay` | `/api/v1/graph/databases` | overlay |
| `ComponentVersionGraph` / `DependencyMappingDashboard` | `/api/v1/components/version-graph` | side-panel (Components) |
| `CodeToRuntimeDashboard` | `/api/v1/code-to-runtime` | side-panel |
| `SubsidiaryAttributionGraph` / `DomainSeedDiscoveryWizard` | `/api/v1/easm/*` | side-panel (EASM) |
| `CrownJewelConfigurator` | `/api/v1/assets/{id}/crown-jewel-tag` | modal CTA from node |
| `ComponentIdentityView` | `/api/v1/components/identity` | side-panel |
| `OrgHierarchyExplorer` / `OrgHierarchyDashboard` | `/api/v1/orgs` | filter pane |

### 2.9 → S9 Inventory
| Source | Endpoint | As |
|---|---|---|
| `AssetInventory` / `AssetInventoryPage` | `/api/v1/assets` | hero (table) |
| `AssetGroupsDashboard` / `AssetTagsDashboard` / `AssetCriticalityDashboard` | `/api/v1/assets/{groups,tags,criticality}` | tab |
| `APIInventoryDashboard` / `APIDiscoveryDashboard` | `/api/v1/api-inventory` | tab (APIs) |
| `CMDBDashboard` | `/api/v1/cmdb` | tab |
| `CloudResourceInventoryDashboard` / `CloudAccountsDashboard` | `/api/v1/cloud/inventory` | tab (Cloud) |
| `ContainerRegistryDashboard` | `/api/v1/containers/registry` | tab (Containers) |
| `SBOMInventory` / `SBOMManagement` / `SBOMDashboard` | `/api/v1/sbom` | tab (SBOM) |
| `SecurityToolInventoryDashboard` / `SecurityRegistryDashboard` | `/api/v1/tools/inventory` | tab (Tools) |
| `ServiceCatalogDashboard` | `/api/v1/service-catalog` | tab |
| `OrgHierarchyDashboard` | shared | filter |
| `ScopeManager` | `/api/v1/scopes` | filter |
| `DataDiscoveryDashboard` / `DataClassificationDashboard` / `DataGovernanceDashboard` / `PIIFieldInventory` | `/api/v1/data/*` | tab (Data) |

### 2.10 → S10 Code Intelligence
| Source | Endpoint | As |
|---|---|---|
| `CodeScanning` | `/api/v1/code/scan` | hero |
| `CodeSemanticExplorer` (cross-link) | shared | tab |
| `CallGraphExplorer` | shared | tab |
| `DeepCodeAnalysisDashboard` | `/api/v1/code/deep` | tab |
| `ArchAwareGraphDashboard` (cross-link) | shared | tab |
| `ArchitectureLayerGraph` (cross-link) | shared | tab |
| `ComponentIdentityView` (cross-link) | shared | tab |
| `PIIFieldInventory` (cross-link) | shared | tab |
| `SecretsDetection` / `SecretScannerDashboard` / `SecretsRotation` | `/api/v1/secrets/*` | tab (Secrets) |
| `SCADashboard` | `/api/v1/sca` | tab (SCA) |
| `IaCScanning` | `/api/v1/iac` | tab (IaC) |
| `DASTDashboard` | `/api/v1/dast` | tab (DAST) |
| `APISecurityDashboard` / `APISecurityPage` / `APISecurityMgmtDashboard` / `APIAbuseDashboard` / `APIThreatProtectionDashboard` | `/api/v1/api-security/*` | tab (API Sec) |
| `AppSecurity` / `MobileSecurity` / `MobileAppSecurityDashboard` / `BrowserSecurityDashboard` | `/api/v1/{app,mobile,browser}-sec` | tab (App Sec) |
| `LicenseSecurity` / `SoftwareLicenseDashboard` | `/api/v1/licenses` | tab |
| `SupplyChainIntelDashboard` / `SupplyChainAttackDashboard` | `/api/v1/supply-chain/*` | tab (Supply Chain) |
| `MalwareAnalysisDashboard` | `/api/v1/malware` | tab |

### 2.11 → S11 Cloud Posture
| Source | Endpoint | As |
|---|---|---|
| `CloudPosture` / `CloudPostureDashboard` / `CloudSecurityDashboard` | `/api/v1/cspm` | hero |
| `CSPMDashboard` | `/api/v1/cspm` | tab (CSPM) |
| `CWPPDashboard` / `CloudWorkloadProtectionDashboard` | `/api/v1/cwpp` | tab (CWPP) |
| `CloudIAM` / `CloudIdentityDashboard` / `IdentityGovernance` / `IdentityAnalyticsDashboard` / `IdentityLifecycleDashboard` / `DigitalIdentityDashboard` / `IdentityRiskDashboard` (cross-link to S4) | `/api/v1/iam/*` | tab (CIEM/Identity) |
| `CNAPPDashboard` | `/api/v1/cnapp` | tab (CNAPP) |
| `CloudSecurityAnalyticsDashboard` / `CloudCostOptimizationDashboard` / `CloudComplianceDashboard` / `CloudAccessSecurityDashboard` | `/api/v1/cloud/*` | tab |
| `ContainerSecurity` / `ContainerSecurityDashboard` / `ContainerPostureDashboard` / `ContainerRuntimeSecurityDashboard` | `/api/v1/containers/*` | tab (Containers) |
| `CWPDashboard` (alias) | shared | tab |
| `IaCScanning` (cross-link) | shared | tab (IaC) |
| `SaasSecurityPostureDashboard` | `/api/v1/sspm` | tab (SSPM) |
| `OTSecurityDashboard` / `IoTSecurityDashboard` / `FirmwareSecurityDashboard` | `/api/v1/{ot,iot,firmware}` | tab (OT/IoT) |
| `EndpointSecurity` / `EndpointComplianceDashboard` / `EndpointHuntingDashboard` (cross-link to S3) | `/api/v1/endpoint/*` | tab (Endpoint) |
| `NetworkSegmentationDashboard` / `MicrosegmentationPolicyDashboard` / `FirewallAnalyzer` / `FirewallPolicyDashboard` | `/api/v1/network/*` | tab (Network Posture) |
| `ZeroTrustDashboard` / `ZeroTrustPolicyDashboard` | `/api/v1/zero-trust/*` | tab (Zero Trust) |
| `DLPDashboard` / `DataExfiltrationDashboard` | `/api/v1/dlp/*` | tab (DLP) |
| `EmailSecurity` / `PhishingSimulation` | `/api/v1/{email,phishing}` | tab (Email/Phish) |
| `RansomwareProtectionDashboard` | `/api/v1/ransomware` | tab |
| `CryptoKeyDashboard` / `CertificateDashboard` / `CertificateManager` / `PKIManagementDashboard` / `QuantumCryptoDashboard` | `/api/v1/crypto/*` | tab (Crypto) |
| `MFAManagementDashboard` / `PAMDashboard` / `PrivilegeEscalationDashboard` / `PrivilegedIdentityDashboard` / `PrivilegedSessionRecordingDashboard` / `AccessGovernanceDashboard` / `AccessAnomalyDashboard` / `AccessRequestManagementDashboard` / `UserAccessReviewDashboard` / `ServiceAccountAuditDashboard` / `PasswordPolicy` | `/api/v1/iam/*` | tab (IAM Deep) |
| `CCMDashboard` (Continuous Cloud Monitoring) | `/api/v1/ccm` | tab |
| `PostureBenchmarkingDashboard` / `ConfigBenchmarkDashboard` / `SecurityBenchmarksDashboard` | `/api/v1/benchmarks/*` | tab (Benchmarks) |
| `CapacityPlanningDashboard` (cross-link to S2) | shared | widget |

### 2.12 → S12 Attack Paths (HERO)
| Source | Endpoint | As |
|---|---|---|
| `AttackPaths` / `AttackPathAnalysis` / `AttackPathInteractiveGraph` | `/api/v1/attack-paths/*` | hero |
| `ChokePointDashboard` | `/api/v1/attack-paths/choke-points` | tab (Choke Points) |
| `AttackChainDashboard` | `/api/v1/attack-chains` | tab |
| `AttackSurface` / `AttackSurfaceDashboard` | `/api/v1/attack-surface` | tab |
| `ThreatVectorDashboard` / `ThreatExposureDashboard` | `/api/v1/threats/{vectors,exposure}` | tab |
| `DomainSeedDiscoveryWizard` / `SubsidiaryAttributionGraph` | `/api/v1/easm/*` | tab (EASM) |
| `DarkWebMonitoringDashboard` (cross-link to S14) | `/api/v1/dark-web` | widget |
| `BlastRadius` (computed via existing engines) | `/api/v1/blast-radius` | widget |
| `ThreatModeling` / `ThreatModelDashboard` / `ThreatModelingPipelineDashboard` / `CyberThreatModelingDashboard` | `/api/v1/threat-modeling/*` | tab (Modeling) |
| `AIAttackPathView` | `/api/v1/ai/attack-paths` | tab (AI Paths) |
| `PAGDashboard` (Predicted Attack Graph) | `/api/v1/pag` | tab |

### 2.13 → S13 MPTE Console
**Pentest / Red Team / Social Engineering sub-cluster: DONE-2026-05-02 SHA=62e9f1d3** — 3 offensive-validation pages folded into OffensiveValidationHub.tsx at `/validate/offensive` (PentestManagement, RedTeamStatus, SocialEngineering). Old routes (`/pentest`, `/red-team`, `/social-engineering`) and the alias `/pentest-mgmt` (PentestManagementDashboard) all redirect with `?tab=`. Real APIs: `/api/v1/pentest-mgmt/*`, `/api/v1/red-team/*`, `/api/v1/phishing/*`. AttackSimulation stays at `/validate/simulation` (RoleGuarded BAS surface); BugBounty stays inside Brain.tsx (already folded).

| Source | Endpoint | As |
|---|---|---|
| `MPTEConsole` | `/api/v1/mpte/run` | hero |
| `AttackSimulation` / `AttackSimulationPage` | `/api/v1/attack-sim` | tab (Simulate) |
| `RedTeamStatus` | `/api/v1/red-team` | tab |
| `PentestManagement` / `PentestManagementDashboard` | `/api/v1/pentest` | tab |
| `BugBounty` | `/api/v1/bug-bounty` | tab |
| `SocialEngineering` | `/api/v1/social-eng` | tab |
| `Reachability` / `ReachabilityProof` (drill from S6) | shared | tab (Reachability) |

### 2.14 → S14 Threat Intel
**Actors/Indicators sub-cluster: DONE-2026-05-02 SHA=17fd2540** — 5 pages folded into ThreatActorsHub.tsx at `/attack/intel/actors` (ThreatActorDashboard, ActorTrackingDashboard, ThreatAttributionDashboard, ThreatIndicatorDashboard, IOCHunter). Old routes (`/threat-actors`, `/actor-tracking`, `/threat-attribution`, `/threat-indicators`, `/ioc-hunter`) redirect with `?tab=`.

| Source | Endpoint | As |
|---|---|---|
| `ThreatFeeds` / `ThreatFeedDashboard` / `ThreatIntelDashboard` / `ThreatIntelDashboardPage` / `ThreatIntelPlatformDashboard` / `ThreatIntelAutomation` | `/api/v1/threat-intel/*` | hero |
| `FeedSubscriptionsDashboard` | `/api/v1/feeds/subscriptions` | tab |
| `ThreatActorDashboard` / `ActorTrackingDashboard` / `ThreatAttributionDashboard` | `/api/v1/threats/actors` | tab (Actors) |
| `ThreatIndicatorDashboard` / `IOCHunter` | `/api/v1/iocs` | tab (IOCs) |
| `ThreatIntelConfidenceDashboard` / `ThreatScoreDashboard` | `/api/v1/threats/score` | tab |
| `ThreatGeolocationDashboard` | shared | widget |
| `DarkWebMonitoringDashboard` | `/api/v1/dark-web` | tab |
| `ZeroDayIntelligenceDashboard` | `/api/v1/zero-day` | tab |
| `ThreatBriefDashboard` / `ThreatLandscapeDashboard` / `ThreatResponseDashboard` / `ThreatDeceptionDashboard` / `CyberThreatIntelDashboard` | `/api/v1/threats/{briefs,landscape,response,deception}` | tab |

### 2.15 → S15 Brain Pipeline (HERO)
| Source | Endpoint | As |
|---|---|---|
| `BrainPipeline` | `/api/v1/brain/pipeline` | hero (12-step viz) |
| `BrainVisualization` | `/api/v1/brain/{stats,nodes}` | tab (Neural Map) |
| `MultiLLM` | `/api/v1/llm/consensus` | tab (Consensus) |
| `AlgorithmicLab` | `/api/v1/algo/lab` | tab |
| `MLDashboard` | `/api/v1/ml/dashboard` | tab |
| `Predictions` | `/api/v1/predictions` | tab |
| `ScoreTransparencyPanel` (cross-link to S6) | shared | widget |
| `FactorWeightsView` (cross-link to S6) | shared | widget |
| `LLMContextTierBadge` / `LLMPreFlightEstimateModal` / `LLMRuleContextEditor` | `/api/v1/llm/*` | tab (Cost Gate) |
| `TraversalExplanationPanel` / `TracedFlowViewer` | `/api/v1/trace/*` | tab (Trace) |

### 2.16 → S16 MPTE Verification
Alias of S13 — same hero exposed under Brain nav for Threat Hunter / Sec Analyst persona muscle memory. No new screen, no new endpoints.

### 2.17 → S17 FAIL Chaos
| Source | Endpoint | As |
|---|---|---|
| `FAILEngine` | `/api/v1/fail/engine` | hero |
| `Playbooks` / `PlaybookEditor` / `PlaybookLibrary` / `PlaybookLibraryPage` | `/api/v1/playbooks/*` | tab (Playbooks) |
| `SecurityChaosDashboard` | `/api/v1/security-chaos` | tab |
| `SecurityTabletopDashboard` | `/api/v1/tabletop` | tab |
| `DeceptionEngine` / `DeceptionAnalyticsDashboard` / `ThreatDeceptionDashboard` | `/api/v1/deception/*` | tab |

### 2.18 → S18 AI Copilot
| Source | Endpoint | As |
|---|---|---|
| `Copilot` / `CopilotDashboard` / `CopilotGraphChat` / `CopilotGraphChatRoot` | `/api/v1/copilot/*` | hero |
| `AIAgentsConsole` / `AgentTaskQueue` | `/api/v1/agents/*` | tab |
| `ShadowAIInventory` | `/api/v1/ai/shadow-inventory` | tab |
| `AIGovernanceDashboard` | `/api/v1/ai-governance` | tab |
| `AIPoweredSOCDashboard` | `/api/v1/ai-soc` | widget |
| `AISecurityAdvisor` / `AISecurityAdvisorDashboard` | `/api/v1/ai-advisor` | tab |
| `LLMContextTierBadge` / `LLMPreFlightEstimateModal` / `LLMRuleContextEditor` (cross-link to S15) | shared | widget |
| `ClaudeSkillsRegistry` (cross-link to S28) | shared | widget |

### 2.19 → S19 Remediation Center
| Source | Endpoint | As |
|---|---|---|
| `RemediationCenter` | `/api/v1/remediation` | hero |
| `AutoFix` | `/api/v1/autofix` | tab |
| `BulkOperations` | `/api/v1/bulk-ops` | tab |
| `Workflows` | `/api/v1/workflows` | tab |
| `TicketIntegration` | `/api/v1/tickets` | tab |
| `ExposureCases` | `/api/v1/cases` | tab |
| `Collaboration` | `/api/v1/collab` | tab |
| `AutonomousRemediationDashboard` | `/api/v1/autonomous-remediation` | tab |
| `PatchManagementDashboard` / `PatchPrioritizer` | `/api/v1/patch/*` | tab (Patch) |
| `PostureAdvisor` | `/api/v1/posture-advisor` | tab |
| `SOARDashboard` | `/api/v1/soar` | tab |
| `SecurityAutomationDashboard` | `/api/v1/security-automation` | widget |

### 2.20 → S20 Waivers & Exceptions
| Source | Endpoint | As |
|---|---|---|
| `WaiversExplorer` | `/api/v1/auto-waiver/{rules,stats}` | hero |
| `AutoWaiverRules` | `/api/v1/auto-waiver/rules` | tab |
| `WaiverRequestModal` | `/api/v1/waivers/request` | modal |
| `RiskAcceptance` (cross-link to S4) | shared | tab |
| `SecurityExceptionDashboard` | `/api/v1/exceptions` | tab |
| `ExceptionWorkflowDashboard` | `/api/v1/exceptions/workflow` | tab |

### 2.21 → S21 Upgrade Paths
| Source | Endpoint | As |
|---|---|---|
| `UpgradePathDashboard` / `UpgradePathExplorer` | `/api/v1/upgrade-path` | hero |
| `ComponentVersionGraph` | `/api/v1/components/version-graph` | tab |
| `DependencyMappingDashboard` | `/api/v1/deps/map` | tab |
| `BinaryFingerprintDashboard` | `/api/v1/binary/fingerprint` | tab |
| `SecurityDependencyRiskDashboard` | `/api/v1/deps/risk` | tab |

### 2.22 → S22 Incident Response
**Forensics sub-cluster: DONE-2026-05-02 SHA=808352ac** — 3 forensics surfaces folded into ForensicsHub.tsx at `/remediate/forensics` (DigitalForensicsDashboard, NetworkForensics-via-FindingsExplorerView, MalwareAnalysis-via-FindingsExplorerView). Old routes (`/digital-forensics`, `/network-forensics`, `/malware-analysis`) redirect with `?tab=`.

| Source | Endpoint | As |
|---|---|---|
| `IncidentResponse` / `IncidentResponseDashboard` | `/api/v1/incidents` | hero |
| `IncidentTimeline` / `IncidentTimelineDashboard` / `EventTimelineDashboard` | `/api/v1/incidents/timeline` | tab |
| `IncidentMetricsDashboard` / `IncidentCostsDashboard` / `IncidentLessonsDashboard` / `IncidentKBDashboard` / `IncidentCommsDashboard` | `/api/v1/incidents/*` | tab |
| `IRPlaybookDashboard` | `/api/v1/ir/playbooks` | tab |
| `BreachResponse` | `/api/v1/breach-response` | tab |
| `CloudIRDashboard` | `/api/v1/cloud-ir` | tab |
| `DigitalForensicsDashboard` / `NetworkForensicsDashboard` / `MalwareAnalysisDashboard` | `/api/v1/forensics/*` | tab (Forensics) |
| `CyberResilienceDashboard` | `/api/v1/cyber-resilience` | widget |

### 2.22b Awareness sub-cluster
**Awareness sub-cluster: DONE-2026-05-02 SHA=29f1aae6** — 4 awareness pages folded into AwarenessHub.tsx at `/comply/awareness` (AwarenessCampaignDashboard, AwarenessProgramDashboard, AwarenessMetricsDashboard, AwarenessScoreDashboard). Old routes (`/awareness-campaigns`, `/awareness-program`, `/awareness-metrics`, `/awareness-score`) redirect with `?tab=`. Real APIs: `/api/v1/awareness-campaigns/*`, `/api/v1/awareness-program/*`, `/api/v1/awareness-metrics/*`, `/api/v1/awareness-score/orgs/{id}/*`.

### 2.23 → S23 Compliance Dashboard
| Source | Endpoint | As |
|---|---|---|
| `ComplianceDashboard` / `StandaloneComplianceDashboard` / `MissionControlComplianceDashboard` (cross-link to S1) | `/api/v1/compliance` | hero |
| `ComplianceScannerDashboard` | `/api/v1/compliance/scan` | tab |
| `ComplianceAutomationDashboard` | `/api/v1/compliance/automation` | tab |
| `ComplianceCalendarDashboard` | `/api/v1/compliance/calendar` | tab |
| `ComplianceGapDashboard` / `GapAnalysisDashboard` | `/api/v1/compliance/gaps` | tab |
| `ComplianceMappingDashboard` | `/api/v1/compliance/mapping` | tab |
| `ComplianceWorkflowDashboard` | `/api/v1/compliance/workflows` | tab |
| `RegulatoryTrackerDashboard` | `/api/v1/regulatory/tracker` | tab |
| `SecurityMaturityDashboard` / `SecurityPostureMaturityDashboard` / `ProgramMaturityDashboard` | `/api/v1/maturity/*` | tab (Maturity) |
| `SecurityScorecardDashboard` / `SecurityHealthScorecardDashboard` | `/api/v1/scorecards` | tab |
| `SecurityBenchmarksDashboard` / `PostureBenchmarkingDashboard` | `/api/v1/benchmarks/*` | tab |
| `CCMDashboard` | `/api/v1/ccm` | tab |
| `PrivacyGDPRDashboard` / `PrivacyImpactDashboard` | `/api/v1/privacy/*` | tab |
| `GRCDashboard` / `GRCAssessment` | `/api/v1/grc/*` | tab (GRC) |
| `SecurityQuestionnaireDashboard` | `/api/v1/questionnaires` | tab |
| `ControlTestingDashboard` | `/api/v1/controls/test` | tab |
| `CloudComplianceDashboard` (cross-link to S11) | shared | tab |
| `EndpointComplianceDashboard` (cross-link to S11) | shared | tab |
| `FipsComplianceDashboard` / `FIPSModeStatus` | `/api/v1/fips/*` | tab |
| `ThirdPartyVendorDashboard` / `TprmExchangeDashboard` / `VendorRiskDashboard` (cross-link to S4) | `/api/v1/tprm/*` | tab (TPRM) |

### 2.24 → S24 Evidence Vault
| Source | Endpoint | As |
|---|---|---|
| `EvidenceVault` / `EvidenceVaultDashboard` | `/api/v1/evidence` | hero |
| `EvidenceBundles` | `/api/v1/evidence/bundles` | tab |
| `EvidenceExportCenter` | `/api/v1/evidence/export` | tab |
| `AuditTrail` / `AuditLog` / `AuditLogExplorer` | `/api/v1/audit/*` | tab (Audit) |
| `Reports` / `ScheduledReportsDashboard` (cross-link to S2) / `PostureReportingDashboard` | `/api/v1/reports/*` | tab |
| `Analytics` / `CrossDomainAnalytics` | `/api/v1/analytics/*` | tab |
| `MetricsAggregatorDashboard` | `/api/v1/metrics/aggregate` | widget |

### 2.25 → S25 SBOM & Provenance
**Provenance/Attestation sub-cluster: DONE-2026-05-02 SHA=16c0b17d** — 6 pages folded into SBOMProvenanceHub.tsx at `/comply/provenance` (SBOMExportDashboard, PipelineBomDashboard, PBOMViewer, SlsaProvenanceDashboard, PipelineAttestationGraph, SLSAAttestationSigner). Old routes (`/sbom-export`, `/pipeline-bom`, `/slsa-provenance`, `/pbom/propagation`, `/provenance/attestation`, `/provenance/sign`) redirect with `?tab=`. Inventory subset (SBOMInventory/SBOMManagement/SBOMDashboard/SBOMContinuousMonitoring) still routed under `/assets?tab=sbom` (S9 Inventory hero) — preserved for the asset-centric persona path.

| Source | Endpoint | As |
|---|---|---|
| `SBOMInventory` / `SBOMManagement` / `SBOMDashboard` | `/api/v1/sbom` | hero |
| `SBOMContinuousMonitoring` | `/api/v1/sbom/{id}/re-eval-history` | tab |
| `SBOMExportDashboard` | `/api/v1/sbom/export` | tab |
| `PipelineBomDashboard` / `PBOMViewer` | `/api/v1/pbom/*` | tab (Pipeline BOM) |
| `PipelineAttestationGraph` | `/api/v1/provenance/attestation` | tab |
| `SLSAProvenance` / `SlsaProvenanceDashboard` / `SLSAAttestationSigner` | `/api/v1/slsa/*` | tab |
| `SOC2Evidence` (cross-link to S23) | shared | tab |

### 2.26 → S26 Policies & Rules
| Source | Endpoint | As |
|---|---|---|
| `Policies` / `PolicyLibraryBrowser` / `PolicyInheritanceView` | `/api/v1/policies/*` | hero |
| `StagePolicyMatrix` / `PolicyStageEditor` | `/api/v1/policies/stage-*` | tab |
| `HooksPolicyEditor` / `HooksStatusPanel` | `/api/v1/hooks/*` | tab (Hooks) |
| `UnifiedRulesCatalog` / `RuleTaxonomyInspector` | `/api/v1/rules/*` | tab (Catalog) |
| `RuleDSLAuthoringStudio` / `RuleDSLValidator` / `DynamicRuleDSLDashboard` | `/api/v1/rules/dsl/*` | tab (DSL) |
| `ViolationLifecycleDashboard` / `ViolationLifecycleTimeline` | `/api/v1/violations/lifecycle` | tab |
| `SecurityBaselineDashboard` | `/api/v1/baselines` | tab |

### 2.27 → S27 Integrations Hub
| Source | Endpoint | As |
|---|---|---|
| `Integrations` / `IntegrationHealth` | `/api/v1/integrations/*` | hero |
| `Marketplace` | `/api/v1/marketplace` | tab |
| `ConnectorMappingUI` | `/api/v1/connectors/mapping` | tab |
| `UniversalIngestionTester` | `/api/v1/connectors/mapping/dry-run` | tab |
| `WebhookEventCatalogExplorer` / `WebhookRetryConsole` | `/api/v1/webhooks/*` | tab (Webhooks) |
| `APIExplorer` / `DeveloperPortal` | `/api/v1/dev/*` | tab (API) |
| `ServiceNowDashboard` / `ProwlerDashboard` / `SIEMOutputDashboard` | `/api/v1/{servicenow,prowler,siem}` | tab (Targets) |
| `IDEBackendDashboard` | `/api/v1/ide/backend` | tab |
| `DataPipelineDashboard` | `/api/v1/data-pipeline` | widget |

### 2.28 → S28 MCP Gateway (HERO)
| Source | Endpoint | As |
|---|---|---|
| `MCPToolRegistry` | `/api/v1/mcp/tools` | hero (650+ tools) |
| `ClaudeSkillsRegistry` / `SkillsInstallPrompt` | `/api/v1/skills/*` | tab |
| `OpenClawDashboard` | `/api/v1/openclaw` | tab |
| `AirGapBundleDashboard` / `AirGapBundleConsole` / `OfflineFeedRegistry` / `OfflineUpdateStatus` | `/api/v1/air-gap/*` | tab (Air-Gap) |
| `LocalFileStoreDashboard` / `LocalStoreStatus` / `ZeroSetupOnboarding` | `/api/v1/local-store/*` | tab (Local Store) |

### 2.29 → S29 Admin Console
| Source | Endpoint | As |
|---|---|---|
| `SettingsPage` | `/api/v1/settings` | hero |
| `UsersPage` | `/api/v1/users` | tab |
| `Teams` | `/api/v1/teams` | tab |
| `UserTokenManager` | `/api/v1/users/me/tokens` | tab |
| `RBAC` (built into existing role-guards) | `/api/v1/rbac` | tab |
| `OrgHierarchyExplorer` / `OrgHierarchyDashboard` | `/api/v1/orgs` | tab |
| `ScopeManager` | `/api/v1/scopes` | tab |
| `SecurityChampionsDashboard` | `/api/v1/champions` | tab |
| `SecurityAwareness` / `SecurityTrainingDashboard` / `AwarenessProgramDashboard` / `AwarenessCampaignDashboard` / `AwarenessMetricsDashboard` / `AwarenessScoreDashboard` / `TrainingEffectivenessDashboard` / `SecurityCultureDashboard` / `SecurityGamificationDashboard` | `/api/v1/awareness/*` | tab (Awareness) |
| `OnboardingWizard` (cross-link from `/onboarding`) | shared | drill |
| `LandingPage` | shared | redirect |
| `CompetitiveComparisonPage` | static | drill |

### 2.30 → S30 System Health
| Source | Endpoint | As |
|---|---|---|
| `SystemHealth` / `SystemHealthDashboard` | `/api/v1/system/health` | hero |
| `LogViewer` | `/api/v1/system/logs` | tab |
| `CapacityPlanningDashboard` (cross-link to S2) | shared | tab |
| `SecurityTelemetryDashboard` | `/api/v1/telemetry` | tab |
| `SecurityToolInventoryDashboard` (cross-link to S9) | shared | tab |
| `FIPSModeStatus` (cross-link to S26) | shared | widget |
| `LocalStoreStatus` (cross-link to S28) | shared | widget |
| `DigitalTwinDashboard` | `/api/v1/digital-twin` | widget |

### 2.31 Pages whose target home is under multiple screens (deliberate cross-listing)
- `IdentityRiskDashboard`, `VendorRiskDashboard`, `ThirdPartyVendorDashboard`, `SupplyChainDashboard`, `CapacityPlanningDashboard`, `DarkWebMonitoringDashboard`, `EndpointSecurity` — surfaced via cross-link in 2 screens to preserve persona muscle memory; *one canonical route* (the lower-numbered screen owns the URL).

---

## 3. Persona Walkthrough Preservation (25/25 zero-regression)

For each persona: **Lands** → **Drills** → **Acts**. Every action has a target screen + tab anchor.

### Executive & Leadership (1–4)
| # | Persona | Lands | Drills | Acts |
|---|---|---|---|---|
| 1 | **CISO** | S1 (`/`) | S2 Executive Brief → CISO tab | S20 Waivers (risk acceptance) |
| 2 | **VP Engineering** | S1 → SLA tab | S4 SLA & Risk Register | S19 Remediation Center → bulk |
| 3 | **CTO** | S2 Executive Brief → Risk tab | S15 Brain Pipeline (release-risk view) | S26 Policies (release gates) |
| 4 | **CFO** | S2 → Investment tab | S2 → BRS Heatmap | S2 → ROI report (export to S24) |

### Security Operations (5–13)
| # | Persona | Lands | Drills | Acts |
|---|---|---|---|---|
| 5 | **SOC T1** | S3 → Triage tab | S5 Issues → drilling to S6 detail | escalate → S22 IR |
| 6 | **SOC T2** | S3 → Hunt tab | S14 Threat Intel + S12 Attack Paths | S22 IR Console |
| 7 | **Incident Responder** | S22 IR Console | S6 Issue Detail → Reachability | S19 Remediation |
| 8 | **Threat Hunter** | S12 Attack Paths (HERO) | S13/S16 MPTE Console | S14 Threat Intel → IOCs |
| 9 | **Vulnerability Manager** | S5 Issues Queue (HERO) | S7 Findings Explorer | S20 Waivers, S19 Remediation |
| 10 | **AppSec Engineer** | S10 Code Intelligence | S13 MPTE Console (verify exploitability) | S26 Policies (tune rules) |
| 11 | **Security Architect** | S8 Asset Graph (HERO) | S26 Policies & Rules | S15 Brain Pipeline (risk model) |
| 12 | **GRC Analyst** | S23 Compliance Dashboard | S24 Evidence Vault | S25 SBOM & Provenance |
| 13 | **Compliance Manager** | S23 → Frameworks tab | S23 → Regulatory Tracker | S24 Evidence Bundles export |

### Engineering & Platform (14–21)
| # | Persona | Lands | Drills | Acts |
|---|---|---|---|---|
| 14 | **Engineering Manager** | S19 Remediation Center | S5 Issues by app | S4 SLA tracking |
| 15 | **Tech Lead** | S6 Issue Detail → AutoFix tab | S21 Upgrade Paths | approve PR (drill to S5 PR Risk tab) |
| 16 | **Backend Engineer** | S5 Issues (filtered to "assigned to me") | S6 Issue Detail | S19 → AutoFix |
| 17 | **Frontend Engineer** | S5 Issues (filtered) | S6 → AutoFix | S19 |
| 18 | **DevOps Engineer** | S27 Integrations Hub | S28 MCP Gateway | S26 Hooks Policy |
| 19 | **SRE** | S30 System Health | S11 Cloud Posture → CSPM tab | S19 → Patch Mgmt |
| 20 | **Platform Engineer** | S11 → Containers tab | S11 → Network Posture | S26 → Hooks |
| 21 | **QA Engineer** | S5 Issues filtered | S6 Issue Detail (regression) | S22 IR Lessons |

### Data & AI (22–25)
| # | Persona | Lands | Drills | Acts |
|---|---|---|---|---|
| 22 | **Data Scientist** | S15 Brain → ML tab | S15 → Predictions | S15 → Algorithmic Lab |
| 23 | **ML Engineer** | S15 Brain → Algorithmic Lab | S15 → Score Transparency | S15 → Factor Weights |
| 24 | **Security Analyst (AI-Assisted)** | S18 AI Copilot | S5 Issues → AI suggestions | S15 → Multi-LLM Consensus |
| 25 | **Automation Engineer** | S28 MCP Gateway (HERO) | S18 AI Agents Console | S26 Rule DSL Studio |

**Verification:** every persona's "Lands" screen exists in §1; every "Drills" tab exists in §2; every "Acts" target preserves the underlying API endpoint per the merge map. **Zero workflows lost.**

---

## 4. Hero Screens for Unique Moats

These 4 screens get **hero-class polish** because no competitor has them (per Phase 2 Section C):

### 4.1 Brain Pipeline (S15) — 12-step Decision Visualization
- **Visual**: animated 12-node pipeline (intake → triage → enrichment → reachability → exploit-check → consensus → score → policy → autofix → ticket → audit → archive). Each node breathes (sine wave radius), color-coded by phase, current finding flows as a packet across nodes.
- **Right rail**: Multi-LLM Consensus tab — shows live model votes (Qwen/Kimi/Gemma/Opus), agreement %.
- **Bottom strip**: Score Transparency + Factor Weights — every score click expands to show contributing factors.
- **Tabs**: Pipeline · Neural Map · Consensus · Algorithmic Lab · Predictions · ML · Trace · Cost Gate.
- **Reuse**: existing `BrainPipeline.tsx` + `BrainVisualization.tsx` + `MultiLLM.tsx` + `AlgorithmicLab.tsx` — composed via a single `<Tabs>` shell.

### 4.2 MPTE Console (S13/S16) — 19-phase Exploit Run
- **Visual**: Gantt-style timeline of 19 phases (recon → entry → priv-esc → lateral → exfil → ...) with live progress bars per phase.
- **Inline proof viewer**: Reachability proof split-pane shows the call chain from entry → vulnerable function → impact.
- **Tabs**: Run · 19-Phase Trace · Reachability Proof · Simulation Library · Red Team · Pentest · Bug Bounty.
- **Reuse**: existing `MPTEConsole.tsx` + `ReachabilityProof.tsx` + `AttackSimulation.tsx` — composed via tabs; phase Gantt is a new `<MPTEPhaseStrip>` component built once and reused.

### 4.3 FAIL Chaos (S17) — Industry-First Chaos Campaigns
- **Visual**: Campaign timeline showing scheduled chaos injections (vulnerable-route deploy, secret-rotation drill, alert-suppression drill). Each campaign card shows blast-radius, blast-confidence, recovery time.
- **Tabs**: Campaigns · Playbook Library · Editor · Tabletop · Deception · Deception Analytics.
- **Reuse**: existing `FAILEngine.tsx` + `Playbooks.tsx` + `PlaybookEditor.tsx` + `DeceptionEngine.tsx` + `SecurityChaosDashboard.tsx`.

### 4.4 MCP Gateway (S28) — 650+ Tool Registry
- **Visual**: searchable card grid of all registered MCP tools (categorized by domain: scanner, ticketing, SIEM, cloud, AI). Each card → invocation history sparkline + latency p95.
- **Right rail**: Skills install prompt (one-click install). Air-gap bundle status badge.
- **Tabs**: Tool Registry · Skills · Skills Install · OpenClaw · Air-Gap · Local Store.
- **Reuse**: existing `MCPToolRegistry.tsx` + `ClaudeSkillsRegistry.tsx` + `OpenClawDashboard.tsx` + air-gap pages.

---

## 5. Implementation Phasing

### P0 — Sprint 1 (week 1–2): 6 hero screens
**Effort:** ~10 person-days. **Output:** demo-ready spine.

| Screen | Effort | Why P0 |
|---|---|---|
| S5 Issues Queue (HERO) | 2d | Wiz-pattern competitor parity; backend GAP-049 ready |
| S8 Asset Graph (HERO) | 2d | Apiiro graph-as-substrate; closes 7 Wiz LOSE cells visually |
| S15 Brain Pipeline (HERO) | 2d | Unique moat #1 — must demo first |
| S1 Command Dashboard | 1d | Default landing; existing root |
| S23 Compliance Dashboard | 1d | Sells the SOC2 + 100-frameworks story |
| S29 Admin Console | 2d | Required for tenant management; consolidates `/settings/*` |

### P1 — Sprint 2 (week 3–4): 14 per-domain dashboards
**Effort:** ~12 person-days (each is mostly tab-composition).

S2, S3, S4, S6, S7, S9, S10, S11, S12, S19, S22, S24, S25, S27.

### P2 — Sprint 3 (week 5–6): 10 deep-moat + admin tail
**Effort:** ~8 person-days.

S13, S14, S16, S17, S18, S20, S21, S26, S28, S30.

### Cross-cutting (parallel to all sprints)
- Build a **`<ScreenShell>`** wrapper: `PageHeader` + `Tabs` + persona-aware default-tab logic. ~1d, reused by all 30 screens.
- Build a **`<MPTEPhaseStrip>`** component for S13. ~1d.
- Update `MainLayout` sidebar from current implicit nav to the **8 nav items** in §1. ~0.5d.
- Update `App.tsx`: add the 30 canonical routes; convert all old routes to `<Navigate>` redirects (see §6). ~1d.

**Total estimate: 33–35 person-days for full consolidation, 6 weeks at 1 FTE. Demo-ready at end of Sprint 1.**

---

## 6. Migration Safety — Redirect Strategy

Old routes MUST keep working for 90 days (persona muscle memory + existing bookmarks + e2e tests).

### 6.1 Pattern
Every retired route gets a `<Route path="<old>" element={<Navigate to="<new>?tab=<anchor>" replace />} />` entry in `App.tsx`. Target screen reads `?tab=` from query string and opens that tab on mount.

### 6.2 Redirect map (illustrative — full table generated by codegen from §2 in Sprint 1)
| Old route | → New route |
|---|---|
| `/cspm` | `/discover/cloud?tab=cspm` |
| `/cwpp` | `/discover/cloud?tab=cwpp` |
| `/cnapp` | `/discover/cloud?tab=cnapp` |
| `/cloud-iam` | `/discover/cloud?tab=ciem` |
| `/choke-points` | `/attack?tab=choke-points` |
| `/issue-queue` | `/issues` |
| `/issues/toxic` | `/issues?tab=toxic` |
| `/material-changes` | `/issues?tab=material` |
| `/pr-change-risk` | `/issues?tab=pr-risk` |
| `/brain` | `/brain?tab=pipeline` |
| `/copilot/graph-chat` | `/brain/copilot?tab=chat` |
| `/waivers/explorer` | `/remediate/waivers?tab=explorer` |
| `/sbom-continuous-monitoring` | `/comply/sbom?tab=monitoring` |
| `/mcp-registry` | `/connect/mcp?tab=tools` |
| `/skills` | `/connect/mcp?tab=skills` |

### 6.3 Existing redirect infrastructure
The current `App.tsx` already declares 6 namespace redirects (`/code/*`, `/cloud/*`, `/attack/*`, `/protect/*`, `/evidence/*`). Consolidation extends this pattern from 6 to ~330 redirects (one per retired route). Generated, not hand-typed.

### 6.4 Telemetry
- Emit `analytics.track("route_redirect", { from, to })` on every redirect.
- After 30 days: report which old routes still see >1% of traffic. Anything >1% gets a more prominent UI breadcrumb in the new screen.
- After 90 days: remove redirects from `App.tsx`; show a friendly "this page moved to X" landing for any 404.

---

## 7. Open Questions (deferred to product, not blockers)

1. **GAP-014 (IDE plugins)** — separate surface; not in this consolidation. Decision needed on VS Code / JetBrains scope before Q3.
2. **GAP-058 (free-tier strategy)** — affects whether `LandingPage` becomes self-serve onboarding or stays sales-led. Doesn't change the 30-screen target.
3. **Marketing site (`suite-ui/marketing`)** — out of scope for this plan (separate deployment).
4. **`suite-ui/aldeci` (legacy)** — frozen; no consolidation work. The new shape lands only in `aldeci-ui-new`.

---

## 8. Acceptance Criteria for "Done"

- [ ] `MainLayout` sidebar shows exactly 8 top-level nav items + Admin cog.
- [ ] `App.tsx` declares 30 canonical routes; every other route is a `<Navigate>` redirect.
- [ ] All 30 target screens render without console errors against a live API tenant.
- [ ] Playwright MCP screenshot of each of the 30 screens stored under `docs/ui-snapshots/consolidation-2026-04-26/`.
- [ ] Network-request audit on each screen confirms ≥1 real `/api/v1/...` call fires (NO MOCKS rule).
- [ ] `npm run build` passes with zero new TS errors.
- [ ] Beast Mode test suite still 100% green.
- [ ] Every persona in §3 has a dry-run walk-through documented in `docs/PERSONA_DRY_RUN_2026-05-XX.md`.

---

*End of Phase 3 plan. Hand-off: this doc is the input contract for `frontend-craftsman` to execute Sprint 1. Do not write any `.tsx` until plan is signed off by CTO.*
