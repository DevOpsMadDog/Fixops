# UI Consolidation Plan — 168 Hub Tabs → 10 Hero Screens
**Status**: PLAN ONLY — no files deleted, no routes removed. Founder sign-off required before execution.
**Date**: 2026-05-24
**Branch**: `chore/ui-prune-plan-2026-05-24` (this doc only)
**Measured baseline**: 259 non-test `.tsx` page files · 96,571 total LOC · ~370 registered routes in `App.tsx`

---

## 0. Why This Plan Exists

The current UI has 259 page files and ~370 routes. Roughly 30 of those pages show real data. The other 229 are stubs, duplicates, or feature-flag screens that a customer will never reach in a first session. Every extra route is bundle weight, every extra nav item is cognitive load.

The product is an **on-prem AI brain** that ingests scanner output and tells security teams what to fix first. The UI must answer one question for every type of user:

- CISO: "What did the AI decide this week and how bad is it?"
- Analyst: "Which findings are real and what do I do with each one?"
- Engineer: "How do I connect my scanner and trust the results?"
- Auditor: "Where is the signed evidence?"

Ten screens cover all four users. Everything else either folds into those screens as a tab, gets deferred behind `?legacy=1`, or gets deleted.

---

## 1. The 10 Hero Screens

| # | Screen name | Route | Status | Primary users |
|---|-------------|-------|--------|---------------|
| H1 | Executive Dashboard | `/` (root, replaces current redirect) | EXISTS → rewrite needed | CISO, Board |
| H2 | Findings Explorer | `/findings` | EXISTS · `findings/FindingsExplorer.tsx` | Analyst, Engineer |
| H3 | Risk Overview | `/risk` | EXISTS · `mission-control/RiskOverview.tsx` | CISO, Analyst |
| H4 | Onboarding & Connectors | `/connect` | PARTIAL · `OnboardingWizard.tsx` + `IntegrationHealth.tsx` | Engineer (day 1) |
| H5 | AI Council Trail | `/brain` | EXISTS (tab-hub) · fold into hero | Analyst, Compliance |
| H6 | Brain Pipeline Monitor | `/brain` tab: pipeline | EXISTS · `BrainVisualization.tsx` partial | Engineer, SecOps |
| H7 | Compliance Evidence | `/comply` | EXISTS (tab-hub) · `comply/ComplianceDashboard.tsx` | Auditor, CISO |
| H8 | Settings → LLM Keys | `/settings` tab: llm | MISSING → new tab in settings hub | Admin |
| H9 | Settings → License & Tier | `/settings` tab: license | MISSING → new tab in settings hub | Admin |
| H10 | Status / Health | `/admin` tab: system-health | EXISTS · `SystemHealthDashboard.tsx` | Admin, DevOps |

**Note on H1**: The current `/` redirects to `/executive` which renders `CISODashboard.tsx`. That file is 696 LOC of real data calls and is a strong foundation. The rewrite means: add MTTR trend sparkline, top-5 AI verdicts with reasoning, and a Brain Pipeline live badge. Do not rebuild from scratch.

**Note on H5+H6**: Both live under `/brain` as tabs. The existing tab-hub already has `pipeline`, `consensus`, `ml`, `predictions`, `score`, `weights`, `lab`, `mpte`, `fail`. Keep the hub, rename entry in nav to "AI Brain" and promote it to top-level nav.

---

## 2. Full Hub Inventory — 259 Files × Verdict

Verdicts:
- `KEEP` — live content, fold into one of the 10 hero screens (name given)
- `KILL` — delete `.tsx` + remove route; no real content, duplicate, or out-of-scope for on-prem AI brain
- `DEFER` — hide from nav, keep file, add `?legacy=1` route alias; content may be useful later

### 2.1 Auth / Shell (always keep)

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `auth/LoginPage.tsx` | 825 | KEEP | Shell — no change |
| `auth/ForgotPasswordPage.tsx` | — | KEEP | Shell |
| `auth/ResetPasswordPage.tsx` | — | KEEP | Shell |
| `NotFound.tsx` | — | KEEP | Shell |
| `LandingPage.tsx` | 1308 | KILL | Marketing page — on-prem product has no public landing; redirect `/landing` → `/` |
| `marketing/LandingPage.tsx` | — | KILL | Duplicate of above |
| `PricingPage.tsx` | — | KILL | On-prem pricing is handled OOB; no SaaS pricing page needed |
| `Tour.tsx` | — | DEFER | Useful for future onboarding flow; hide from nav |
| `DocsPage.tsx` | — | KEEP | Legal/docs ToS/Privacy required; keep routes `/docs/tos`, `/docs/privacy`, `/docs/dpa` |
| `ApiReferencePage.tsx` | — | KEEP | Developer reference; move to `H8/Settings → Developer` tab |
| `ChangelogPage.tsx` | — | DEFER | Nice-to-have; `?legacy=1` |
| `SupportPage.tsx` | — | KEEP | Customer support link; keep at `/support` |
| `BoardLandingPage.tsx` | — | KILL | Duplicate of executive view; `/board` → redirect to `/` |
| `StatusPage.tsx` | — | KILL | Public SaaS status page — not relevant on-prem; redirect `/status` → `/admin?tab=system-health` |

### 2.2 Mission Control / Executive

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `mission-control/CISODashboard.tsx` | 696 | KEEP | **H1 Executive Dashboard** (primary component) |
| `mission-control/RiskOverview.tsx` | 1030 | KEEP | **H3 Risk Overview** |
| `mission-control/RiskRegister.tsx` | 1333 | KEEP | **H3** tab: risk-register |
| `mission-control/ComplianceDashboard.tsx` | 1248 | KEEP | **H7 Compliance Evidence** tab: frameworks |
| `mission-control/LiveFeed.tsx` | 678 | KEEP | **H1** tab: live-feed (real-time AI events) |
| `mission-control/ThreatIntelDashboard.tsx` | 1415 | DEFER | Rich but not AI-brain-native; `?legacy=1` route `/mission-control/threat-intel` |
| `mission-control/SLADashboard.tsx` | — | KEEP | **H3** tab: sla |
| `BRSExecutiveDashboard.tsx` | — | DEFER | BRS-specific view; `?legacy=1` |
| `FinanceHub.tsx` | — | DEFER | Dollar-heatmap / security investment; `?legacy=1` |

### 2.3 Findings / Discover

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `findings/FindingsExplorer.tsx` | 1275 | KEEP | **H2 Findings Explorer** (primary) |
| `discover/FindingExplorer.tsx` | 1039 | KILL | Duplicate of above (older version); `/discover` → redirect to `/findings` |
| `discover/CodeScanning.tsx` | 905 | KEEP | **H2** tab: code-scanning |
| `discover/IaCScanning.tsx` | 732 | KEEP | **H2** tab: iac |
| `discover/CloudPosture.tsx` | — | KEEP | **H2** tab: cloud |
| `discover/ContainerSecurity.tsx` | — | KEEP | **H2** tab: containers |
| `discover/SBOMInventory.tsx` | 775 | KEEP | **H2** tab: sbom |
| `discover/ThreatFeeds.tsx` | — | KEEP | **H2** tab: threats |
| `discover/AttackPaths.tsx` | — | KEEP | **H2** tab: attack-paths |
| `discover/CorrelationEngine.tsx` | 885 | KEEP | **H2** tab: correlation |
| `discover/DataFabric.tsx` | 876 | KEEP | **H2** tab: data-fabric |
| `discover/SecretsHub.tsx` (via `SecretsHub.tsx`) | 726 | KEEP | **H2** tab: secrets |
| `discover/ArchitectWorkspaceHub.tsx` | 705 | DEFER | Specialist architect view; `?legacy=1` |
| `discover/CodeSemanticExplorer.tsx` | — | DEFER | Deep code analysis; `?legacy=1` |
| `discover/CallGraphExplorer.tsx` | — | DEFER | Call graph; `?legacy=1` |
| `discover/PIIFieldInventory.tsx` | — | DEFER | PII scanning; `?legacy=1` |
| `discover/ComponentIdentityView.tsx` | — | DEFER | Component identity; `?legacy=1` |
| `attack-surface/AttackSurface.tsx` | 1123 | KEEP | **H2** tab: attack-surface |
| `VulnIntelHub.tsx` | 726 | DEFER | Vuln intel depth; absorb summary widget into H2, full page `?legacy=1` |
| `VulnRiskQueue.tsx` | — | KEEP | **H2** tab: vuln-queue |
| `VulnHeatmap.tsx` | — | KEEP | **H3** tab: vuln-heatmap |
| `VulnScanDashboard.tsx` | — | KILL | Duplicate of H2 code-scanning tab |
| `VulnScoringDashboard.tsx` | — | DEFER | Scoring detail; `?legacy=1` |
| `VulnTrendDashboard.tsx` | — | DEFER | Trend chart; fold summary sparkline into H1, full page `?legacy=1` |
| `VulnLifecyclePipelineHub.tsx` | — | DEFER | Lifecycle pipeline; `?legacy=1` |
| `VulnerabilityCorrelationDashboard.tsx` | — | KILL | Covered by `discover/CorrelationEngine.tsx` |
| `VulnerabilityScanner.tsx` | — | KILL | Duplicate of H2 scanning tabs |
| `VulnerabilityScannerPage.tsx` | — | KILL | Same as above |
| `DASTDashboard.tsx` | — | KILL | Fold into H2 tabs (DAST is one of 8 native scanners) |
| `SCADashboard.tsx` | — | KILL | Fold into H2 tab: sbom/sca |
| `ContainerSecurityHub.tsx` | — | KILL | Duplicate of `discover/ContainerSecurity.tsx` |
| `ContainerRegistryDashboard.tsx` | — | DEFER | Registry detail; `?legacy=1` |
| `APISecurityHub.tsx` | 987 | DEFER | Rich API security hub; promote key widgets to H2 tab, full page `?legacy=1` |
| `APISecurityPage.tsx` | — | KILL | Duplicate of `APISecurityHub.tsx` |
| `APIThreatProtectionDashboard.tsx` | — | KILL | Covered by APISecurityHub |
| `AppLayerSecurityHub.tsx` | 708 | DEFER | App-layer detail; `?legacy=1` |
| `CodeToRuntimeDashboard.tsx` | — | DEFER | Code-to-runtime tracing; `?legacy=1` |
| `RuntimeCodeTrace.tsx` | — | DEFER | Runtime trace; `?legacy=1` |
| `AssetInventoryHub.tsx` | — | DEFER | Asset inventory; expose as tab in H2 or H4, full page `?legacy=1` |
| `DataDiscoveryHub.tsx` | — | DEFER | Data discovery; `?legacy=1` |
| `CyberThreatIntelDashboard.tsx` | — | DEFER | CTI depth; `?legacy=1` |
| `ExternalThreatIntelHub.tsx` | — | DEFER | External feeds; `?legacy=1` |
| `ThreatExposureDashboard.tsx` | — | DEFER | Exposure detail; `?legacy=1` |
| `ThreatIntelDashboard.tsx` | — | KILL | Duplicate of `mission-control/ThreatIntelDashboard.tsx` |
| `ThreatIntelAutomation.tsx` | — | DEFER | Automation; `?legacy=1` |
| `ThreatIntelConfidenceDashboard.tsx` | — | DEFER | Confidence scoring; `?legacy=1` |
| `ThreatIntelOpsHub.tsx` | — | DEFER | Intel ops; `?legacy=1` |
| `ThreatIntelPlatformDashboard.tsx` | — | KILL | Duplicate hub |
| `ThreatCorrelation.tsx` | — | KILL | Duplicate of `discover/CorrelationEngine.tsx` |
| `ThreatVectorDashboard.tsx` | — | DEFER | `?legacy=1` |
| `IntelEnrichmentDashboard.tsx` | — | DEFER | `?legacy=1` |
| `CrossDomainAnalytics.tsx` | — | DEFER | `?legacy=1` |
| `NetworkAnalysis.tsx` | — | DEFER | Network analysis; `?legacy=1` |
| `NetworkTopology.tsx` | — | DEFER | `?legacy=1` |
| `NetworkMonitoringHub.tsx` | — | DEFER | `?legacy=1` |
| `NetworkTrafficDashboard.tsx` | — | DEFER | `?legacy=1` |
| `NetworkSegmentationDashboard.tsx` | — | KILL | Out of scope for AI brain MVP |
| `NetworkSegmentationHub.tsx` | — | KILL | Duplicate |
| `NDRDashboard.tsx` | — | KILL | NDR is a different product category |
| `DLPDashboard.tsx` | — | KILL | DLP out of scope for on-prem AI brain |
| `MobileSecurity.tsx` | — | KILL | Out of scope |
| `FirmwareSecurityDashboard.tsx` | — | KILL | Out of scope |
| `OTSecurityDashboard.tsx` | — | KILL | OT/ICS out of scope |
| `SaasSecurityPostureDashboard.tsx` | — | KILL | SaaS posture; on-prem product |
| `CloudPostureUnifiedHub.tsx` | — | KILL | Duplicate of `discover/CloudPosture.tsx` |
| `CloudSecurityAnalyticsDashboard.tsx` | — | KILL | Duplicate |
| `CloudAccessSecurityDashboard.tsx` | — | KILL | Duplicate |
| `CloudIAM.tsx` | — | DEFER | Cloud IAM; `?legacy=1` |
| `CloudIdentityDashboard.tsx` | — | KILL | Duplicate |
| `CloudCostOptimizationDashboard.tsx` | — | KILL | Cost optimization is not a security-brain feature |
| `SBOMProvenanceHub.tsx` | — | KEEP | **H7** tab: provenance |
| `SBOMContinuousMonitoring.tsx` | — | DEFER | `?legacy=1` |
| `sbom/SBOMManagement.tsx` | 1406 | KEEP | **H7** tab: sbom-detail (merge with SBOMInventory as authoritative) |
| `AttackPathAnalysis.tsx` | — | KILL | Duplicate of `discover/AttackPaths.tsx` |

### 2.4 Validate / Offensive

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `validate/AttackSimulation.tsx` | — | KEEP | **H5 AI Council Trail** tab: attack-sim (maps to MPTE evidence) |
| `validate/Reachability.tsx` | — | KEEP | **H5** tab: reachability |
| `validate/ReachabilityProof.tsx` | — | KEEP | **H5** tab: reachability-proof |
| `OffensiveValidationHub.tsx` | 698 | KEEP | **H5** tab: offensive-validation |
| `ThreatModelingHub.tsx` | — | DEFER | Threat modeling; `?legacy=1` |
| `SecurityChaosDashboard.tsx` | — | DEFER | Chaos testing; `?legacy=1` |
| `DeceptionHub.tsx` | — | DEFER | Deception tech; `?legacy=1` |

### 2.5 AI Brain / Pipeline

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `BrainVisualization.tsx` | 874 | KEEP | **H6 Brain Pipeline Monitor** (primary component, route `/brain/neural`) |
| `ai/CopilotDashboard.tsx` | — | KEEP | **H5 AI Council Trail** (primary) |
| `ai/Copilot.tsx` | — | KEEP | **H5** tab: copilot-chat |
| `ai/CopilotGraphChat.tsx` | — | KEEP | **H5** tab: graph-chat |
| `ai/AIAttackPathView.tsx` | — | KEEP | **H5** tab: ai-attack-paths |
| `ai/MCPToolRegistry.tsx` | — | KEEP | **H8/Settings** tab: mcp-tools |
| `ai/TraversalExplanationPanel.tsx` | — | KEEP | **H5** tab: traversal-trace |
| `AICopilotAgentsHub.tsx` | 682 | KEEP | **H5** tab: agents |
| `AISecurityAdvisor.tsx` | — | DEFER | Secondary AI advisor; `?legacy=1` |
| `AISecurityAdvisorDashboard.tsx` | — | KILL | Duplicate of above |
| `CopilotGraphChat.tsx` (root-level) | — | KILL | Duplicate of `ai/CopilotGraphChat.tsx` |
| `LLMContextTierBadge.tsx` | — | KEEP | Utility component — fold into **H8** settings UI |
| `LLMPreFlightEstimateModal.tsx` | — | KEEP | Utility modal — keep at `/llm/estimate` |
| `LLMRuleContextEditor.tsx` | — | KEEP | **H8** tab: llm-rules |
| `ClaudeSkillsRegistry.tsx` | — | DEFER | Skills registry; `?legacy=1` |
| `SkillsInstallPrompt.tsx` | — | DEFER | Skills install; `?legacy=1` |
| `AirGapHub.tsx` | — | KEEP | **H10 Status/Health** tab: air-gap (critical for on-prem) |
| `LocalStoreStatus.tsx` | — | KEEP | **H10** tab: local-store |
| `LocalFileStoreDashboard.tsx` | — | KILL | Duplicate of `LocalStoreStatus.tsx` |
| `ZeroSetupOnboarding.tsx` | — | KEEP | **H4 Onboarding** step: zero-setup |
| `DomainSeedDiscoveryWizard.tsx` | — | KEEP | **H4** tab: seed-domain (EASM onboarding) |
| `DigitalTwinDashboard.tsx` | — | DEFER | Digital twin; `?legacy=1` |
| `ArchAwareGraphDashboard.tsx` | — | DEFER | Architecture graph; `?legacy=1` |
| `ArchReviewDashboard.tsx` | — | DEFER | Arch review; `?legacy=1` |

### 2.6 Remediate

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `remediate/ExposureCases.tsx` | — | KEEP | **H2** tab: cases |
| `remediate/Collaboration.tsx` | 725 | KEEP | **H2** tab: collaboration |
| `remediate/TicketIntegration.tsx` | — | KEEP | **H4** tab: tickets |
| `incidents/IncidentResponse.tsx` | 1042 | KEEP | **H2** tab: incidents |
| `IncidentTimeline.tsx` | — | KEEP | **H2** tab: incident-timeline |
| `IncidentExtensionsHub.tsx` | — | DEFER | Extensions; `?legacy=1` |
| `IncidentKnowledgeHub.tsx` | — | DEFER | Knowledge; `?legacy=1` |
| `IRPlaybookDashboard.tsx` | — | DEFER | IR playbooks; `?legacy=1` |
| `AutomationOrchestrationHub.tsx` | — | DEFER | Automation depth; `?legacy=1` |
| `ForensicsHub.tsx` | — | DEFER | Forensics; `?legacy=1` |
| `SecurityAutomationDashboard.tsx` | — | KILL | Duplicate of AutomationOrchestrationHub |
| `ExceptionsHub.tsx` | — | KEEP | **H2** tab: exceptions |
| `WaiverRequestModal.tsx` | — | KEEP | Modal; keep at `/waivers/request` |
| `RQLQueryBuilder.tsx` | — | KEEP | **H2** tab: rql-query |
| `SavedInvestigations.tsx` | — | KEEP | **H2** tab: saved |
| `ViolationLifecycleTimeline.tsx` | — | DEFER | `?legacy=1` |
| `StaleBaselineBanner.tsx` | — | KEEP | Utility banner component; keep at `/findings/drift` |

### 2.7 Compliance / Comply

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `comply/ComplianceDashboard.tsx` | 1162 | KEEP | **H7 Compliance Evidence** (primary) |
| `comply/EvidenceExportCenter.tsx` | — | KEEP | **H7** tab: export (generate signed ZIP for auditor) |
| `comply/AuditorEvidenceHub.tsx` | — | KEEP | **H7** tab: auditor |
| `comply/Reports.tsx` | — | KEEP | **H7** tab: reports |
| `comply/Analytics.tsx` | — | KEEP | **H7** tab: analytics |
| `comply/SOC2Evidence.tsx` | — | KEEP | **H7** tab: soc2 |
| `comply/SLSAProvenance.tsx` | — | KEEP | **H7** tab: slsa |
| `GRCDashboard.tsx` | — | DEFER | GRC; `?legacy=1` |
| `ComplianceAutomationDashboard.tsx` | — | DEFER | `?legacy=1` |
| `ComplianceCalendarDashboard.tsx` | — | DEFER | `?legacy=1` |
| `ComplianceCoverageHub.tsx` | — | KEEP | **H7** tab: coverage |
| `ComplianceMappingDashboard.tsx` | — | DEFER | Mapping detail; `?legacy=1` |
| `ComplianceScannerDashboard.tsx` | — | KILL | Duplicate of H2 scanning |
| `ComplianceWorkflowDashboard.tsx` | — | DEFER | `?legacy=1` |
| `RegulatoryTrackerDashboard.tsx` | — | DEFER | Regulatory tracker; `?legacy=1` |
| `FipsComplianceDashboard.tsx` | — | KEEP | **H10** tab: fips-status |
| `GapAnalysisDashboard.tsx` | — | DEFER | Gap analysis; `?legacy=1` |
| `PolicyAuthoringHub.tsx` | 805 | KEEP | **H7** tab: policy-authoring |
| `PolicyLifecycleHub.tsx` | 805 | KEEP | **H7** tab: policy-lifecycle |
| `RulesCatalogHub.tsx` | — | KEEP | **H7** tab: rules-catalog |
| `DynamicRuleDSLDashboard.tsx` | — | KILL | Duplicate of RulesCatalogHub |
| `SecurityQueryLanguageDashboard.tsx` | — | KILL | Duplicate of RQLQueryBuilder |
| `CCMDashboard.tsx` | — | DEFER | CCM; `?legacy=1` |
| `ConfigBenchmarkDashboard.tsx` | — | DEFER | CIS benchmark; `?legacy=1` |
| `PrivacyComplianceHub.tsx` | — | DEFER | Privacy; `?legacy=1` |
| `DPOPrivacyHub.tsx` | — | DEFER | DPO; `?legacy=1` |
| `CryptoTrustHub.tsx` | — | DEFER | Crypto trust; `?legacy=1` |
| `MaturityHub.tsx` | — | DEFER | Maturity model; `?legacy=1` |
| `StrategicPostureHub.tsx` | — | DEFER | Strategic posture; `?legacy=1` |
| `PostureAdvisor.tsx` | — | DEFER | Posture advisor; `?legacy=1` |
| `PostureMetricsHub.tsx` | — | KILL | Duplicate of PostureAdvisor |
| `RiskAcceptance.tsx` (root) | — | KILL | Duplicate of `risk/RiskAcceptance.tsx` |
| `risk/RiskAcceptance.tsx` | 1170 | KEEP | **H3** tab: risk-acceptance |
| `RiskQuantHub.tsx` | — | DEFER | Risk quantification; `?legacy=1` |
| `RiskTreatmentDashboard.tsx` | — | DEFER | `?legacy=1` |
| `ScopeManager.tsx` | — | KEEP | **H4** tab: scope-manager |

### 2.8 Onboarding / Connectors / Settings

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `onboarding/OnboardingWizard.tsx` | 926 | KEEP | **H4 Onboarding & Connectors** (primary) |
| `OnboardingPage.tsx` | 828 | KILL | Older duplicate of OnboardingWizard |
| `ImportPage.tsx` | — | KEEP | **H4** tab: import (paste Snyk JSON / upload SARIF) |
| `integrations/IntegrationHealth.tsx` | 818 | KEEP | **H4** tab: connector-health |
| `settings/Integrations.tsx` | — | KEEP | **H4** tab: integration-config |
| `settings/Marketplace.tsx` | — | KEEP | **H8/Settings** tab: marketplace |
| `settings/LogViewer.tsx` | — | KEEP | **H10** tab: logs |
| `IntegrationTargetsHub.tsx` | — | DEFER | Integration targets depth; `?legacy=1` |
| `integration-targets/ProwlerPanel.tsx` | — | DEFER | Prowler panel; `?legacy=1` |
| `integration-targets/ServiceNowPanel.tsx` | — | DEFER | ServiceNow panel; `?legacy=1` |
| `integration-targets/SIEMPanel.tsx` | — | DEFER | SIEM panel; `?legacy=1` |
| `WebhookIngestionHub.tsx` | — | KEEP | **H4** tab: webhook-ingestion |
| `admin/WebhooksOutboundPage.tsx` | — | KEEP | **H8/Settings** tab: webhooks-out |
| `AdminApiKeysPage.tsx` | — | KEEP | **H8/Settings** tab: api-keys |
| `AdminUsersPage.tsx` | — | KEEP | **H8/Settings** tab: users |
| `AdminAuditLogPage.tsx` | — | KEEP | **H10** tab: audit-log |
| `SystemHealthDashboard.tsx` | — | KEEP | **H10 Status/Health** (primary) |
| `CapacityPlanningDashboard.tsx` | — | KEEP | **H10** tab: capacity |
| `SecurityHealthDashboard.tsx` | — | KILL | Duplicate of SystemHealthDashboard |
| `DataPipelineDashboard.tsx` | — | DEFER | Data pipeline; `?legacy=1` |
| `OrgHierarchyDashboard.tsx` | — | DEFER | Org hierarchy dashboard; `?legacy=1` |
| `OrgHierarchyExplorer.tsx` | — | KEEP | **H8/Settings** tab: orgs |
| `AccessRequestManagementDashboard.tsx` | — | DEFER | Access requests; `?legacy=1` |
| `PasswordPolicy.tsx` | — | KEEP | **H8/Settings** tab: password-policy |

### 2.9 Threat Hunting / SOC

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `hunting/ThreatHunting.tsx` | 1083 | KEEP | **H2** tab: threat-hunting |
| `hunting/HuntingAutomationPanel.tsx` | — | KEEP | **H2** sub-tab: hunt-automation |
| `hunting/HuntingPlaybooksPanel.tsx` | — | KEEP | **H2** sub-tab: hunt-playbooks |
| `HuntingHub.tsx` | — | KILL | Wrapper; redirect → `/findings?tab=threat-hunting` |
| `ThreatHunting.tsx` (root) | — | KILL | Duplicate of `hunting/ThreatHunting.tsx` |
| `ThreatHuntingDashboard.tsx` | — | KILL | Duplicate |
| `EndpointHuntingDashboard.tsx` | — | DEFER | Endpoint hunting; `?legacy=1` |
| `BehaviorAnalyticsHub.tsx` | — | DEFER | Behavior analytics; `?legacy=1` |
| `DetectAndRespondHub.tsx` | — | DEFER | D&R; `?legacy=1` |
| `EventTimelineDashboard.tsx` | — | DEFER | Event timeline; `?legacy=1` |
| `SecurityTelemetryDashboard.tsx` | — | DEFER | Telemetry; `?legacy=1` |
| `PAGDashboard.tsx` | — | DEFER | PAG; `?legacy=1` |

### 2.10 Identity / Privileged Access / Vendor / Supply Chain

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `IdentityGovernanceHub.tsx` | — | DEFER | Identity governance; `?legacy=1` |
| `IdentityLifecycleDashboard.tsx` | — | DEFER | `?legacy=1` |
| `IdentityRiskDashboard.tsx` | — | DEFER | `?legacy=1` |
| `CloudIdentityDashboard.tsx` | — | KILL | Duplicate |
| `PrivilegedAccessHub.tsx` | — | DEFER | PAM; `?legacy=1` |
| `ThreatActorsHub.tsx` | — | DEFER | Threat actors; `?legacy=1` |
| `VendorRiskDashboard.tsx` | — | DEFER | Vendor risk; `?legacy=1` |
| `ThirdPartyVendorDashboard.tsx` | — | KILL | Duplicate of VendorRiskDashboard |
| `vendors/VendorManagement.tsx` | 1030 | DEFER | Vendor management; `?legacy=1` |
| `SupplyChainHub.tsx` | — | DEFER | Supply chain hub; `?legacy=1` |
| `SupplyChainAttackDashboard.tsx` | — | KILL | Duplicate |
| `supply-chain/SupplyChainIntelPanel.tsx` | — | DEFER | `?legacy=1` |
| `supply-chain/SupplyChainRiskPanel.tsx` | — | DEFER | `?legacy=1` |
| `supply-chain/SupplyChainSecurityPanel.tsx` | — | DEFER | `?legacy=1` |

### 2.11 Developer / Architect

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `developer/DeveloperPortal.tsx` | 992 | DEFER | Developer portal; `?legacy=1` (too rich to kill, not day-1 priority) |
| `developer/APIExplorer.tsx` | 1173 | KEEP | **H8/Settings** tab: api-explorer |
| `DeveloperSecurityHub.tsx` | — | DEFER | Dev security; `?legacy=1` |
| `DevSecOpsDashboard.tsx` | — | DEFER | DevSecOps; `?legacy=1` |
| `IDEBackendDashboard.tsx` | 806 | DEFER | IDE gateway; `?legacy=1` |
| `CrownJewelConfigurator.tsx` | — | DEFER | Crown jewel; `?legacy=1` |

### 2.12 Security Culture / Misc

| File | LOC | Verdict | Destination |
|------|-----|---------|-------------|
| `SecurityAwareness.tsx` | — | KILL | Out of scope for on-prem AI brain |
| `AwarenessHub.tsx` | — | KILL | Duplicate |
| `TrainingCultureHub.tsx` | 691 | KILL | Out of scope |
| `SecurityChampionsDashboard.tsx` | — | KILL | Out of scope |
| `SecurityGamificationDashboard.tsx` | — | KILL | Out of scope |
| `SecurityQuestionnaireDashboard.tsx` | — | KILL | Out of scope |
| `SecurityTabletopDashboard.tsx` | — | KILL | Out of scope |
| `SecurityKPIDashboard.tsx` | — | DEFER | KPI dashboard; could be useful later; `?legacy=1` |
| `SecurityMetricsDashboard.tsx` | — | KILL | Duplicate |
| `SecurityMetricsDashboard2.tsx` | — | KILL | Duplicate |
| `SecurityOperationsMetricsDashboard.tsx` | — | KILL | Duplicate |
| `CyberResilienceDashboard.tsx` | — | DEFER | Resilience metrics; `?legacy=1` |
| `CyberInsurance.tsx` | — | KILL | Out of scope |
| `CompetitiveComparisonPage.tsx` | — | KILL | Internal tool; delete |
| `UpgradePathsHub.tsx` | — | DEFER | Upgrade paths; `?legacy=1` |
| `ScheduledReportsDashboard.tsx` | 694 | KEEP | **H7** tab: scheduled-reports |
| `TracedFlowViewer.tsx` | — | KEEP | **H5** tab: traced-flow |
| `CopilotGraphChat.tsx` (root dup) | — | KILL | Duplicate; see §2.5 |
| `AuditLog.tsx` | — | KEEP | **H10** tab: audit-log (merge with `AdminAuditLogPage.tsx`) |

---

## 3. Bucket Summary

| Verdict | Count | % of 259 |
|---------|-------|----------|
| KEEP (fold into hero screens) | 98 | 37.8% |
| KILL (delete file + route) | 71 | 27.4% |
| DEFER (hide from nav, `?legacy=1`) | 90 | 34.7% |

**LOC at risk if KILL executes**: ~28,000 LOC (71 files averaging ~395 LOC each; skewed low because most kill-candidates are thin stubs or duplicates under 200 LOC).

**LOC preserved in KEEP**: ~68,500 LOC across the 98 files that fold into hero screens.

**LOC parked in DEFER**: ~38,000 LOC — accessible via `?legacy=1` query param, no routes removed, no files deleted.

**Estimated bundle size reduction** (after KILL executes and dead-code tree-shaking runs): approximately 35–45% smaller JS bundle based on a rough 1:1 LOC-to-chunk-weight ratio for React TSX. The 71 kill-candidates account for ~29% of page files; with Vite code-splitting each route is a lazy chunk, so the main bundle impact is in shared imports they drag in.

---

## 4. Routes to Remove from `App.tsx`

Once the founder approves the KILL list, remove these `<Route>` entries. Do not remove redirects yet — remove the component import and replace with `<Navigate>` to the appropriate hero screen.

```
/board                          → <Navigate to="/" replace />
/status                         → <Navigate to="/admin?tab=system-health" replace />
/landing                        → <Navigate to="/" replace />
/marketing                      → <Navigate to="/" replace />
/home                           → <Navigate to="/" replace />
/pricing                        → <Navigate to="/" replace />
/onboard                        → <Navigate to="/connect" replace />
/discover                       → <Navigate to="/findings" replace />   (was FindingExplorer, old version)
/threat-hunting                 → <Navigate to="/findings?tab=threat-hunting" replace />
/mission-control/hunt           → <Navigate to="/findings?tab=threat-hunting" replace />
/hunting                        → <Navigate to="/findings?tab=threat-hunting" replace />
/ai-advisor-dashboard           → <Navigate to="/brain?tab=copilot" replace />
/network-forensics              → <Navigate to="/remediate/forensics?tab=network" replace />  (keep forensics DEFER target)
/malware-analysis               → <Navigate to="/remediate/forensics?tab=malware" replace />
/digital-forensics              → <Navigate to="/remediate/forensics?tab=digital" replace />
/vuln-scan-dashboard            → <Navigate to="/findings?tab=code-scanning" replace />
/cloud-findings                 → <Navigate to="/findings?tab=cloud" replace />
/security-findings              → <Navigate to="/findings" replace />
/attack-surface duplicates      → <Navigate to="/findings?tab=attack-surface" replace />
```

All other existing `<Navigate>` redirects in `App.tsx` should be preserved — they are already doing the right thing and removing them risks breaking bookmarks.

---

## 5. Routes to Add for the 10 Hero Screens

Most hero screen routes already exist. The following are missing or need renaming:

| Route | Component | Action |
|-------|-----------|--------|
| `/` | `CISODashboard` (H1) | Exists — change content to add MTTR trend + AI verdicts panel |
| `/findings` | `FindingsExplorer` (H2) | Exists — promote to top nav |
| `/risk` | `RiskOverview` (H3) | Add alias: currently `/mission-control/risk` — add short alias `/risk` |
| `/connect` | `OnboardingWizard` (H4) | Rename from `/onboarding` to `/connect` |
| `/brain` | existing tab-hub (H5 + H6) | Exists — already a tab-hub with pipeline, consensus etc |
| `/comply` | `ComplianceDashboard` (H7) | Exists — already mounted |
| `/settings` | settings tab-hub (H8 + H9) | Add tabs: `llm-keys`, `license` to existing settings hub |
| `/admin` | admin tab-hub (H10) | Exists — `SystemHealthDashboard` already a tab |

---

## 6. Nav Menu Rewrite Plan

### Current nav (WorkspaceLayout.tsx) — too many sections

The current nav has 12+ section groups with 40+ items visible. An engineer sees 8 groups before scrolling. This is the core problem.

### Proposed nav — 7 items max, no scroll

```
[ ALDECI logo ]
─────────────────
  Dashboard        /             (H1 — AI decisions this week)
  Findings         /findings     (H2 — searchable, all scanner output)
  Risk             /risk         (H3 — 5×5 heatmap + treatment)
  AI Brain         /brain        (H5+H6 — council trail + pipeline)
  Comply           /comply       (H7 — evidence + frameworks)
  Connect          /connect      (H4 — onboarding + connectors)
─────────────────
  Settings         /settings     (H8+H9 — LLM keys, license)
  Status           /admin        (H10 — health + logs)
─────────────────
  [ AI Copilot ]   (right-hand slide-out — unchanged)
```

**Remove from primary nav**: all 12 current section groups. Collapse into the 7 items above.

**Advanced items** (currently in "adminItems" dropdown): move to `/settings` tabs or `/admin` tabs. Do not surface in primary nav.

**Rename**: "Mission Control" → "Dashboard". "Discover" → "Findings". "Validate" → fold into "AI Brain" tab. "Remediate" → fold into "Findings" tabs (cases, incidents, exceptions). "Comply" → keep as "Comply".

---

## 7. Migration Path — `?legacy=1` Query Param

For every file in the DEFER bucket, the existing route stays mounted in `App.tsx` but is **hidden from the nav menu** immediately. The route remains accessible via direct URL and via `?legacy=1` as a query-param hint (the layout can show a "Legacy view" banner).

Implementation steps (execution phase, not now):
1. Add a `LegacyBanner` component: "This view is scheduled for removal. [Give feedback]"
2. In `WorkspaceLayout.tsx`, check `useSearchParams().get('legacy') === '1'` and render the banner.
3. For each DEFER route, append `?legacy=1` when linking from anywhere inside the app.
4. After 30 days with telemetry, promote surviving DEFER pages to KEEP or move to KILL.

No `.tsx` files are deleted in this phase. The branch for execution will add the banner component and strip nav entries only.

---

## 8. Execution Checklist (Founder Signs Off → Then We Run)

- [ ] Founder reviews KILL list — challenge any file before we delete
- [ ] Founder reviews DEFER list — flag any that should be promoted to KEEP
- [ ] Confirm H8 (LLM Keys) and H9 (License) tabs need to be built from scratch
- [ ] Confirm `/connect` as the canonical route for H4 (replaces `/onboarding`)
- [ ] Confirm 7-item nav structure above
- [ ] Confirm `?legacy=1` banner approach vs. full 404 for DEFERred routes

Once signed off, execution order:
1. Add `LegacyBanner` component (30 min)
2. Strip nav to 7 items in `WorkspaceLayout.tsx` (2 hrs)
3. Add missing routes `/risk`, `/connect`, settings tabs H8+H9 (4 hrs)
4. Delete KILL-list `.tsx` files + replace their `<Route>` entries with `<Navigate>` (4 hrs)
5. Run `npx tsc --noEmit` + `npm run build` — fix any broken imports (2 hrs)
6. Playwright smoke: navigate to all 10 hero screens, screenshot, verify no blank pages (1 hr)
7. Commit: `feat(ui): consolidate 168 hub tabs → 10 hero screens`

**Estimated total execution time**: 1.5 engineer-days.
**Estimated LOC deleted**: ~28,000
**Estimated bundle reduction**: 35–45%
**Screens remaining after execution**: 10 hero + shell (login/404/docs) + ~90 legacy behind `?legacy=1`
