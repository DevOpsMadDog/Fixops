import { lazy, Suspense } from "react";
import LoginPage from "@/pages/auth/LoginPage";
import { Routes, Route, Navigate } from "react-router-dom";
import { WorkspaceLayout } from "@/components/layout/WorkspaceLayout";
import { ErrorBoundary } from "@/components/shared/ErrorBoundary";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import NotFound from "@/pages/NotFound";
import { RequireAuth, RequireRole } from "@/lib/auth";
import { GenericDashboard } from "@/components/GenericDashboard";
import { DASHBOARD_ROUTES } from "@/config/dashboardRoutes";
import { FindingsExplorerView } from "@/components/FindingsExplorerView";
import { FINDINGS_EXPLORER_ROUTES } from "@/config/findingsExplorerRoutes";

// Tour — public demo mode (no auth)
const Tour = lazy(() => import("@/pages/Tour"));
// Status — public, no auth required (Multica #4113)
const StatusPage = lazy(() => import("@/pages/StatusPage"));
// Pricing — public landing page, no auth required (Multica #4123)
const PricingPage = lazy(() => import("@/pages/PricingPage"));
// Password reset — public, no auth required (Multica #4132)
const ForgotPasswordPage = lazy(() => import("@/pages/auth/ForgotPasswordPage"));
const ResetPasswordPage = lazy(() => import("@/pages/auth/ResetPasswordPage"));
// Support — public, no auth required (Multica #4137)
const SupportPage = lazy(() => import("@/pages/SupportPage"));

// Auth — LoginPage is eagerly imported above (must always work, no Suspense boundary)

// ── Lazy-loaded pages ──

// Space 1: Mission Control
const SLADashboard = lazy(() => import("@/pages/mission-control/SLADashboard"));
const LiveFeed = lazy(() => import("@/pages/mission-control/LiveFeed"));
const RiskOverview = lazy(() => import("@/pages/mission-control/RiskOverview"));
const MissionControlComplianceDashboard = lazy(() => import("@/pages/mission-control/ComplianceDashboard"));
const ThreatIntelDashboard = lazy(() => import("@/pages/mission-control/ThreatIntelDashboard"));
const RiskRegister = lazy(() => import("@/pages/mission-control/RiskRegister"));
const CISODashboard = lazy(() => import("@/pages/mission-control/CISODashboard"));

// Findings Explorer (universal — all personas)
const FindingsExplorer = lazy(() => import("@/pages/findings/FindingsExplorer"));

// Space 2: Discover
const FindingExplorer = lazy(() => import("@/pages/discover/FindingExplorer"));
const CodeScanning = lazy(() => import("@/pages/discover/CodeScanning"));
const IaCScanning = lazy(() => import("@/pages/discover/IaCScanning"));
const CloudPosture = lazy(() => import("@/pages/discover/CloudPosture"));
const ContainerSecurity = lazy(() => import("@/pages/discover/ContainerSecurity"));
const SBOMInventory = lazy(() => import("@/pages/discover/SBOMInventory"));
const AttackPaths = lazy(() => import("@/pages/discover/AttackPaths"));
const ThreatFeeds = lazy(() => import("@/pages/discover/ThreatFeeds"));
const CorrelationEngine = lazy(() => import("@/pages/discover/CorrelationEngine"));
const DataFabric = lazy(() => import("@/pages/discover/DataFabric"));
// P29 Software Architect persona — ArchitectWorkspaceHub
const ArchitectWorkspaceHub = lazy(() => import("@/pages/discover/ArchitectWorkspaceHub"));

// Space 3: Validate
const AttackSimulation = lazy(() => import("@/pages/validate/AttackSimulation"));
const Reachability = lazy(() => import("@/pages/validate/Reachability"));

// Space 4: Remediate
const Collaboration = lazy(() => import("@/pages/remediate/Collaboration"));
const ExposureCases = lazy(() => import("@/pages/remediate/ExposureCases"));
const TicketIntegration = lazy(() => import("@/pages/remediate/TicketIntegration"));

// Space 5: Comply
const ComplianceDashboard = lazy(() => import("@/pages/comply/ComplianceDashboard"));
const SOC2Evidence = lazy(() => import("@/pages/comply/SOC2Evidence"));
const SLSAProvenance = lazy(() => import("@/pages/comply/SLSAProvenance"));
const Reports = lazy(() => import("@/pages/comply/Reports"));
const Analytics = lazy(() => import("@/pages/comply/Analytics"));
const EvidenceExportCenter = lazy(() => import("@/pages/comply/EvidenceExportCenter"));
const AuditorEvidenceHub = lazy(() => import("@/pages/comply/AuditorEvidenceHub"));

// Settings
const Integrations = lazy(() => import("@/pages/settings/Integrations"));
const Marketplace = lazy(() => import("@/pages/settings/Marketplace"));
const LogViewer = lazy(() => import("@/pages/settings/LogViewer"));

// Onboarding
const OnboardingWizard = lazy(() => import("@/pages/onboarding/OnboardingWizard"));
const OnboardingPage = lazy(() => import("@/pages/OnboardingPage"));

// Developer Security Hub (P20 + P11) — replaces DeveloperPortal 2026-05-05
const DeveloperSecurityHub = lazy(() => import("@/pages/DeveloperSecurityHub"));
const DeveloperPortal = lazy(() => import("@/pages/developer/DeveloperPortal"));
const APIExplorer = lazy(() => import("@/pages/developer/APIExplorer"));

// Attack Surface
const AttackSurface = lazy(() => import("@/pages/attack-surface/AttackSurface"));

// Integration Health
const IntegrationHealth = lazy(() => import("@/pages/integrations/IntegrationHealth"));

// Threat Hunting
const ThreatHunting = lazy(() => import("@/pages/hunting/ThreatHunting"));
// Phase 3 fold (2026-05-02): Hunting unified hub at /mission-control/hunt
const HuntingHub = lazy(() => import("@/pages/HuntingHub"));

// Vendor Management
const VendorManagement = lazy(() => import("@/pages/vendors/VendorManagement"));

// Incident Response
const IncidentResponse = lazy(() => import("@/pages/incidents/IncidentResponse"));

// Risk Acceptance
const RiskAcceptance = lazy(() => import("@/pages/RiskAcceptance"));

// SBOM Management
const SBOMManagement = lazy(() => import("@/pages/sbom/SBOMManagement"));

// New standalone pages
const ThreatIntelDashboardPage = lazy(() => import("@/pages/ThreatIntelDashboard"));
const SecurityKPIDashboard = lazy(() => import("@/pages/SecurityKPIDashboard"));
const VendorRiskDashboard = lazy(() => import("@/pages/VendorRiskDashboard"));
const PostureAdvisor = lazy(() => import("@/pages/PostureAdvisor"));
const AutomationOrchestrationHub = lazy(() => import("@/pages/AutomationOrchestrationHub"));
const DLPDashboard = lazy(() => import("@/pages/DLPDashboard"));
const ThreatModelingHub = lazy(() => import("@/pages/ThreatModelingHub"));
const AttackPathAnalysis = lazy(() => import("@/pages/AttackPathAnalysis"));
const IncidentTimeline = lazy(() => import("@/pages/IncidentTimeline"));
const IdentityGovernanceHub = lazy(() => import("@/pages/IdentityGovernanceHub"));
const SecurityAwareness = lazy(() => import("@/pages/SecurityAwareness"));
const NetworkAnalysis = lazy(() => import("@/pages/NetworkAnalysis"));
const VulnHeatmap = lazy(() => import("@/pages/VulnHeatmap"));
const AuditLog = lazy(() => import("@/pages/AuditLog"));
const AdminAuditLogPage = lazy(() => import("@/pages/AdminAuditLogPage"));
const AdminUsersPage = lazy(() => import("@/pages/AdminUsersPage"));
const AdminApiKeysPage = lazy(() => import("@/pages/AdminApiKeysPage"));
const ThreatHuntingPage = lazy(() => import("@/pages/ThreatHunting"));
const OffensiveValidationHub = lazy(() => import("@/pages/OffensiveValidationHub"));
const CloudIAM = lazy(() => import("@/pages/CloudIAM"));
const EmailThreatProtectionHub = lazy(() => import("@/pages/EmailThreatProtectionHub"));
const SecurityMetricsDashboard = lazy(() => import("@/pages/SecurityMetricsDashboard"));
const MobileSecurity = lazy(() => import("@/pages/MobileSecurity"));
const PasswordPolicy = lazy(() => import("@/pages/PasswordPolicy"));
// S10 Application Security hub — Phase 3 cluster (2026-05-02): 3 pages folded
const AppLayerSecurityHub = lazy(() => import("@/pages/AppLayerSecurityHub"));
const VulnRiskQueue = lazy(() => import("@/pages/VulnRiskQueue"));
const NetworkTopology = lazy(() => import("@/pages/NetworkTopology"));
const GRCDashboard = lazy(() => import("@/pages/GRCDashboard"));
const ThreatCorrelation = lazy(() => import("@/pages/ThreatCorrelation"));
const CloudPostureUnifiedHub = lazy(() => import("@/pages/CloudPostureUnifiedHub"));
const APISecurityPage = lazy(() => import("@/pages/APISecurityPage"));
const CyberInsurance = lazy(() => import("@/pages/CyberInsurance"));
const VulnerabilityScanner = lazy(() => import("@/pages/VulnerabilityScanner"));
// P3 fold 2026-05-02 — Risk Quant cluster hub (folds RiskQuantification, RiskQuantDashboard, RiskScenarioDashboard)
const RiskQuantHub = lazy(() => import("@/pages/RiskQuantHub"));
// P3 fold 2026-05-02 — Strategic Posture cluster hub (folds SecurityPostureDashboard, SecurityRoadmap, GRCAssessment)
const StrategicPostureHub = lazy(() => import("@/pages/StrategicPostureHub"));
const VulnerabilityScannerPage = lazy(() => import("@/pages/VulnerabilityScannerPage"));
// FOLDED 2026-05-02 → ForensicsHub#digital. Hub re-imports lazily.
const DataGovernanceDashboard = lazy(() => import("@/pages/DataGovernanceDashboard"));
const ThreatHuntingDashboard = lazy(() => import("@/pages/ThreatHuntingDashboard"));
const ComplianceScannerDashboard = lazy(() => import("@/pages/ComplianceScannerDashboard"));
const SecurityHealthDashboard = lazy(() => import("@/pages/SecurityHealthDashboard"));

// New pages: Cross-Domain Analytics, DevSecOps, Vuln Trends, Config Benchmarks
const CrossDomainAnalytics = lazy(() => import("@/pages/CrossDomainAnalytics"));
const DevSecOpsDashboard = lazy(() => import("@/pages/DevSecOpsDashboard"));
const VulnTrendDashboard = lazy(() => import("@/pages/VulnTrendDashboard"));
const ConfigBenchmarkDashboard = lazy(() => import("@/pages/ConfigBenchmarkDashboard"));

// New Beast Mode pages
const SecurityMetricsDashboard2 = lazy(() => import("@/pages/SecurityMetricsDashboard2"));
const ZeroTrustPolicyDashboard = lazy(() => import("@/pages/ZeroTrustPolicyDashboard"));

// OpenClaw + SOC Triage AI + SBOM Dashboard
const DASTDashboard = lazy(() => import("@/pages/DASTDashboard"));
const IRPlaybookDashboard = lazy(() => import("@/pages/IRPlaybookDashboard"));

// NDR / XDR / Awareness / EDR pages
const NDRDashboard = lazy(() => import("@/pages/NDRDashboard"));

// Awareness hub (Phase 3 fold 2026-05-02 — folds 4 awareness dashboards)
const AwarenessHub = lazy(() => import("@/pages/AwarenessHub"));

// Training & Culture hub (Phase 3 fold 2026-05-02 — folds 3 training/culture dashboards)
const TrainingCultureHub = lazy(() => import("@/pages/TrainingCultureHub"));

// New Beast Mode pages — Identity Analytics, CNAPP, Pentest Mgmt, Supply Chain Intel
const SupplyChainHub = lazy(() => import("@/pages/SupplyChainHub"));

// Governance + Executive pages
const RegulatoryTrackerDashboard = lazy(() => import("@/pages/RegulatoryTrackerDashboard"));
const CCMDashboard = lazy(() => import("@/pages/CCMDashboard"));

// System Health Dashboard
const SystemHealthDashboard = lazy(() => import("@/pages/SystemHealthDashboard"));

// Security Maturity, Privacy/GDPR, Network Traffic, Container Security
const NetworkTrafficDashboard = lazy(() => import("@/pages/NetworkTrafficDashboard"));

// Threat Actor Intelligence + Security Champions
const SecurityChampionsDashboard = lazy(() => import("@/pages/SecurityChampionsDashboard"));

// Compliance Dashboard — standalone P07 view (route: /compliance)

// Threat Geolocation + IP Reputation dashboards

// Secret Scanner, TIP, Attack Surface dashboards (wave 9)
const ContainerRegistryDashboard = lazy(() => import("@/pages/ContainerRegistryDashboard"));
const NetworkMonitoringHub = lazy(() => import("@/pages/NetworkMonitoringHub"));
const SCADashboard = lazy(() => import("@/pages/SCADashboard"));
const ThreatIntelPlatformDashboard = lazy(() => import("@/pages/ThreatIntelPlatformDashboard"));

// API Security Management + Vuln Intelligence

// Phase 3 UX consolidation 2026-05-02 — Vuln Intelligence hub (S7 sub-cluster)
const VulnIntelHub = lazy(() => import("@/pages/VulnIntelHub"));
const ExternalThreatIntelHub = lazy(() => import("@/pages/ExternalThreatIntelHub"));

// AI Security Advisor
const AISecurityAdvisor = lazy(() => import("@/pages/AISecurityAdvisor"));

// AI Security Advisor Dashboard + Scheduled Reports Dashboard
const AISecurityAdvisorDashboard = lazy(() => import("@/pages/AISecurityAdvisorDashboard"));
const ScheduledReportsDashboard = lazy(() => import("@/pages/ScheduledReportsDashboard"));

// Crypto Key, Certificate, Privilege Escalation, Security Automation dashboards
const SecurityAutomationDashboard = lazy(() => import("@/pages/SecurityAutomationDashboard"));

// Cloud Compliance + Endpoint Compliance dashboards

// Firewall Policy, Network Segmentation dashboards
const NetworkSegmentationDashboard = lazy(() => import("@/pages/NetworkSegmentationDashboard"));

// MFA Management, Threat Scores, Security Budget, Compliance Gaps

// Wave 18 domain dashboards
const ThreatExposureDashboard = lazy(() => import("@/pages/ThreatExposureDashboard"));
const SoftwareLicenseDashboard = lazy(() => import("@/pages/SoftwareLicenseDashboard"));
const CloudIdentityDashboard = lazy(() => import("@/pages/CloudIdentityDashboard"));

// Wave 19 domain dashboards
const SecurityChaosDashboard = lazy(() => import("@/pages/SecurityChaosDashboard"));

// Wave 20 domain dashboards
const SecurityTabletopDashboard = lazy(() => import("@/pages/SecurityTabletopDashboard"));

// Wave 21 domain dashboards
const FirmwareSecurityDashboard = lazy(() => import("@/pages/FirmwareSecurityDashboard"));
const SupplyChainAttackDashboard = lazy(() => import("@/pages/SupplyChainAttackDashboard"));

// Wave 22 domain dashboards
const VulnerabilityCorrelationDashboard = lazy(() => import("@/pages/VulnerabilityCorrelationDashboard"));

// Phase 3 UX consolidation: CryptoTrustHub folds CryptoKey/Certificate/CertManager/PKI/QuantumCrypto
const CryptoTrustHub = lazy(() => import("@/pages/CryptoTrustHub"));

// Wave 23 domain dashboards
const ThreatIntelAutomation = lazy(() => import("@/pages/ThreatIntelAutomation"));
const EndpointHuntingDashboard = lazy(() => import("@/pages/EndpointHuntingDashboard"));
const CloudSecurityAnalyticsDashboard = lazy(() => import("@/pages/CloudSecurityAnalyticsDashboard"));
const IdentityRiskDashboard = lazy(() => import("@/pages/IdentityRiskDashboard"));
const OTSecurityDashboard = lazy(() => import("@/pages/OTSecurityDashboard"));

// Wave 24 domain dashboards
// FOLDED 2026-05-02 → ForensicsHub uses FindingsExplorerView from FINDINGS_EXPLORER_ROUTES.
// Standalone dashboards retained on disk for git history; previously unrouted.
const PAGDashboard = lazy(() => import("@/pages/PAGDashboard"));
const SecurityGamificationDashboard = lazy(() => import("@/pages/SecurityGamificationDashboard"));

// Wave 25 domain dashboards
const DeceptionHub = lazy(() => import("@/pages/DeceptionHub"));
const APIThreatProtectionDashboard = lazy(() => import("@/pages/APIThreatProtectionDashboard"));
const ChangeManagementDashboard = lazy(() => import("@/pages/ChangeManagementDashboard"));

// Wave 26 domain dashboards
const ComplianceAutomationDashboard = lazy(() => import("@/pages/ComplianceAutomationDashboard"));
const CloudAccessSecurityDashboard = lazy(() => import("@/pages/CloudAccessSecurityDashboard"));
const DataPipelineDashboard = lazy(() => import("@/pages/DataPipelineDashboard"));

// Wave 27 domain dashboards
// Phase 3 UX consolidation — Container Security hub (folds image + runtime + posture, 2026-05-02)
const ContainerSecurityHub = lazy(() => import("@/pages/ContainerSecurityHub"));
// Phase 3 UX consolidation — Detect & Respond hub (folds XDR + EDR + ITDR, 2026-05-02)
const DetectAndRespondHub = lazy(() => import("@/pages/DetectAndRespondHub"));
// Phase 3 UX consolidation — API Security hub (folds inventory + management + discovery, 2026-05-02)
const APISecurityHub = lazy(() => import("@/pages/APISecurityHub"));
const CyberThreatIntelDashboard = lazy(() => import("@/pages/CyberThreatIntelDashboard"));
const DigitalTwinDashboard = lazy(() => import("@/pages/DigitalTwinDashboard"));

// Wave 28 domain dashboards
const AccessRequestManagementDashboard = lazy(() => import("@/pages/AccessRequestManagementDashboard"));
// Phase 3 UX consolidation — Privileged Access hub (folds MFA + PAM + Sessions, 2026-05-02)
const PrivilegedAccessHub = lazy(() => import("@/pages/PrivilegedAccessHub"));
const SecurityTelemetryDashboard = lazy(() => import("@/pages/SecurityTelemetryDashboard"));
const NetworkSegmentationHub = lazy(() => import("@/pages/NetworkSegmentationHub"));
const ThirdPartyVendorDashboard = lazy(() => import("@/pages/ThirdPartyVendorDashboard"));

// Wave 29 domain dashboards
const ThreatVectorDashboard = lazy(() => import("@/pages/ThreatVectorDashboard"));
const RiskTreatmentDashboard = lazy(() => import("@/pages/RiskTreatmentDashboard"));

// Wave 30 domain dashboards
const ComplianceMappingDashboard = lazy(() => import("@/pages/ComplianceMappingDashboard"));
const VulnScanDashboard = lazy(() => import("@/pages/VulnScanDashboard"));
// P3 fold 2026-05-02 — Asset metadata sub-cluster (groups/tags/criticality) hub
const AssetInventoryHub = lazy(() => import("@/pages/AssetInventoryHub"));

// Strategic engine dashboards (2026-04-25)
const OrgHierarchyDashboard = lazy(() => import("@/pages/OrgHierarchyDashboard"));
const SecurityQueryLanguageDashboard = lazy(() => import("@/pages/SecurityQueryLanguageDashboard"));
const ArchAwareGraphDashboard = lazy(() => import("@/pages/ArchAwareGraphDashboard"));
const IDEBackendDashboard = lazy(() => import("@/pages/IDEBackendDashboard"));

// Strategic engine dashboards — batch 2 (2026-04-25)
// Phase 3 UX consolidation — S21 unified hero (2026-05-02)
const UpgradePathsHub = lazy(() => import("@/pages/UpgradePathsHub"));
const SBOMProvenanceHub = lazy(() => import("@/pages/SBOMProvenanceHub"));
const CodeToRuntimeDashboard = lazy(() => import("@/pages/CodeToRuntimeDashboard"));
const FipsComplianceDashboard = lazy(() => import("@/pages/FipsComplianceDashboard"));
const LocalFileStoreDashboard = lazy(() => import("@/pages/LocalFileStoreDashboard"));
const DynamicRuleDSLDashboard = lazy(() => import("@/pages/DynamicRuleDSLDashboard"));

// Wave 35 domain dashboards
const VulnScoringDashboard = lazy(() => import("@/pages/VulnScoringDashboard"));

// Wave 42 domain dashboards (frontend pages for Wave 41 engines)
const CloudCostOptimizationDashboard = lazy(() => import("@/pages/CloudCostOptimizationDashboard"));

// Phase 3 UX consolidation hubs (2026-05-02)
const ThreatActorsHub = lazy(() => import("@/pages/ThreatActorsHub"));
const PolicyAuthoringHub = lazy(() => import("@/pages/PolicyAuthoringHub"));
const PolicyLifecycleHub = lazy(() => import("@/pages/PolicyLifecycleHub"));
const SecretsHub = lazy(() => import("@/pages/SecretsHub"));

// Sales & Marketing
const CompetitiveComparisonPage = lazy(() => import("@/pages/CompetitiveComparisonPage"));
const LandingPage = lazy(() => import("@/pages/LandingPage"));
// Marketing landing page — public, no auth (Multica #4143)
const MarketingLandingPage = lazy(() => import("@/pages/marketing/LandingPage"));

// Security Graph — interactive force-directed security relationship canvas

// Wave 41 domain dashboards (frontend pages for Wave 40 engines)
const ArchReviewDashboard = lazy(() => import("@/pages/ArchReviewDashboard"));
const IdentityLifecycleDashboard = lazy(() => import("@/pages/IdentityLifecycleDashboard"));

// Wave 40 domain dashboards (frontend pages for Wave 39 engines)
const CapacityPlanningDashboard = lazy(() => import("@/pages/CapacityPlanningDashboard"));
const EventTimelineDashboard = lazy(() => import("@/pages/EventTimelineDashboard"));

// Wave 39 domain dashboards

// Wave 38 domain dashboards
const GapAnalysisDashboard = lazy(() => import("@/pages/GapAnalysisDashboard"));

// Wave 37 domain dashboards
const SecurityOperationsMetricsDashboard = lazy(() => import("@/pages/SecurityOperationsMetricsDashboard"));
const VulnLifecyclePipelineHub = lazy(() => import("@/pages/VulnLifecyclePipelineHub"));
const ThreatIntelConfidenceDashboard = lazy(() => import("@/pages/ThreatIntelConfidenceDashboard"));

// Wave 36 domain dashboards
const ComplianceCalendarDashboard = lazy(() => import("@/pages/ComplianceCalendarDashboard"));
const CyberResilienceDashboard = lazy(() => import("@/pages/CyberResilienceDashboard"));

// Wave 34 domain dashboards
const SecurityQuestionnaireDashboard = lazy(() => import("@/pages/SecurityQuestionnaireDashboard"));
// Phase 3 — Threat Intel Operations hero (combined 4-page fold 2026-05-02)
const ThreatIntelOpsHub = lazy(() => import("@/pages/ThreatIntelOpsHub"));

// Wave 32 domain dashboards
const ComplianceWorkflowDashboard = lazy(() => import("@/pages/ComplianceWorkflowDashboard"));
// Phase 3 §2.11 (Posture Metrics sub-cluster) — PostureMetricsHub at /discover/posture-metrics
const PostureMetricsHub = lazy(() => import("@/pages/PostureMetricsHub"));

// Wave 31 domain dashboards
// Phase 3 hub fold 2026-05-02 — IncidentMetrics + IncidentKB + IncidentLessons
const IncidentKnowledgeHub = lazy(() => import("@/pages/IncidentKnowledgeHub"));
const IntelEnrichmentDashboard = lazy(() => import("@/pages/IntelEnrichmentDashboard"));

// Connector dashboards — Prowler, ServiceNow, SIEM Output
// FOLDED into IntegrationTargetsHub at /connect/targets (2026-05-02) — kept as lazy imports for hub composition
const IntegrationTargetsHub = lazy(() => import("@/pages/IntegrationTargetsHub"));
// FOLDED into WebhookIngestionHub at /connect/webhook-ingestion (2026-05-02)
const WebhookIngestionHub = lazy(() => import("@/pages/WebhookIngestionHub"));

// Neural Brain Visualization
const BrainVisualization = lazy(() => import("@/pages/BrainVisualization"));

// Main Overview Dashboard

// Wave 3 — risk / dashboards / runtime (15 screens, 2026-04-26)
const BRSExecutiveDashboard = lazy(() => import("@/pages/BRSExecutiveDashboard"));
// Phase 3 UX consolidation S2 — Executive Brief Finance/Investment hub (2026-05-02)
const FinanceHub = lazy(() => import("@/pages/FinanceHub"));
const ForensicsHub = lazy(() => import("@/pages/ForensicsHub"));
const SBOMContinuousMonitoring = lazy(() => import("@/pages/SBOMContinuousMonitoring"));
const RuntimeCodeTrace = lazy(() => import("@/pages/RuntimeCodeTrace"));

// ── Phase 3 P0 hero pages (UX_CONSOLIDATION_PLAN_2026-04-26.md) ──
// ── Phase 3 P1 hero (Remediate) ──
// ── Phase 3 P0 Wave 3 hero pages (Command + Admin) ──

// AI Copilot & AI Engine
const CopilotDashboard = lazy(() => import("@/pages/ai/CopilotDashboard"));

// Frontend Wave 1 — AI / discovery / code-intel screens
const CodeSemanticExplorer = lazy(() => import("@/pages/discover/CodeSemanticExplorer"));
const CallGraphExplorer = lazy(() => import("@/pages/discover/CallGraphExplorer"));
const ReachabilityProof = lazy(() => import("@/pages/validate/ReachabilityProof"));
const PIIFieldInventory = lazy(() => import("@/pages/discover/PIIFieldInventory"));
const ComponentIdentityView = lazy(() => import("@/pages/discover/ComponentIdentityView"));
const AIAttackPathView = lazy(() => import("@/pages/ai/AIAttackPathView"));
const MCPToolRegistry = lazy(() => import("@/pages/ai/MCPToolRegistry"));
const Copilot = lazy(() => import("@/pages/ai/Copilot"));
const CopilotGraphChat = lazy(() => import("@/pages/ai/CopilotGraphChat"));
const TraversalExplanationPanel = lazy(() => import("@/pages/ai/TraversalExplanationPanel"));
const AICopilotAgentsHub = lazy(() => import("@/pages/AICopilotAgentsHub"));

// Frontend Wave 4 — final cleanup wave (35 screens, 2026-04-26)
// Phase 3 §2.28 (Air-Gap operational sub-cluster) — AirGapHub at /connect/mcp/air-gap
const AirGapHub = lazy(() => import("@/pages/AirGapHub"));
const ClaudeSkillsRegistry = lazy(() => import("@/pages/ClaudeSkillsRegistry"));
const SkillsInstallPrompt = lazy(() => import("@/pages/SkillsInstallPrompt"));
const LocalStoreStatus = lazy(() => import("@/pages/LocalStoreStatus"));
const CopilotGraphChatRoot = lazy(() => import("@/pages/CopilotGraphChat"));
const RQLQueryBuilder = lazy(() => import("@/pages/RQLQueryBuilder"));
const SavedInvestigations = lazy(() => import("@/pages/SavedInvestigations"));
const ScopeManager = lazy(() => import("@/pages/ScopeManager"));
const DomainSeedDiscoveryWizard = lazy(() => import("@/pages/DomainSeedDiscoveryWizard"));
const LLMContextTierBadge = lazy(() => import("@/pages/LLMContextTierBadge"));
const LLMPreFlightEstimateModal = lazy(() => import("@/pages/LLMPreFlightEstimateModal"));
const LLMRuleContextEditor = lazy(() => import("@/pages/LLMRuleContextEditor"));
const CrownJewelConfigurator = lazy(() => import("@/pages/CrownJewelConfigurator"));
const OrgHierarchyExplorer = lazy(() => import("@/pages/OrgHierarchyExplorer"));
const StaleBaselineBanner = lazy(() => import("@/pages/StaleBaselineBanner"));
const TracedFlowViewer = lazy(() => import("@/pages/TracedFlowViewer"));
const ZeroSetupOnboarding = lazy(() => import("@/pages/ZeroSetupOnboarding"));
// Founder-P0 #4003 — repo URL + zip import page
const ImportPage = lazy(() => import("@/pages/ImportPage"));

// Frontend Wave 2 — policy / waivers / rules / audit (14 screens, 2026-04-26)
const WaiverRequestModal = lazy(() => import("@/pages/WaiverRequestModal"));
// Phase 3 §2.26 (Rules sub-cluster) — RulesCatalogHub at /comply/rules
const RulesCatalogHub = lazy(() => import("@/pages/RulesCatalogHub"));
// Phase 3 §2.23 (Maturity sub-cluster) — MaturityHub at /comply/maturity
const MaturityHub = lazy(() => import("@/pages/MaturityHub"));
// Phase 3 §2.3 (Behavior sub-cluster) — BehaviorAnalyticsHub at /mission-control/behavior
const BehaviorAnalyticsHub = lazy(() => import("@/pages/BehaviorAnalyticsHub"));
// Phase 3 §2.23 (Privacy/Controls sub-cluster) — PrivacyComplianceHub at /comply/privacy
const PrivacyComplianceHub = lazy(() => import("@/pages/PrivacyComplianceHub"));
// P28 DPO persona — DPOPrivacyHub at /comply/dpo
const DPOPrivacyHub = lazy(() => import("@/pages/DPOPrivacyHub"));
// Phase 3 §2.20 (Exceptions sub-cluster) — ExceptionsHub at /remediate/exceptions
const ExceptionsHub = lazy(() => import("@/pages/ExceptionsHub"));
// Phase 3 §2.22 (Incident Extensions sub-cluster) — IncidentExtensionsHub at /remediate/incidents/extensions
const IncidentExtensionsHub = lazy(() => import("@/pages/IncidentExtensionsHub"));
// Phase 3 §2.23 (Compliance Coverage / Gap sub-cluster) — ComplianceCoverageHub at /comply/coverage
const ComplianceCoverageHub = lazy(() => import("@/pages/ComplianceCoverageHub"));
// Phase 3 Data Discovery / DSPM sub-cluster — DataDiscoveryHub at /discover/dspm (2026-05-02)
const DataDiscoveryHub = lazy(() => import("@/pages/DataDiscoveryHub"));
const ViolationLifecycleTimeline = lazy(() => import("@/pages/ViolationLifecycleTimeline"));

// P24 Board Member landing — Multica #4092
const BoardLandingPage = lazy(() => import("@/pages/BoardLandingPage"));

// Outbound Webhooks admin page — Multica #4155
const WebhooksOutboundPage = lazy(() => import("@/pages/admin/WebhooksOutboundPage"));

// DocsPage — Public documentation hub (Multica #4118)
const DocsPage = lazy(() => import("@/pages/DocsPage"));
// ApiReferencePage — API reference documentation (Multica #4161)
const ApiReferencePage = lazy(() => import("@/pages/ApiReferencePage"));
// ChangelogPage — Public changelog (Multica #4141)
const ChangelogPage = lazy(() => import("@/pages/ChangelogPage"));

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageSkeleton />}>
        <Routes>
          {/* Public routes */}
          {/* /login — eagerly imported, never suspends; listed first for priority */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/tour" element={<Tour />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/onboarding" element={<OnboardingWizard />} />
          <Route path="/onboard" element={<OnboardingPage />} />
          <Route path="/import" element={<ImportPage />} />
          <Route path="/landing" element={<LandingPage />} />
          {/* Marketing landing — public, no auth (Multica #4143) */}
          <Route path="/marketing" element={<MarketingLandingPage />} />
          <Route path="/home" element={<MarketingLandingPage />} />
          <Route path="/status" element={<StatusPage />} />
          {/* DocsPage — public legal, install, POC docs (Multica #4118) */}
          <Route path="/docs/tos" element={<DocsPage />} />
          <Route path="/docs/privacy" element={<DocsPage />} />
          <Route path="/docs/dpa" element={<DocsPage />} />
          <Route path="/docs/install" element={<DocsPage />} />
          <Route path="/docs/poc" element={<DocsPage />} />
          {/* ApiReferencePage — API reference documentation (Multica #4161) */}
          <Route path="/docs/api" element={<Suspense fallback={<PageSkeleton />}><ApiReferencePage /></Suspense>} />
          {/* ChangelogPage — public changelog (Multica #4141) */}
          <Route path="/changelog" element={<ChangelogPage />} />
          {/* Password reset — public, no auth required (Multica #4132) */}
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/reset-password/:token" element={<ResetPasswordPage />} />
          {/* Support — public, no auth required (Multica #4137) */}
          <Route path="/support" element={<SupportPage />} />

          {/* Protected workspace */}
          <Route element={<RequireAuth><WorkspaceLayout /></RequireAuth>}>
            {/* CISO / Executive landing — P01 board-level view (Multica #3986) */}
            <Route path="/executive" element={<CISODashboard />} />

            {/* P24 Board Member landing — Multica #4092 */}
            <Route path="/board" element={<BoardLandingPage />} />

            {/* Space 1: Mission Control — Phase 3 P0 Wave 3: root → CommandHero, legacy → redirects */}
            <Route path="/mission-control" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control/ciso" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control/executive" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control/sla" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/mission-control/live-feed" element={<LiveFeed />} />
            <Route path="/mission-control/risk" element={<RiskOverview />} />
            <Route path="/mission-control/soc" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/mission-control/soc-t1" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/mission-control/compliance" element={<Navigate to="/compliance" replace />} />
            {/* DoD #5 — CTEM Cycles surface lives in mission-control compliance variant */}
            <Route path="/mission-control/ctem" element={<MissionControlComplianceDashboard />} />
            <Route path="/mission-control/dev-security" element={<Navigate to="/?view=dev" replace />} />
            <Route path="/mission-control/threat-intel" element={<ThreatIntelDashboard />} />
            <Route path="/mission-control/risk-register" element={<Navigate to="/compliance?tab=sla-risk" replace />} />

            {/* Space 2: Discover */}
            <Route path="/discover" element={<FindingExplorer />} />
            <Route path="/discover/code" element={<CodeScanning />} />
            {/* Phase 3 fold 2026-05-02 — Secrets Hub (S10 Code Intel — Secrets sub-cluster) */}
            <Route path="/discover/secrets-hub" element={<SecretsHub />} />
            <Route path="/discover/secrets" element={<Navigate to="/discover/secrets-hub?tab=detection" replace />} />
            <Route path="/discover/iac" element={<IaCScanning />} />
            <Route path="/discover/cloud" element={<CloudPosture />} />
            <Route path="/discover/containers" element={<ContainerSecurity />} />
            <Route path="/discover/sbom" element={<SBOMInventory />} />
            {/* /discover/graph → consolidated into /assets hero (see redirect block below) */}
            <Route path="/discover/attack-paths" element={<AttackPaths />} />
            <Route path="/discover/threats" element={<ThreatFeeds />} />
            <Route path="/discover/correlation" element={<CorrelationEngine />} />
            <Route path="/discover/data-fabric" element={<DataFabric />} />
            {/* P29 Software Architect — ArchitectWorkspaceHub (threat models, code-to-runtime, API deps, arch graph) */}
            <Route path="/discover/architect" element={<ArchitectWorkspaceHub />} />
            {/* Wave 1 — Discover */}
            <Route path="/discover/code-semantic" element={<CodeSemanticExplorer />} />
            <Route path="/discover/callgraph" element={<CallGraphExplorer />} />
            {/* /discover/graph-perf, /discover/arch-layers → consolidated into /assets hero */}
            <Route path="/discover/pii-inventory" element={<PIIFieldInventory />} />
            <Route path="/discover/component-identity" element={<ComponentIdentityView />} />

            {/* Space 3: Validate — admin + security_analyst only (except Reachability) */}
            <Route path="/validate/reachability" element={<Reachability />} />
            {/* Wave 1 — Validate */}
            <Route path="/validate/reachability-proof" element={<ReachabilityProof />} />

            <Route path="/remediate/autofix" element={<Navigate to="/remediate?tab=suggested" replace />} />
            <Route path="/remediate/collaborate" element={<Collaboration />} />
            <Route path="/remediate/workflows" element={<Navigate to="/remediate?tab=workflows" replace />} />
            <Route path="/remediate/cases" element={<ExposureCases />} />
            <Route path="/remediate/tickets" element={<TicketIntegration />} />
            <Route path="/remediate/center" element={<Navigate to="/remediate?tab=center" replace />} />
            <Route path="/remediate/waivers" element={<Navigate to="/remediate?tab=waivers" replace />} />

            {/* Space 5: Comply */}
            {/* /comply, /comply/evidence, /comply/bundles → consolidated into /compliance hero */}
            <Route path="/comply/soc2" element={<SOC2Evidence />} />
            <Route path="/comply/slsa" element={<SLSAProvenance />} />
            {/* /comply/audit → consolidated into /compliance hero */}
            <Route path="/comply/reports" element={<Reports />} />
            <Route path="/comply/analytics" element={<Analytics />} />
            <Route path="/comply/export" element={<EvidenceExportCenter />} />
            <Route path="/comply/auditor" element={<AuditorEvidenceHub />} />

            {/* Settings */}
            <Route path="/settings/integrations" element={<Integrations />} />
            <Route path="/settings/marketplace" element={<Marketplace />} />
            <Route path="/settings/health" element={<Navigate to="/admin?tab=system" replace />} />
            <Route path="/settings/logs" element={<LogViewer />} />

            {/* AI Security Advisor */}
            <Route path="/ai-advisor" element={<AISecurityAdvisor />} />
            <Route path="/ai-advisor-dashboard" element={<AISecurityAdvisorDashboard />} />

            {/* Scheduled Reports */}
            <Route path="/scheduled-reports" element={<ScheduledReportsDashboard />} />

            {/* AI Copilot & AI Engine */}
            <Route path="/ai" element={<CopilotDashboard />} />
            {/* /ai/* → Brain hero (Phase 3 P0 consolidation, 90-day redirects) */}
            <Route path="/ai/brain" element={<Navigate to="/brain?tab=pipeline" replace />} />
            <Route path="/ai/consensus" element={<Navigate to="/brain?tab=consensus" replace />} />
            <Route path="/ai/algorithms" element={<Navigate to="/brain?tab=lab" replace />} />
            <Route path="/ai/ml" element={<Navigate to="/brain?tab=ml" replace />} />
            <Route path="/ai/predictions" element={<Navigate to="/brain?tab=predictions" replace />} />
            {/* P2 Wave: MPTE / Verification / FAIL Chaos → Brain hero (S13/S16/S17) */}
            <Route path="/verification" element={<Navigate to="/brain?tab=mpte" replace />} />
            <Route path="/brain/mpte" element={<Navigate to="/brain?tab=mpte" replace />} />
            <Route path="/brain/fail" element={<Navigate to="/brain?tab=fail" replace />} />
            <Route path="/attack/mpte" element={<Navigate to="/brain?tab=mpte" replace />} />
            {/* P2 Wave: MCP Gateway + System Health → Admin hero (S28/S30) */}
            <Route path="/connect/mcp" element={<Navigate to="/admin?tab=mcp" replace />} />
            <Route path="/ai/mcp-registry" element={<Navigate to="/admin?tab=mcp" replace />} />
            <Route path="/skills" element={<Navigate to="/admin?tab=mcp" replace />} />
            <Route path="/openclaw" element={<Navigate to="/admin?tab=mcp" replace />} />
            <Route path="/airgap" element={<Navigate to="/admin?tab=mcp" replace />} />
            <Route path="/admin/system" element={<Navigate to="/admin?tab=system-health" replace />} />
            <Route path="/system-health" element={<Navigate to="/admin?tab=system-health" replace />} />
            <Route path="/capacity-planning" element={<Navigate to="/admin?tab=system-health" replace />} />
            <Route path="/fips-status" element={<Navigate to="/admin?tab=system-health" replace />} />
            <Route path="/local-store-status" element={<Navigate to="/admin?tab=system-health" replace />} />
            <Route path="/comply/waivers" element={<Navigate to="/compliance?tab=waivers" replace />} />
            <Route path="/comply/policies" element={<Navigate to="/compliance?tab=policies" replace />} />
            <Route path="/remediate/waivers" element={<Navigate to="/compliance?tab=waivers" replace />} />
            <Route path="/policy-library" element={<Navigate to="/compliance?tab=policies" replace />} />
            <Route path="/policy-stage-matrix" element={<Navigate to="/compliance?tab=policies" replace />} />
            <Route path="/rules-catalog" element={<Navigate to="/compliance?tab=policies" replace />} />
            <Route path="/auto-waiver-rules" element={<Navigate to="/compliance?tab=waivers" replace />} />
            {/* Wave 1 — AI */}
            {/* AICopilotAgentsHub fold (Phase 3 §2.18, 2026-05-02) — canonical hub + 3 redirects */}
            <Route path="/ai/agents" element={<AICopilotAgentsHub />} />
            <Route path="/ai/shadow-inventory" element={<Navigate to="/ai/agents?tab=shadow" replace />} />
            <Route path="/ai/attack-paths" element={<AIAttackPathView />} />
            <Route path="/ai/mcp-registry" element={<MCPToolRegistry />} />
            <Route path="/ai/agents-console" element={<Navigate to="/ai/agents?tab=console" replace />} />
            <Route path="/ai/agent-tasks" element={<Navigate to="/ai/agents?tab=tasks" replace />} />
            <Route path="/ai/copilot" element={<Copilot />} />
            <Route path="/ai/copilot-chat" element={<CopilotGraphChat />} />
            <Route path="/ai/copilot-trace" element={<TraversalExplanationPanel />} />

            {/* Findings Explorer — universal, all personas */}
            <Route path="/findings" element={<FindingsExplorer />} />

            {/* Attack Surface */}
            <Route path="/attack-surface" element={<AttackSurface />} />

            {/* Integration Health */}
            <Route path="/integrations" element={<IntegrationHealth />} />

            {/* Threat Hunting — Phase 3 fold (2026-05-02): unified HuntingHub */}
            <Route path="/mission-control/hunt" element={<HuntingHub />} />
            <Route path="/hunting" element={<ThreatHunting />} />
            <Route path="/threat-hunting" element={<Navigate to="/mission-control/hunt?tab=sessions" replace />} />

            {/* Developer Security Hub (P20 + P11) — 4-tab hub 2026-05-05 */}
            <Route path="/developer" element={<DeveloperSecurityHub />} />
            {/* Legacy DeveloperPortal still reachable as /developer-portal */}
            <Route path="/developer-portal" element={<DeveloperPortal />} />
            <Route path="/api-explorer" element={<APIExplorer />} />

            {/* Vendor Management */}
            <Route path="/vendors" element={<VendorManagement />} />

            {/* Incident Response */}
            <Route path="/incidents" element={<IncidentResponse />} />

            {/* Risk Acceptance */}
            <Route path="/risk-acceptance" element={<RiskAcceptance />} />

            {/* SBOM Management */}
            <Route path="/sbom" element={<SBOMManagement />} />

            {/* Compliance Dashboard — P07 standalone */}
            {/* /compliance → consolidated into hero (see Phase 3 P0 block) */}

            {/* DLP & API Abuse Detection */}
            <Route path="/dlp" element={<DLPDashboard />} />
            <Route path="/api-abuse" element={<Navigate to="/asset-graph?tab=api-abuse" replace />} />

            {/* Crypto Key, Certificate, Privilege Escalation, Security Automation */}
            {/* S11 Crypto sub-cluster — folded 2026-05-02 into CryptoTrustHub */}
            <Route path="/discover/crypto" element={<CryptoTrustHub />} />
            <Route path="/crypto-keys" element={<Navigate to="/discover/crypto?tab=keys" replace />} />
            <Route path="/certificates" element={<Navigate to="/discover/crypto?tab=certs" replace />} />
            {/* /privilege-escalation → FindingsExplorerView (Pattern-2 2026-04-27) */}
            <Route path="/security-automation" element={<SecurityAutomationDashboard />} />

            {/* Secret Scanner, Threat Intel Platform, Attack Surface Dashboard */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/dast" element={<DASTDashboard />} />
            <Route path="/ir-playbook" element={<IRPlaybookDashboard />} />
            <Route path="/container-registry" element={<ContainerRegistryDashboard />} />
            <Route path="/discover/network" element={<NetworkMonitoringHub />} />
            <Route path="/network-monitoring" element={<Navigate to="/discover/network?tab=monitoring" replace />} />
            <Route path="/sca" element={<SCADashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/threat-intel-platform" element={<ThreatIntelPlatformDashboard />} />
            <Route path="/attack-surface-dashboard" element={<Navigate to="/assets?tab=attack-surface" replace />} />

            {/* New standalone pages */}
            <Route path="/threat-intel" element={<ThreatIntelDashboardPage />} />
            {/* /assets standalone -> consolidated into /assets hero (AssetGraph) Inventory tab */}
            <Route path="/assets/inventory" element={<Navigate to="/assets?tab=inventory" replace />} />
            {/* S2.10 Vuln Lifecycle Pipeline hub — folded 2026-05-02 (combined 4-page pair) */}
            <Route path="/discover/vuln-pipeline" element={<VulnLifecyclePipelineHub />} />
            <Route path="/vuln-age" element={<Navigate to="/discover/vuln-pipeline?tab=age" replace />} />
            <Route path="/vuln-lifecycle" element={<Navigate to="/discover/vuln-pipeline?tab=lifecycle" replace />} />
            {/* S3 Behavior hub — folded 2026-05-02 (FOLDED InsiderThreatMonitor) */}
            <Route path="/mission-control/behavior" element={<BehaviorAnalyticsHub />} />
            <Route path="/insider-threats" element={<Navigate to="/mission-control/behavior?tab=insider" replace />} />
            <Route path="/security-kpis" element={<SecurityKPIDashboard />} />
            <Route path="/posture-advisor" element={<PostureAdvisor />} />
            {/* Phase 3 fold 2026-05-02 — Automation & Orchestration Hub (S19 Patch+SOAR sub-cluster) */}
            <Route path="/remediate/automation" element={<AutomationOrchestrationHub />} />
            <Route path="/patch-prioritizer" element={<Navigate to="/remediate/automation?tab=prioritize" replace />} />
            <Route path="/vendor-risk" element={<VendorRiskDashboard />} />
            {/* Phase 3 fold 2026-05-02 — Vuln Intelligence Hub (S7 sub-cluster) */}
            <Route path="/discover/vuln-intel" element={<VulnIntelHub />} />
            <Route path="/cve-search" element={<Navigate to="/discover/vuln-intel?tab=cve-search" replace />} />
            <Route path="/ip-reputation" element={<Navigate to="/discover/vuln-intel?tab=ip-rep" replace />} />
            <Route path="/threat-geolocation" element={<Navigate to="/discover/vuln-intel?tab=geolocation" replace />} />
            <Route path="/secrets-rotation" element={<Navigate to="/discover/secrets-hub?tab=rotation" replace />} />
            <Route path="/secret-scanner" element={<Navigate to="/discover/secrets-hub?tab=scanner" replace />} />
            <Route path="/security-awareness" element={<SecurityAwareness />} />
            {/* Phase 3 fold 2026-05-02 — Supply Chain Hub (S4/S10 sub-cluster) */}
            <Route path="/discover/supply-chain" element={<SupplyChainHub />} />
            <Route path="/supply-chain" element={<Navigate to="/discover/supply-chain?tab=security" replace />} />
            <Route path="/zero-trust" element={<Navigate to="/asset-graph?tab=zero-trust" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/attack-paths" element={<AttackPathAnalysis />} />
            <Route path="/incident-timeline" element={<IncidentTimeline />} />
            <Route path="/discover/identity-governance" element={<IdentityGovernanceHub />} />
            <Route path="/identity-governance" element={<Navigate to="/discover/identity-governance?tab=governance" replace />} />
            <Route path="/executive-report" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/network-analysis" element={<NetworkAnalysis />} />
            <Route path="/vuln-heatmap" element={<VulnHeatmap />} />
            <Route path="/audit-log" element={<AuditLog />} />
            <Route path="/admin/audit-log" element={<AdminAuditLogPage />} />
            <Route path="/admin/users" element={<AdminUsersPage />} />
            <Route path="/admin/api-keys" element={<RequireRole roles={["admin"]}><AdminApiKeysPage /></RequireRole>} />
            {/* Outbound Webhooks — Multica #4155 */}
            <Route path="/admin/webhooks-out" element={<WebhooksOutboundPage />} />
            <Route path="/cspm" element={<Navigate to="/compliance?tab=cspm" replace />} />
            {/* S13 MPTE Offensive Validation hub — folded 2026-05-02 (FOLDED PentestManagement) */}
            <Route path="/pentest" element={<Navigate to="/validate/offensive?tab=pentest" replace />} />
            <Route path="/brain/fail/deception" element={<DeceptionHub />} />
            <Route path="/deception" element={<Navigate to="/brain/fail/deception?tab=engine" replace />} />
            <Route path="/threat-deception" element={<Navigate to="/brain/fail/deception?tab=decoys" replace />} />
            <Route path="/cert-manager" element={<Navigate to="/discover/crypto?tab=manager" replace />} />
            <Route path="/discover/network-segmentation" element={<NetworkSegmentationHub />} />
            <Route path="/firewall" element={<Navigate to="/discover/network-segmentation?tab=firewall" replace />} />
            <Route path="/microsegmentation" element={<Navigate to="/discover/network-segmentation?tab=microseg" replace />} />
            <Route path="/risk-register" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/bug-bounty" element={<Navigate to="/brain?tab=bug-bounty" replace />} />
            <Route path="/mitre" element={<Navigate to="/brain?tab=mitre" replace />} />
            <Route path="/cloud-iam" element={<CloudIAM />} />
            {/* S11 Email & Threat Protection hub — folded 2026-05-02 (FOLDED EmailSecurity, PhishingSimulation, RansomwareProtectionDashboard) */}
            <Route path="/discover/threat-protection" element={<EmailThreatProtectionHub />} />
            <Route path="/email-security" element={<Navigate to="/discover/threat-protection?tab=email" replace />} />
            <Route path="/sla-dashboard" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/security-metrics" element={<SecurityMetricsDashboard />} />
            <Route path="/vuln-risk" element={<VulnRiskQueue />} />
            {/* S13 MPTE Offensive Validation hub — folded 2026-05-02 (FOLDED RedTeamStatus) */}
            <Route path="/red-team" element={<Navigate to="/validate/offensive?tab=red-team" replace />} />
            <Route path="/network-topology" element={<NetworkTopology />} />
            {/* S14 Threat Actors hub — folded 2026-05-02 (FOLDED IOCHunter) */}
            <Route path="/ioc-hunter" element={<Navigate to="/attack/intel/actors?tab=ioc-hunter" replace />} />
            {/* S13 MPTE Offensive Validation hub — folded 2026-05-02 (FOLDED SocialEngineering) */}
            <Route path="/social-engineering" element={<Navigate to="/validate/offensive?tab=social-eng" replace />} />
            <Route path="/mobile-security" element={<MobileSecurity />} />
            <Route path="/password-policy" element={<PasswordPolicy />} />
            {/* S10 Application Security hub — Phase 3 cluster (2026-05-02) */}
            <Route path="/discover/app-security" element={<AppLayerSecurityHub />} />
            <Route path="/app-security" element={<Navigate to="/discover/app-security?tab=web" replace />} />
            <Route path="/soar" element={<Navigate to="/remediate/automation?tab=soar" replace />} />
            <Route path="/grc" element={<GRCDashboard />} />
            <Route path="/discover/api-security" element={<APISecurityHub />} />
            <Route path="/api-security" element={<Navigate to="/discover/api-security?tab=inventory" replace />} />
            <Route path="/threat-correlation" element={<ThreatCorrelation />} />
            <Route path="/supply-chain-risk" element={<Navigate to="/discover/supply-chain?tab=risk" replace />} />
            <Route path="/cloud-security" element={<Navigate to="/discover/cloud-posture?tab=posture" replace />} />
            <Route path="/discover/cloud-posture" element={<CloudPostureUnifiedHub />} />
            <Route path="/breach-response" element={<Navigate to="/remediate/incidents/extensions?tab=breach" replace />} />
            <Route path="/soc" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/watchlist" element={<Navigate to="/attack/intel/ops?tab=watchlist" replace />} />
            {/* Canonical hub route — Threat Intel Operations (combined 4-page fold) */}
            <Route path="/attack/intel/ops" element={<ThreatIntelOpsHub />} />
            <Route path="/uba" element={<Navigate to="/mission-control/behavior?tab=uba" replace />} />
            <Route path="/cmdb" element={<Navigate to="/discover/assets/inventory?tab=cmdb" replace />} />
            <Route path="/incident-response" element={<Navigate to="/?view=soc" replace />} />
            {/* S11 Email & Threat Protection hub — folded 2026-05-02 (FOLDED PhishingSimulation) */}
            <Route path="/phishing" element={<Navigate to="/discover/threat-protection?tab=phishing" replace />} />
            <Route path="/api-sec" element={<APISecurityPage />} />
            {/* Phase 3 DSPM hub — Data Discovery / Classification / Exfiltration sub-cluster (2026-05-02): 3 pages folded */}
            <Route path="/discover/dspm" element={<DataDiscoveryHub />} />
            <Route path="/data-classification" element={<Navigate to="/discover/dspm?tab=classification" replace />} />
            {/* S29 Training & Culture hub — Phase 3 cluster (2026-05-02): 3 pages folded */}
            <Route path="/admin/training-culture" element={<TrainingCultureHub />} />
            <Route path="/security-training" element={<Navigate to="/admin/training-culture?tab=training" replace />} />
            {/* Phase 3 — Privileged Access hub canonical route */}
            <Route path="/discover/privileged-access" element={<PrivilegedAccessHub />} />
            <Route path="/pam" element={<Navigate to="/discover/privileged-access?tab=pam" replace />} />
            {/* S2 Finance hub — folded 2026-05-02. Old route redirects below. */}
            <Route path="/cyber-insurance" element={<Navigate to="/mission-control/finance?tab=cyber-insur" replace />} />
            <Route path="/cyber-insurance-legacy" element={<CyberInsurance />} />
            <Route path="/executive-reporting" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/vuln-scanner" element={<VulnerabilityScanner />} />
            <Route path="/risk-quantification" element={<Navigate to="/comply/risk-quant?tab=fair" replace />} />
            {/* Canonical Risk Quant hub route */}
            <Route path="/comply/risk-quant" element={<RiskQuantHub />} />
            <Route path="/vuln-scanner-mgmt" element={<VulnerabilityScannerPage />} />
            {/* Phase 3 Strategic Posture hub — Comply space (2026-05-02): 3 pages folded */}
            <Route path="/comply/strategic-posture" element={<StrategicPostureHub />} />
            <Route path="/security-posture" element={<Navigate to="/comply/strategic-posture?tab=posture" replace />} />
            <Route path="/executive-briefing" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/threat-feeds" element={<Navigate to="/issues?tab=threat-feed" replace />} />
            <Route path="/cwpp" element={<Navigate to="/discover/cloud-posture?tab=platform" replace />} />
            {/* S22 fold 2026-05-02: /digital-forensics → ForensicsHub#digital (canonical mounted later) */}
            <Route path="/grc-assessment" element={<Navigate to="/comply/strategic-posture?tab=grc" replace />} />
            <Route path="/data-governance" element={<DataGovernanceDashboard />} />
            <Route path="/security-roadmap" element={<Navigate to="/comply/strategic-posture?tab=roadmap" replace />} />
            <Route path="/threat-hunting-dashboard" element={<ThreatHuntingDashboard />} />
            <Route path="/compliance-scanner" element={<ComplianceScannerDashboard />} />
            <Route path="/asset-risk" element={<Navigate to="/discover/assets/inventory?tab=risk" replace />} />
            <Route path="/security-health" element={<SecurityHealthDashboard />} />
            <Route path="/cross-domain-analytics" element={<CrossDomainAnalytics />} />
            <Route path="/devsecops" element={<DevSecOpsDashboard />} />
            <Route path="/vuln-trends" element={<VulnTrendDashboard />} />
            <Route path="/config-benchmark" element={<ConfigBenchmarkDashboard />} />
            <Route path="/incident-timeline-dashboard" element={<Navigate to="/brain?tab=incident-timeline" replace />} />
            <Route path="/security-metrics-live" element={<SecurityMetricsDashboard2 />} />
            <Route path="/zero-trust-policies" element={<ZeroTrustPolicyDashboard />} />
            {/* S12 Threat Modeling hub — Phase 3 cluster (2026-05-02) */}
            <Route path="/attack/threat-modeling" element={<ThreatModelingHub />} />
            <Route path="/threat-models" element={<Navigate to="/attack/threat-modeling?tab=models" replace />} />
            <Route path="/threat-modeling-pipeline" element={<Navigate to="/attack/threat-modeling?tab=pipeline" replace />} />
            {/* Phase 3 §2.20 — Exceptions sub-cluster folded into ExceptionsHub at /remediate/exceptions */}
            <Route path="/remediate/exceptions" element={<ExceptionsHub />} />
            <Route path="/security-exceptions" element={<Navigate to="/remediate/exceptions?tab=exceptions" replace />} />
            <Route path="/regulatory-tracker" element={<RegulatoryTrackerDashboard />} />
            <Route path="/security-scorecard" element={<Navigate to="/compliance?tab=scorecard" replace />} />
            <Route path="/ccm" element={<CCMDashboard />} />
            <Route path="/system-health" element={<SystemHealthDashboard />} />

            {/* OpenClaw + SOC Triage AI + SBOM */}
            <Route path="/soc-triage" element={<Navigate to="/?view=soc" replace />} />

            {/* NDR / XDR / Awareness / EDR */}
            <Route path="/ndr" element={<NDRDashboard />} />
            {/* Phase 3 UX consolidation — Detect & Respond hub (folds 3 pages, 2026-05-02) */}
            <Route path="/discover/detect-respond" element={<DetectAndRespondHub />} />
            <Route path="/xdr" element={<Navigate to="/discover/detect-respond?tab=xdr" replace />} />
            {/* Awareness hub — folded 2026-05-02. Canonical route + 4 redirects. */}
            <Route path="/comply/awareness" element={<AwarenessHub />} />
            <Route path="/awareness-score" element={<Navigate to="/comply/awareness?tab=score" replace />} />
            <Route path="/edr" element={<Navigate to="/discover/detect-respond?tab=edr" replace />} />

            {/* Identity Analytics, CNAPP, Pentest Mgmt, Supply Chain Intel */}
            <Route path="/identity-analytics" element={<Navigate to="/discover/identity-governance?tab=analytics" replace />} />
            <Route path="/cnapp" element={<Navigate to="/discover/cloud-posture?tab=unified" replace />} />
            <Route path="/pentest-mgmt" element={<Navigate to="/validate/offensive?tab=pentest" replace />} />
            <Route path="/supply-chain-intel" element={<Navigate to="/discover/supply-chain?tab=intel" replace />} />

            {/* Threat Actor Intelligence + Security Champions */}
            {/* S14 Threat Actors hub — folded 2026-05-02 (FOLDED ThreatActorDashboard) */}
            <Route path="/attack/intel/actors" element={<ThreatActorsHub />} />

            {/* S13 MPTE Offensive Validation hub — folded 2026-05-02 (canonical) */}
            <Route path="/validate/offensive" element={<OffensiveValidationHub />} />
            <Route path="/threat-actors" element={<Navigate to="/attack/intel/actors?tab=actors" replace />} />
            <Route path="/security-champions" element={<Navigate to="/developer?tab=champion" replace />} />

            {/* Phase 3 §2.23 — Maturity sub-cluster folded into MaturityHub at /comply/maturity */}
            <Route path="/comply/maturity" element={<MaturityHub />} />
            {/* Phase 3 §2.23 — Privacy/Controls sub-cluster folded into PrivacyComplianceHub at /comply/privacy */}
            <Route path="/comply/privacy" element={<PrivacyComplianceHub />} />
            {/* P28 DPO persona — DPO Privacy Center */}
            <Route path="/comply/dpo" element={<DPOPrivacyHub />} />
            {/* Security Maturity, Privacy/GDPR, Network Traffic, Container Security */}
            <Route path="/security-maturity" element={<Navigate to="/comply/maturity?tab=security" replace />} />
            <Route path="/posture-maturity" element={<Navigate to="/comply/maturity?tab=posture" replace />} />
            <Route path="/privacy-gdpr" element={<Navigate to="/comply/privacy?tab=gdpr" replace />} />
            <Route path="/network-traffic" element={<NetworkTrafficDashboard />} />
            {/* Phase 3 UX consolidation — Container Security hub (folds 3 pages, 2026-05-02) */}
            <Route path="/discover/container-security" element={<ContainerSecurityHub />} />
            <Route path="/container-security" element={<Navigate to="/discover/container-security?tab=image" replace />} />

            {/* Cloud Compliance + Endpoint Compliance */}
            {/* Phase 3 §2.23 ComplianceCoverageHub fold — canonical hub + legacy redirects */}
            <Route path="/comply/coverage" element={<ComplianceCoverageHub />} />
            <Route path="/cloud-compliance" element={<Navigate to="/comply/coverage?tab=cloud" replace />} />
            <Route path="/endpoint-compliance" element={<Navigate to="/comply/coverage?tab=endpoint" replace />} />

            {/* API Security Management + Vuln Intelligence */}
            <Route path="/api-security-mgmt" element={<Navigate to="/discover/api-security?tab=management" replace />} />
            <Route path="/vuln-intelligence" element={<Navigate to="/discover/vuln-intel?tab=vuln-intel" replace />} />

            {/* Firewall Policy, Network Segmentation */}
            <Route path="/firewall-policy" element={<Navigate to="/discover/network-segmentation?tab=policy" replace />} />
            <Route path="/network-segmentation" element={<NetworkSegmentationDashboard />} />

            {/* MFA Management, Threat Scores, Security Budget, Compliance Gaps */}
            <Route path="/mfa-management" element={<Navigate to="/discover/privileged-access?tab=mfa" replace />} />
            <Route path="/attack/intel/external" element={<ExternalThreatIntelHub />} />
            <Route path="/threat-scores" element={<Navigate to="/attack/intel/external?tab=scores" replace />} />
            {/* S2 Finance hub — folded 2026-05-02 */}
            <Route path="/security-budget" element={<Navigate to="/mission-control/finance?tab=budget" replace />} />
            <Route path="/compliance-gaps" element={<Navigate to="/comply/coverage?tab=gaps" replace />} />

            {/* Wave 18 domain dashboards */}
            <Route path="/ai-governance" element={<Navigate to="/brain?tab=ai-governance" replace />} />
            <Route path="/digital-identity" element={<Navigate to="/discover/identity-governance?tab=digital" replace />} />
            <Route path="/attack-chains" element={<Navigate to="/brain?tab=attack-chain" replace />} />
            <Route path="/threat-exposure" element={<ThreatExposureDashboard />} />
            <Route path="/license-security" element={<SoftwareLicenseDashboard />} />
            <Route path="/cloud-identity" element={<CloudIdentityDashboard />} />

            {/* Wave 19 domain dashboards */}
            <Route path="/dark-web" element={<Navigate to="/attack/intel/external?tab=darkweb" replace />} />
            <Route path="/itdr" element={<Navigate to="/discover/detect-respond?tab=itdr" replace />} />
            <Route path="/container-runtime" element={<Navigate to="/discover/container-security?tab=runtime" replace />} />
            <Route path="/api-discovery" element={<Navigate to="/discover/api-security?tab=discovery" replace />} />
            <Route path="/security-chaos" element={<SecurityChaosDashboard />} />
            <Route path="/remediate/incidents/knowledge" element={<IncidentKnowledgeHub />} />
            <Route path="/incident-metrics" element={<Navigate to="/remediate/incidents/knowledge?tab=metrics" replace />} />

            {/* Wave 20 domain dashboards */}
            <Route path="/zero-day" element={<Navigate to="/attack/intel/external?tab=zeroday" replace />} />
            <Route path="/security-tabletop" element={<SecurityTabletopDashboard />} />
            <Route path="/browser-security" element={<Navigate to="/discover/app-security?tab=browser" replace />} />
            <Route path="/data-exfiltration" element={<Navigate to="/discover/dspm?tab=exfiltration" replace />} />
            <Route path="/pki-management" element={<Navigate to="/discover/crypto?tab=pki" replace />} />
            <Route path="/tool-inventory" element={<Navigate to="/assets?tab=tool-inventory" replace />} />

            {/* Wave 21 domain dashboards */}
            <Route path="/firmware-security" element={<FirmwareSecurityDashboard />} />
            <Route path="/iot-security" element={<Navigate to="/assets?tab=iot-security" replace />} />
            <Route path="/mobile-app-security" element={<Navigate to="/discover/app-security?tab=mobile" replace />} />
            <Route path="/supply-chain-attacks" element={<SupplyChainAttackDashboard />} />
            <Route path="/cwp" element={<Navigate to="/discover/cloud-posture?tab=workloads" replace />} />

            {/* Wave 22 domain dashboards */}
            <Route path="/autonomous-remediation" element={<Navigate to="/remediate?tab=autonomous-remediation" replace />} />
            <Route path="/vuln-correlation" element={<VulnerabilityCorrelationDashboard />} />
            {/* Phase 3 §2.11 fold 2026-05-02 — PostureMetricsHub at /discover/posture-metrics (Posture Metrics sub-cluster) */}
            <Route path="/discover/posture-metrics" element={<PostureMetricsHub />} />
            <Route path="/posture-benchmarking" element={<Navigate to="/discover/posture-metrics?tab=benchmarking" replace />} />
            <Route path="/quantum-crypto" element={<Navigate to="/discover/crypto?tab=quantum" replace />} />
            <Route path="/ai-soc" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/deception-analytics" element={<Navigate to="/brain/fail/deception?tab=analytics" replace />} />

            {/* Wave 23 domain dashboards */}
            <Route path="/threat-intel-automation" element={<ThreatIntelAutomation />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/endpoint-hunting" element={<EndpointHuntingDashboard />} />
            <Route path="/cloud-security-analytics" element={<CloudSecurityAnalyticsDashboard />} />
            <Route path="/identity-risk" element={<IdentityRiskDashboard />} />
            <Route path="/ot-security" element={<OTSecurityDashboard />} />

            {/* Wave 24 domain dashboards */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/application-risk" element={<Navigate to="/assets?tab=app-risk" replace />} />
            <Route path="/pag" element={<PAGDashboard />} />
            <Route path="/security-gamification" element={<SecurityGamificationDashboard />} />
            <Route path="/vuln-prioritization" element={<Navigate to="/discover/vuln-pipeline?tab=prioritize" replace />} />

            {/* Wave 25 domain dashboards */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/posture-scoring" element={<Navigate to="/discover/posture-metrics?tab=scoring" replace />} />
            <Route path="/cloud-posture" element={<Navigate to="/compliance?tab=cloud-posture-dash" replace />} />
            <Route path="/api-threat-protection" element={<APIThreatProtectionDashboard />} />
            <Route path="/risk-register-engine" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/change-management" element={<ChangeManagementDashboard />} />

            {/* Wave 26 domain dashboards */}
            <Route path="/compliance-automation" element={<ComplianceAutomationDashboard />} />
            {/* S14 Threat Actors hub — folded 2026-05-02 (FOLDED ThreatAttributionDashboard) */}
            <Route path="/threat-attribution" element={<Navigate to="/attack/intel/actors?tab=attribution" replace />} />
            <Route path="/cloud-access-security" element={<CloudAccessSecurityDashboard />} />
            <Route path="/behavioral-analytics" element={<Navigate to="/mission-control/behavior?tab=behavioral" replace />} />
            <Route path="/vuln-workflow" element={<Navigate to="/discover/vuln-pipeline?tab=workflow" replace />} />
            <Route path="/data-pipeline" element={<DataPipelineDashboard />} />

            {/* Wave 27 domain dashboards */}
            <Route path="/alert-triage" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/awareness-metrics" element={<Navigate to="/comply/awareness?tab=metrics" replace />} />
            <Route path="/patch-management" element={<Navigate to="/remediate/automation?tab=patch" replace />} />
            <Route path="/container-posture" element={<Navigate to="/discover/container-security?tab=posture" replace />} />
            <Route path="/cyber-threat-intel" element={<CyberThreatIntelDashboard />} />
            <Route path="/digital-twin" element={<DigitalTwinDashboard />} />

            {/* Wave 28 domain dashboards */}
            <Route path="/access-requests" element={<AccessRequestManagementDashboard />} />
            <Route path="/session-recording" element={<Navigate to="/discover/privileged-access?tab=sessions" replace />} />
            <Route path="/cloud-inventory" element={<Navigate to="/discover/assets/inventory?tab=cloud-res" replace />} />
            <Route path="/security-telemetry" element={<SecurityTelemetryDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/third-party-vendor" element={<ThirdPartyVendorDashboard />} />

            {/* Wave 29 domain dashboards */}
            <Route path="/api-inventory" element={<Navigate to="/asset-graph?tab=api-inventory" replace />} />
            <Route path="/threat-vectors" element={<ThreatVectorDashboard />} />
            <Route path="/awareness-campaigns" element={<Navigate to="/comply/awareness?tab=campaigns" replace />} />
            <Route path="/risk-treatment" element={<RiskTreatmentDashboard />} />
            <Route path="/data-discovery" element={<Navigate to="/discover/dspm?tab=discovery" replace />} />

            {/* Wave 30 domain dashboards */}
            <Route path="/compliance-mapping" element={<ComplianceMappingDashboard />} />
            <Route path="/vuln-scans" element={<VulnScanDashboard />} />
            <Route path="/threat-briefs" element={<Navigate to="/attack/intel/ops?tab=briefs" replace />} />
            <Route path="/incident-comms" element={<Navigate to="/remediate/incidents/extensions?tab=comms" replace />} />
            <Route path="/asset-tags" element={<Navigate to="/discover/assets/inventory?tab=tags" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}

            {/* Security Graph — Wiz-killer interactive relationship canvas */}
            {/* /security-graph → consolidated into /assets hero */}

            {/* Wave 42 domain dashboards (pages for Wave 41 engines) */}
            <Route path="/privacy-impact" element={<Navigate to="/comply/privacy?tab=impact" replace />} />
            {/* S14 Threat Actors hub — folded 2026-05-02 (FOLDED ThreatIndicatorDashboard) */}
            <Route path="/threat-indicators" element={<Navigate to="/attack/intel/actors?tab=indicators" replace />} />
            {/* S11 Email & Threat Protection hub — folded 2026-05-02 (FOLDED RansomwareProtectionDashboard) */}
            <Route path="/ransomware-protection" element={<Navigate to="/discover/threat-protection?tab=ransomware" replace />} />
            <Route path="/access-anomaly" element={<Navigate to="/asset-graph?tab=access-anomaly" replace />} />
            <Route path="/training-effectiveness" element={<Navigate to="/admin/training-culture?tab=effectiveness" replace />} />
            <Route path="/cost-optimization" element={<CloudCostOptimizationDashboard />} />
            <Route path="/competitive-comparison" element={<CompetitiveComparisonPage />} />

            {/* Wave 41 domain dashboards (pages for Wave 40 engines) */}
            <Route path="/arch-review" element={<ArchReviewDashboard />} />
            <Route path="/hunting-playbooks" element={<Navigate to="/mission-control/hunt?tab=playbooks" replace />} />
            <Route path="/program-maturity" element={<Navigate to="/comply/maturity?tab=program" replace />} />
            {/* Phase 3 §2.22 — Incident Extensions sub-cluster folded into IncidentExtensionsHub */}
            <Route path="/remediate/incidents/extensions" element={<IncidentExtensionsHub />} />
            <Route path="/cloud-ir" element={<Navigate to="/remediate/incidents/extensions?tab=cloud" replace />} />
            <Route path="/identity-lifecycle" element={<IdentityLifecycleDashboard />} />
            <Route path="/dependency-mapping" element={<Navigate to="/remediate/upgrade?tab=dep-map" replace />} />

            {/* Wave 40 domain dashboards (pages for Wave 39 engines) */}
            <Route path="/risk-quant" element={<Navigate to="/comply/risk-quant?tab=dashboard" replace />} />
            <Route path="/cyber-threat-modeling" element={<Navigate to="/attack/threat-modeling?tab=cyber" replace />} />
            <Route path="/capacity-planning" element={<CapacityPlanningDashboard />} />
            <Route path="/tprm-exchange" element={<Navigate to="/compliance?tab=tprm" replace />} />
            <Route path="/event-timeline" element={<EventTimelineDashboard />} />
            <Route path="/vuln-intel-fusion" element={<Navigate to="/issues?tab=vuln-intel-fusion" replace />} />

            {/* Wave 39 domain dashboards */}
            <Route path="/posture-reports" element={<Navigate to="/compliance?tab=posture-reports" replace />} />
            <Route path="/network-anomaly" element={<Navigate to="/discover/network?tab=anomaly" replace />} />
            <Route path="/privileged-identity" element={<Navigate to="/admin?tab=privileged-access" replace />} />
            <Route path="/hunting-automation" element={<Navigate to="/mission-control/hunt?tab=automation" replace />} />
            <Route path="/service-catalog" element={<Navigate to="/assets?tab=catalog" replace />} />

            {/* Wave 38 domain dashboards */}
            <Route path="/sbom-export" element={<Navigate to="/comply/provenance?tab=export" replace />} />
            <Route path="/gap-analysis" element={<GapAnalysisDashboard />} />
            <Route path="/alert-enrichment" element={<Navigate to="/brain?tab=alert-enrichment" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/threat-response" element={<Navigate to="/attack/intel/ops?tab=response" replace />} />
            <Route path="/awareness-program" element={<Navigate to="/comply/awareness?tab=program" replace />} />

            {/* Wave 37 domain dashboards */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/cloud-findings" element={<Navigate to="/issues?tab=all" replace />} />
            <Route path="/soc-metrics" element={<SecurityOperationsMetricsDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/ti-confidence" element={<ThreatIntelConfidenceDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}

            {/* Wave 36 domain dashboards */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/compliance-calendar" element={<ComplianceCalendarDashboard />} />
            <Route path="/cyber-resilience" element={<CyberResilienceDashboard />} />
            <Route path="/asset-criticality" element={<Navigate to="/discover/assets/inventory?tab=criticality" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}

            {/* Wave 35 domain dashboards */}
            <Route path="/exception-workflow" element={<Navigate to="/remediate/exceptions?tab=workflow" replace />} />
            {/* S14 Threat Actors hub — folded 2026-05-02 (FOLDED ActorTrackingDashboard, was redirected to brain) */}
            <Route path="/actor-tracking" element={<Navigate to="/attack/intel/actors?tab=tracking" replace />} />
            <Route path="/vuln-scoring" element={<VulnScoringDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* S2 Finance hub — folded 2026-05-02 */}
            <Route path="/incident-costs" element={<Navigate to="/mission-control/finance?tab=incident-costs" replace />} />
            <Route path="/security-culture" element={<Navigate to="/admin/training-culture?tab=culture" replace />} />

            {/* Wave 34 domain dashboards */}
            <Route path="/security-questionnaires" element={<SecurityQuestionnaireDashboard />} />
            <Route path="/risk-scenarios" element={<Navigate to="/comply/risk-quant?tab=scenarios" replace />} />
            <Route path="/feed-subscriptions" element={<Navigate to="/attack/intel/ops?tab=feeds" replace />} />
            <Route path="/asset-groups" element={<Navigate to="/discover/assets/inventory?tab=groups" replace />} />
            {/* Canonical hub route — Asset metadata workspace (groups/tags/criticality) */}
            <Route path="/discover/assets/inventory" element={<AssetInventoryHub />} />
            <Route path="/security-findings" element={<Navigate to="/issues" replace />} />
            <Route path="/control-testing" element={<Navigate to="/comply/privacy?tab=controls" replace />} />

            {/* Wave 32 domain dashboards */}
            <Route path="/compliance-workflows" element={<ComplianceWorkflowDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/posture-trends" element={<Navigate to="/discover/posture-metrics?tab=trends" replace />} />
            <Route path="/access-governance" element={<Navigate to="/asset-graph?tab=access-governance" replace />} />
            <Route path="/network-threats" element={<Navigate to="/discover/network?tab=threats" replace />} />
            <Route path="/incident-kb" element={<Navigate to="/remediate/incidents/knowledge?tab=knowledge" replace />} />

            {/* Wave 31 domain dashboards */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/incident-lessons" element={<Navigate to="/remediate/incidents/knowledge?tab=lessons" replace />} />
            <Route path="/cloud-accounts" element={<Navigate to="/discover/assets/inventory?tab=cloud-accts" replace />} />
            <Route path="/intel-enrichment" element={<IntelEnrichmentDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}

            {/* Connector dashboards — folded into IntegrationTargetsHub (Phase 3, 2026-05-02) */}
            <Route path="/connect/targets" element={<IntegrationTargetsHub />} />
            <Route path="/prowler" element={<Navigate to="/connect/targets?tab=prowler" replace />} />
            <Route path="/servicenow" element={<Navigate to="/connect/targets?tab=servicenow" replace />} />
            <Route path="/siem-output" element={<Navigate to="/connect/targets?tab=siem" replace />} />

            {/* Webhook + ingestion-pipeline pages — folded into WebhookIngestionHub (Phase 3, 2026-05-02) */}
            <Route path="/connect/webhook-ingestion" element={<WebhookIngestionHub />} />

            {/* Strategic engine dashboards (2026-04-25) */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/org-hierarchy" element={<OrgHierarchyDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/agentless-snapshot" element={<Navigate to="/discover/assets/inventory?tab=snapshot" replace />} />
            <Route path="/security-query" element={<SecurityQueryLanguageDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/arch-graph" element={<ArchAwareGraphDashboard />} />
            <Route path="/ide-backend" element={<IDEBackendDashboard />} />

            {/* Strategic engine dashboards — batch 2 (2026-04-25) */}
            {/* S21 hero (Phase 3 UX consolidation, 2026-05-02): merges 6 pages into one tabbed screen. */}
            <Route path="/remediate/upgrade" element={<UpgradePathsHub />} />
            <Route path="/upgrade-path" element={<Navigate to="/remediate/upgrade?tab=resolver" replace />} />
            <Route path="/binary-fingerprint" element={<Navigate to="/remediate/upgrade?tab=binary-fp" replace />} />
            <Route path="/dependency-risk" element={<Navigate to="/remediate/upgrade?tab=dep-risk" replace />} />
            <Route path="/code-to-runtime" element={<CodeToRuntimeDashboard />} />
            <Route path="/pipeline-bom" element={<Navigate to="/comply/provenance?tab=pipeline-bom" replace />} />
            <Route path="/slsa-provenance" element={<Navigate to="/comply/provenance?tab=slsa" replace />} />
            <Route path="/fips-compliance" element={<FipsComplianceDashboard />} />
            <Route path="/local-file-store" element={<LocalFileStoreDashboard />} />
            <Route path="/dynamic-rule-dsl" element={<DynamicRuleDSLDashboard />} />

            {/* ─── Phase 3 P0 hero pages (Wiz/Apiiro pattern) ─── */}

            {/* ─── Phase 3 P0 Wave 3 hero pages (Command + Admin) ─── */}

            {/* 90-day muscle-memory redirects → Command hero */}
            <Route path="/main" element={<Navigate to="/" replace />} />
            <Route path="/overview" element={<Navigate to="/" replace />} />
            <Route path="/executive-brief" element={<Navigate to="/executive" replace />} />
            <Route path="/executive-briefing" element={<Navigate to="/executive" replace />} />
            <Route path="/executive-report" element={<Navigate to="/executive" replace />} />
            <Route path="/executive-reporting" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control/ciso" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control/executive" element={<Navigate to="/executive" replace />} />
            <Route path="/mission-control/soc" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/mission-control/soc-t1" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/mission-control/dev-security" element={<Navigate to="/?view=dev" replace />} />

            {/* 90-day muscle-memory redirects → Admin hero */}
            <Route path="/users/me/tokens" element={<Navigate to="/admin?tab=tokens" replace />} />
            <Route path="/admin/tokens" element={<Navigate to="/admin?tab=tokens" replace />} />
            <Route path="/connectors/mapping" element={<Navigate to="/admin?tab=connectors" replace />} />
            {/* Webhook + ingestion redirects — folded into WebhookIngestionHub (Phase 3, 2026-05-02) */}
            <Route path="/webhooks/event-catalogue" element={<Navigate to="/connect/webhook-ingestion?tab=catalogue" replace />} />
            <Route path="/webhooks/retry-queue" element={<Navigate to="/connect/webhook-ingestion?tab=retry" replace />} />
            <Route path="/organizations" element={<Navigate to="/admin?tab=orgs" replace />} />
            <Route path="/billing" element={<Navigate to="/admin?tab=billing" replace />} />
            <Route path="/settings/health" element={<Navigate to="/admin?tab=system" replace />} />

            {/* 90-day muscle-memory redirects → Compliance hero */}
            <Route path="/comply/evidence" element={<Navigate to="/compliance?tab=evidence" replace />} />
            <Route path="/comply/bundles" element={<Navigate to="/compliance?tab=bundles" replace />} />
            <Route path="/comply/audit" element={<Navigate to="/compliance?tab=audit" replace />} />
            <Route path="/compliance-mapping" element={<Navigate to="/compliance?tab=mapping" replace />} />
            {/* /compliance-gaps now folded into /comply/coverage hub (Phase 3 §2.23 ComplianceCoverageHub) */}
            <Route path="/compliance-calendar" element={<Navigate to="/compliance?tab=calendar" replace />} />
            <Route path="/compliance-workflows" element={<Navigate to="/compliance?tab=workflows" replace />} />
            <Route path="/compliance-automation" element={<Navigate to="/compliance?tab=workflows" replace />} />
            <Route path="/fips-mode" element={<Navigate to="/compliance?tab=frameworks" replace />} />
            <Route path="/system/fips-status" element={<Navigate to="/compliance?tab=frameworks" replace />} />
            <Route path="/audit/explorer" element={<Navigate to="/compliance?tab=audit" replace />} />
            <Route path="/ai-exposure" element={<Navigate to="/compliance?tab=ai-exposure" replace />} />

            {/* P1 Wave 2 — Evidence Vault redirects → Compliance hero */}
            <Route path="/evidence-vault" element={<Navigate to="/compliance?tab=vault" replace />} />
            <Route path="/comply/vault" element={<Navigate to="/compliance?tab=vault" replace />} />
            <Route path="/evidence/vault" element={<Navigate to="/compliance?tab=vault" replace />} />
            <Route path="/comply/cryptographic-evidence" element={<Navigate to="/compliance?tab=vault" replace />} />

            {/* P1 Wave 3 — SLA & Risk Register redirects → Compliance hero (S4) */}
            <Route path="/sla-dashboard" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/sla" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/mission-control/sla" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/risk-register" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/risk-register-engine" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/mission-control/risk-register" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/risk-acceptance" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/risk-treatment" element={<Navigate to="/compliance?tab=sla-risk" replace />} />
            <Route path="/risk-scenarios" element={<Navigate to="/compliance?tab=sla-risk" replace />} />

            {/* P1 Wave 3 — SOC Operations redirects → Command hero soc tab (S3) */}
            <Route path="/soc" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/soc-triage" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/alert-triage" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/incident-response" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/incidents/response" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/ai-soc" element={<Navigate to="/?view=soc" replace />} />

            {/* P1 Wave 3 — Executive Brief redirects → CISO Dashboard (Multica #3986) */}
            <Route path="/ciso" element={<Navigate to="/executive" replace />} />
            <Route path="/ciso-report" element={<Navigate to="/executive" replace />} />
            <Route path="/bu-risk-heatmap" element={<Navigate to="/executive" replace />} />
            <Route path="/executive-risk-report" element={<Navigate to="/executive" replace />} />

            {/* P1 Wave 3 — Issue Detail (S6) — drill-in pattern: /issues/:id → hero with selection */}
            <Route path="/issues/:findingId" element={<Navigate to="/issues" replace />} />
            <Route path="/finding/:findingId" element={<Navigate to="/issues" replace />} />
            <Route path="/vuln-lifecycle" element={<Navigate to="/issues" replace />} />

            {/* P1 Wave 2 — Integrations Hub redirects → Admin hero */}
            <Route path="/integrations-hub" element={<Navigate to="/admin?tab=integrations" replace />} />
            <Route path="/connectors/health" element={<Navigate to="/admin?tab=integrations" replace />} />
            <Route path="/connectors/marketplace" element={<Navigate to="/admin?tab=integrations" replace />} />
            <Route path="/connect" element={<Navigate to="/admin?tab=integrations" replace />} />

            {/* P1 Wave 2 — Attack Paths + SBOM new redirect-only routes → Asset Graph hero
                (existing canonical routes preserved at /discover/sbom, /discover/attack-paths,
                /sbom-continuous-monitoring, /comply/slsa for backward compat) */}
            <Route path="/attack-paths-graph" element={<Navigate to="/assets?tab=attack-paths" replace />} />
            <Route path="/attack/paths" element={<Navigate to="/assets?tab=attack-paths" replace />} />
            <Route path="/sbom-inventory" element={<Navigate to="/assets?tab=sbom" replace />} />
            <Route path="/sbom-management" element={<Navigate to="/assets?tab=sbom" replace />} />
            <Route path="/comply/sbom" element={<Navigate to="/assets?tab=sbom" replace />} />
            <Route path="/provenance" element={<Navigate to="/assets?tab=sbom" replace />} />

            {/* 90-day muscle-memory redirects → Asset Graph hero */}
            <Route path="/discover/inventory" element={<Navigate to="/assets?tab=inventory" replace />} />
            <Route path="/discover/code-intel" element={<Navigate to="/brain?tab=code-intel" replace />} />
            <Route path="/code-intel" element={<Navigate to="/brain?tab=code-intel" replace />} />
            <Route path="/discover/graph" element={<Navigate to="/assets?tab=architecture" replace />} />
            <Route path="/security-graph" element={<Navigate to="/assets?tab=architecture" replace />} />
            <Route path="/discover/arch-layers" element={<Navigate to="/assets?tab=architecture" replace />} />
            <Route path="/discover/graph-perf" element={<Navigate to="/assets?tab=architecture" replace />} />
            <Route path="/choke-points" element={<Navigate to="/assets?tab=chokepoints" replace />} />
            <Route path="/attack-paths/graph" element={<Navigate to="/assets?tab=architecture" replace />} />
            {/* S21 fold 2026-05-02: redirect to hub instead of /assets */}
            <Route path="/components/version-graph" element={<Navigate to="/remediate/upgrade?tab=version-graph" replace />} />
            <Route path="/graph/diff" element={<Navigate to="/assets?tab=diff" replace />} />
            <Route path="/graph/databases" element={<Navigate to="/assets?tab=databases" replace />} />
            <Route path="/easm/subsidiaries" element={<Navigate to="/assets?tab=subsidiaries" replace />} />

            {/* 90-day muscle-memory redirects → Issues hero */}
            <Route path="/issue-queue" element={<Navigate to="/issues" replace />} />
            <Route path="/issues/toxic" element={<Navigate to="/issues?tab=toxic" replace />} />
            <Route path="/material-changes" element={<Navigate to="/issues?tab=material" replace />} />
            <Route path="/pr-change-risk" element={<Navigate to="/issues?tab=pr-risk" replace />} />
            <Route path="/drift-tracking" element={<Navigate to="/issues?tab=drift" replace />} />
            <Route path="/security-findings" element={<Navigate to="/issues" replace />} />
            <Route path="/cloud-findings" element={<Navigate to="/issues?tab=all" replace />} />

            {/* 90-day muscle-memory redirects → Brain hero */}
            <Route path="/ai/brain" element={<Navigate to="/brain?tab=pipeline" replace />} />
            <Route path="/ai/consensus" element={<Navigate to="/brain?tab=consensus" replace />} />
            <Route path="/ai/algorithms" element={<Navigate to="/brain?tab=lab" replace />} />
            <Route path="/ai/predictions" element={<Navigate to="/brain?tab=predictions" replace />} />
            <Route path="/score-transparency" element={<Navigate to="/brain?tab=score" replace />} />
            <Route path="/factor-weights" element={<Navigate to="/brain?tab=weights" replace />} />

            {/* Legacy: BrainVisualization preserved under explicit alias for the Neural Map view */}
            <Route path="/brain/neural" element={<BrainVisualization />} />

            {/* ── GenericDashboard routes — 69 homogeneous pages collapsed 2026-04-27 ── */}
            {DASHBOARD_ROUTES.map(({ path, props }) => (
              <Route key={path} path={path} element={<GenericDashboard {...props} />} />
            ))}

            {/* ── FindingsExplorerView routes — Pattern-2 collapse 2026-04-27 (Wave 4) ──
                NB: /network-forensics and /malware-analysis are filtered out below;
                they are folded into ForensicsHub at /remediate/forensics (S22 fold 2026-05-02). */}
            {FINDINGS_EXPLORER_ROUTES
              .filter(({ path }) => path !== "/network-forensics" && path !== "/malware-analysis")
              .map(({ path, props }) => (
                <Route key={path} path={path} element={<FindingsExplorerView {...props} />} />
              ))}

            {/* S22 Forensics hub — folded 2026-05-02. Canonical hub + 3 legacy redirects. */}
            <Route path="/remediate/forensics" element={<ForensicsHub />} />
            <Route path="/digital-forensics" element={<Navigate to="/remediate/forensics?tab=digital" replace />} />
            <Route path="/network-forensics" element={<Navigate to="/remediate/forensics?tab=network" replace />} />
            <Route path="/malware-analysis" element={<Navigate to="/remediate/forensics?tab=malware" replace />} />

            {/* Main Overview Dashboard */}
            <Route path="/dashboard" element={<Navigate to="/" replace />} />

            {/* Wave 3 — risk / dashboards / runtime (15 screens, 2026-04-26) */}
            <Route path="/brs-executive" element={<BRSExecutiveDashboard />} />
            {/* S2 Finance hub — folded 2026-05-02. Canonical route mounted above. */}
            <Route path="/bu-dollar-heatmap" element={<Navigate to="/mission-control/finance?tab=bu-heatmap" replace />} />
            <Route path="/security-investment" element={<Navigate to="/mission-control/finance?tab=investment" replace />} />
            <Route path="/mission-control/finance" element={<FinanceHub />} />
            {/* /choke-points, /attack-paths/graph → consolidated into /assets hero */}
            {/* These 7 routes were consolidated into /issues + /brain heroes — see redirects above */}
            <Route path="/sbom-continuous-monitoring" element={<SBOMContinuousMonitoring />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/runtime-code-trace" element={<RuntimeCodeTrace />} />

            {/* Frontend Wave 4 — final cleanup wave (35 screens, 2026-04-26) */}
            {/* Phase 3 §2.28 fold 2026-05-02 — AirGapHub at /connect/mcp/air-gap (Air-Gap operational triad sub-cluster) */}
            <Route path="/connect/mcp/air-gap" element={<AirGapHub />} />
            <Route path="/air-gap/feed-status" element={<Navigate to="/connect/mcp/air-gap?tab=feed-status" replace />} />
            <Route path="/air-gap/feeds" element={<Navigate to="/connect/mcp/air-gap?tab=feeds" replace />} />
            <Route path="/air-gap/update-status" element={<Navigate to="/connect/mcp/air-gap?tab=update-status" replace />} />
            <Route path="/skills" element={<ClaudeSkillsRegistry />} />
            <Route path="/skills/install" element={<SkillsInstallPrompt />} />
            <Route path="/local-store/status" element={<LocalStoreStatus />} />
            <Route path="/local-store/init" element={<ZeroSetupOnboarding />} />
            {/* /components/version-graph → consolidated into /assets hero */}
            <Route path="/components/upgrade-path" element={<Navigate to="/remediate/upgrade?tab=explorer" replace />} />
            {/* /graph/databases, /graph/diff → consolidated into /assets hero */}
            <Route path="/copilot/graph-chat" element={<CopilotGraphChatRoot />} />
            <Route path="/copilot/traversal-trace" element={<TracedFlowViewer />} />
            <Route path="/investigate/rql" element={<RQLQueryBuilder />} />
            <Route path="/investigate/saved" element={<SavedInvestigations />} />
            <Route path="/scopes" element={<ScopeManager />} />
            <Route path="/easm/seed-domain" element={<DomainSeedDiscoveryWizard />} />
            {/* /easm/subsidiaries → consolidated into /assets hero */}
            <Route path="/users/me/tokens" element={<Navigate to="/admin?tab=tokens" replace />} />
            <Route path="/llm/context-tier" element={<LLMContextTierBadge />} />
            <Route path="/llm/estimate" element={<LLMPreFlightEstimateModal />} />
            <Route path="/llm/rules/edit" element={<LLMRuleContextEditor />} />
            <Route path="/hooks/policy" element={<Navigate to="/comply/policies/authoring?tab=hooks-policy" replace />} />
            <Route path="/hooks/status" element={<Navigate to="/comply/policies/authoring?tab=hooks-status" replace />} />
            <Route path="/connectors/mapping" element={<Navigate to="/admin?tab=connectors" replace />} />
            <Route path="/connectors/mapping/dry-run" element={<Navigate to="/connect/webhook-ingestion?tab=dry-run" replace />} />
            <Route path="/pbom/propagation" element={<Navigate to="/comply/provenance?tab=pbom-prop" replace />} />
            <Route path="/provenance/attestation" element={<Navigate to="/comply/provenance?tab=attestation" replace />} />
            <Route path="/provenance/sign" element={<Navigate to="/comply/provenance?tab=sign" replace />} />
            {/* S25 unified hero — Phase 3 cluster (2026-05-02): 6 standalone pages folded into one tabbed screen */}
            <Route path="/comply/provenance" element={<SBOMProvenanceHub />} />
            <Route path="/webhooks/event-catalogue" element={<Navigate to="/connect/webhook-ingestion?tab=catalogue" replace />} />
            <Route path="/webhooks/retry-queue" element={<Navigate to="/connect/webhook-ingestion?tab=retry" replace />} />
            <Route path="/assets/crown-jewel" element={<CrownJewelConfigurator />} />
            <Route path="/organizations" element={<OrgHierarchyExplorer />} />
            <Route path="/findings/drift" element={<StaleBaselineBanner />} />

            {/* Frontend Wave 2 — policy / waivers / rules / audit (14 screens, 2026-04-26) */}
            <Route path="/policies/stage-matrix" element={<Navigate to="/comply/policies/authoring?tab=stage-matrix" replace />} />
            {/* S26 unified hero — Phase 3 cluster (2026-05-02): 3 policy/hooks pages folded into one tabbed screen */}
            <Route path="/comply/policies/authoring" element={<PolicyAuthoringHub />} />
            {/* S27 unified hero — Phase 3 cluster (2026-05-02): 3 policy lifecycle pages folded into one tabbed hub */}
            <Route path="/comply/policies/lifecycle" element={<PolicyLifecycleHub />} />
            <Route path="/policies/stage-editor" element={<Navigate to="/comply/policies/lifecycle?tab=stage-edit" replace />} />
            {/* /waivers/* — Phase 3 P1 consolidated into /remediate?tab=waivers (S19 fold). */}
            {/* Standalone pages still render for old bookmarks; add a top-level /waivers redirect. */}
            <Route path="/waivers" element={<Navigate to="/remediate?tab=waivers" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/waivers/request" element={<WaiverRequestModal />} />
            <Route path="/waivers/auto-rules" element={<Navigate to="/remediate/exceptions?tab=auto-rules" replace />} />
            <Route path="/policies/inheritance" element={<Navigate to="/comply/policies/lifecycle?tab=inheritance" replace />} />
            <Route path="/policies/library" element={<Navigate to="/comply/policies/lifecycle?tab=library" replace />} />
            {/* Phase 3 §2.26 — Rules / DSL sub-cluster folded into RulesCatalogHub at /comply/rules */}
            <Route path="/comply/rules" element={<RulesCatalogHub />} />
            <Route path="/rules/dsl/author" element={<Navigate to="/comply/rules?tab=author" replace />} />
            <Route path="/rules/dsl/validate" element={<Navigate to="/comply/rules?tab=validate" replace />} />
            <Route path="/rules/catalog" element={<Navigate to="/comply/rules?tab=catalog" replace />} />
            <Route path="/rules/taxonomy" element={<Navigate to="/comply/rules?tab=taxonomy" replace />} />
            {/* /audit/explorer, /system/fips-status → consolidated into /compliance hero */}
            <Route path="/violations/lifecycle" element={<ViolationLifecycleTimeline />} />

            {/* Legacy redirects */}
            <Route path="/core/dashboard" element={<Navigate to="/" replace />} />
            <Route path="/code/*" element={<Navigate to="/discover" replace />} />
            <Route path="/cloud/*" element={<Navigate to="/discover/cloud" replace />} />
            <Route path="/attack/*" element={<Navigate to="/validate" replace />} />
            <Route path="/protect/*" element={<Navigate to="/remediate" replace />} />
            <Route path="/evidence/*" element={<Navigate to="/compliance?tab=evidence" replace />} />

            {/* 404 — show proper Not Found page instead of silent redirect */}
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
