import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { WorkspaceLayout } from "@/components/layout/WorkspaceLayout";
import { ErrorBoundary } from "@/components/shared/ErrorBoundary";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import NotFound from "@/pages/NotFound";
import { RequireAuth, RequireRole } from "@/lib/auth";

// Auth
const LoginPage = lazy(() => import("@/pages/auth/LoginPage"));
const AccessDenied = lazy(() => import("@/pages/auth/AccessDenied"));

// ── Lazy-loaded pages ──

// Space 1: Mission Control
const CommandDashboard = lazy(() => import("@/pages/mission-control/CommandDashboard"));
const CISODashboard = lazy(() => import("@/pages/mission-control/CISODashboard"));
const ExecutiveView = lazy(() => import("@/pages/mission-control/ExecutiveView"));
const SLADashboard = lazy(() => import("@/pages/mission-control/SLADashboard"));
const LiveFeed = lazy(() => import("@/pages/mission-control/LiveFeed"));
const RiskOverview = lazy(() => import("@/pages/mission-control/RiskOverview"));
const SOCDashboard = lazy(() => import("@/pages/mission-control/SOCDashboard"));
const SOCT1Dashboard = lazy(() => import("@/pages/mission-control/SOCT1Dashboard"));
const MissionControlComplianceDashboard = lazy(() => import("@/pages/mission-control/ComplianceDashboard"));
const DevSecurityDashboard = lazy(() => import("@/pages/mission-control/DevSecurityDashboard"));
const ThreatIntelDashboard = lazy(() => import("@/pages/mission-control/ThreatIntelDashboard"));
const RiskRegister = lazy(() => import("@/pages/mission-control/RiskRegister"));

// Findings Explorer (universal — all personas)
const FindingsExplorer = lazy(() => import("@/pages/findings/FindingsExplorer"));

// Space 2: Discover
const FindingExplorer = lazy(() => import("@/pages/discover/FindingExplorer"));
const CodeScanning = lazy(() => import("@/pages/discover/CodeScanning"));
const SecretsDetection = lazy(() => import("@/pages/discover/SecretsDetection"));
const IaCScanning = lazy(() => import("@/pages/discover/IaCScanning"));
const CloudPosture = lazy(() => import("@/pages/discover/CloudPosture"));
const ContainerSecurity = lazy(() => import("@/pages/discover/ContainerSecurity"));
const SBOMInventory = lazy(() => import("@/pages/discover/SBOMInventory"));
const KnowledgeGraph = lazy(() => import("@/pages/discover/KnowledgeGraph"));
const AttackPaths = lazy(() => import("@/pages/discover/AttackPaths"));
const ThreatFeeds = lazy(() => import("@/pages/discover/ThreatFeeds"));
const CorrelationEngine = lazy(() => import("@/pages/discover/CorrelationEngine"));
const DataFabric = lazy(() => import("@/pages/discover/DataFabric"));

// Space 3: Validate
const MPTEConsole = lazy(() => import("@/pages/validate/MPTEConsole"));
const AttackSimulation = lazy(() => import("@/pages/validate/AttackSimulation"));
const FAILEngine = lazy(() => import("@/pages/validate/FAILEngine"));
const Playbooks = lazy(() => import("@/pages/validate/Playbooks"));
const PlaybookEditor = lazy(() => import("@/pages/validate/PlaybookEditor"));
const Reachability = lazy(() => import("@/pages/validate/Reachability"));

// Space 4: Remediate
const RemediationCenter = lazy(() => import("@/pages/remediate/RemediationCenter"));
const AutoFix = lazy(() => import("@/pages/remediate/AutoFix"));
const BulkOperations = lazy(() => import("@/pages/remediate/BulkOperations"));
const Collaboration = lazy(() => import("@/pages/remediate/Collaboration"));
const Workflows = lazy(() => import("@/pages/remediate/Workflows"));
const ExposureCases = lazy(() => import("@/pages/remediate/ExposureCases"));
const TicketIntegration = lazy(() => import("@/pages/remediate/TicketIntegration"));

// Space 5: Comply
const ComplianceDashboard = lazy(() => import("@/pages/comply/ComplianceDashboard"));
const EvidenceVault = lazy(() => import("@/pages/comply/EvidenceVault"));
const EvidenceBundles = lazy(() => import("@/pages/comply/EvidenceBundles"));
const SOC2Evidence = lazy(() => import("@/pages/comply/SOC2Evidence"));
const SLSAProvenance = lazy(() => import("@/pages/comply/SLSAProvenance"));
const AuditTrail = lazy(() => import("@/pages/comply/AuditTrail"));
const Reports = lazy(() => import("@/pages/comply/Reports"));
const Analytics = lazy(() => import("@/pages/comply/Analytics"));
const EvidenceExportCenter = lazy(() => import("@/pages/comply/EvidenceExportCenter"));

// Settings
const SettingsHub = lazy(() => import("@/pages/settings/SettingsHub"));
const SettingsPage = lazy(() => import("@/pages/settings/Settings"));
const Integrations = lazy(() => import("@/pages/settings/Integrations"));
const UsersPage = lazy(() => import("@/pages/settings/Users"));
const Teams = lazy(() => import("@/pages/settings/Teams"));
const Marketplace = lazy(() => import("@/pages/settings/Marketplace"));
const Policies = lazy(() => import("@/pages/settings/Policies"));
const SystemHealth = lazy(() => import("@/pages/settings/SystemHealth"));
const LogViewer = lazy(() => import("@/pages/settings/LogViewer"));

// Onboarding
const OnboardingWizard = lazy(() => import("@/pages/onboarding/OnboardingWizard"));

// Developer Portal
const DeveloperPortal = lazy(() => import("@/pages/developer/DeveloperPortal"));

// Attack Surface
const AttackSurface = lazy(() => import("@/pages/attack-surface/AttackSurface"));

// Integration Health
const IntegrationHealth = lazy(() => import("@/pages/integrations/IntegrationHealth"));

// Threat Hunting
const ThreatHunting = lazy(() => import("@/pages/hunting/ThreatHunting"));

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
const AssetInventoryPage = lazy(() => import("@/pages/AssetInventory"));
const VulnLifecyclePage = lazy(() => import("@/pages/VulnLifecycle"));
const InsiderThreatMonitor = lazy(() => import("@/pages/InsiderThreatMonitor"));
const SecurityKPIDashboard = lazy(() => import("@/pages/SecurityKPIDashboard"));
const VendorRiskDashboard = lazy(() => import("@/pages/VendorRiskDashboard"));
const PostureAdvisor = lazy(() => import("@/pages/PostureAdvisor"));
const ZeroTrustDashboard = lazy(() => import("@/pages/ZeroTrustDashboard"));
const PatchPrioritizer = lazy(() => import("@/pages/PatchPrioritizer"));
const CVESearch = lazy(() => import("@/pages/CVESearch"));
const IPReputationDashboard = lazy(() => import("@/pages/IPReputationDashboard"));
const SecretsRotation = lazy(() => import("@/pages/SecretsRotation"));
const SupplyChainSecurity = lazy(() => import("@/pages/SupplyChainSecurity"));
const DLPDashboard = lazy(() => import("@/pages/DLPDashboard"));
const APIAbuseDashboard = lazy(() => import("@/pages/APIAbuseDashboard"));
const ThreatModeling = lazy(() => import("@/pages/ThreatModeling"));
const AttackPathAnalysis = lazy(() => import("@/pages/AttackPathAnalysis"));
const IncidentTimeline = lazy(() => import("@/pages/IncidentTimeline"));
const IdentityGovernance = lazy(() => import("@/pages/IdentityGovernance"));
const SecurityAwareness = lazy(() => import("@/pages/SecurityAwareness"));
const ExecutiveRiskReport = lazy(() => import("@/pages/ExecutiveRiskReport"));
const NetworkAnalysis = lazy(() => import("@/pages/NetworkAnalysis"));
const VulnHeatmap = lazy(() => import("@/pages/VulnHeatmap"));
const AuditLog = lazy(() => import("@/pages/AuditLog"));
const CSPMDashboard = lazy(() => import("@/pages/CSPMDashboard"));
const ThreatHuntingPage = lazy(() => import("@/pages/ThreatHunting"));
const PentestManagement = lazy(() => import("@/pages/PentestManagement"));
const DeceptionEngine = lazy(() => import("@/pages/DeceptionEngine"));
const CertificateManager = lazy(() => import("@/pages/CertificateManager"));
const FirewallAnalyzer = lazy(() => import("@/pages/FirewallAnalyzer"));
const RiskRegisterPage = lazy(() => import("@/pages/RiskRegister"));
const PlaybookLibraryPage = lazy(() => import("@/pages/PlaybookLibrary"));
const BugBounty = lazy(() => import("@/pages/BugBounty"));
const CloudIAM = lazy(() => import("@/pages/CloudIAM"));
const EmailSecurity = lazy(() => import("@/pages/EmailSecurity"));
const SLADashboardPage = lazy(() => import("@/pages/SLADashboard"));
const SecurityMetricsDashboard = lazy(() => import("@/pages/SecurityMetricsDashboard"));
const MobileSecurity = lazy(() => import("@/pages/MobileSecurity"));
const PasswordPolicy = lazy(() => import("@/pages/PasswordPolicy"));
const AppSecurity = lazy(() => import("@/pages/AppSecurity"));
const VulnRiskQueue = lazy(() => import("@/pages/VulnRiskQueue"));
const RedTeamStatus = lazy(() => import("@/pages/RedTeamStatus"));
const NetworkTopology = lazy(() => import("@/pages/NetworkTopology"));
const IOCHunter = lazy(() => import("@/pages/IOCHunter"));
const SocialEngineering = lazy(() => import("@/pages/SocialEngineering"));
const SOARDashboard = lazy(() => import("@/pages/SOARDashboard"));
const GRCDashboard = lazy(() => import("@/pages/GRCDashboard"));
const APISecurityDashboard = lazy(() => import("@/pages/APISecurityDashboard"));
const ThreatCorrelation = lazy(() => import("@/pages/ThreatCorrelation"));
const SupplyChainDashboard = lazy(() => import("@/pages/SupplyChainDashboard"));
const CloudSecurityDashboard = lazy(() => import("@/pages/CloudSecurityDashboard"));
const BreachResponse = lazy(() => import("@/pages/BreachResponse"));
const SecurityOperationsCenter = lazy(() => import("@/pages/SecurityOperationsCenter"));
const WatchlistManager = lazy(() => import("@/pages/WatchlistManager"));
const UBADashboard = lazy(() => import("@/pages/UBADashboard"));
const CMDBDashboard = lazy(() => import("@/pages/CMDBDashboard"));
const IncidentResponseDashboard = lazy(() => import("@/pages/IncidentResponseDashboard"));
const PhishingSimulation = lazy(() => import("@/pages/PhishingSimulation"));
const APISecurityPage = lazy(() => import("@/pages/APISecurityPage"));
const DataClassificationDashboard = lazy(() => import("@/pages/DataClassificationDashboard"));
const SecurityTrainingDashboard = lazy(() => import("@/pages/SecurityTrainingDashboard"));
const PAMDashboard = lazy(() => import("@/pages/PAMDashboard"));
const CyberInsurance = lazy(() => import("@/pages/CyberInsurance"));
const CyberInsuranceDashboard = lazy(() => import("@/pages/CyberInsuranceDashboard"));
const ExecutiveReportingDashboard = lazy(() => import("@/pages/ExecutiveReportingDashboard"));
const VulnerabilityScanner = lazy(() => import("@/pages/VulnerabilityScanner"));
const RiskQuantification = lazy(() => import("@/pages/RiskQuantification"));
const AttackSimulationPage = lazy(() => import("@/pages/AttackSimulation"));
const VulnerabilityScannerPage = lazy(() => import("@/pages/VulnerabilityScannerPage"));
const SecurityPostureDashboard = lazy(() => import("@/pages/SecurityPostureDashboard"));
const ExecutiveBriefing = lazy(() => import("@/pages/ExecutiveBriefing"));
const ThreatFeedDashboard = lazy(() => import("@/pages/ThreatFeedDashboard"));
const CWPPDashboard = lazy(() => import("@/pages/CWPPDashboard"));
const DigitalForensicsDashboard = lazy(() => import("@/pages/DigitalForensicsDashboard"));
const GRCAssessment = lazy(() => import("@/pages/GRCAssessment"));
const DataGovernanceDashboard = lazy(() => import("@/pages/DataGovernanceDashboard"));
const SecurityRoadmap = lazy(() => import("@/pages/SecurityRoadmap"));
const ThreatHuntingDashboard = lazy(() => import("@/pages/ThreatHuntingDashboard"));
const ComplianceScannerDashboard = lazy(() => import("@/pages/ComplianceScannerDashboard"));
const AssetRiskDashboard = lazy(() => import("@/pages/AssetRiskDashboard"));
const SecurityHealthDashboard = lazy(() => import("@/pages/SecurityHealthDashboard"));

// New pages: Cross-Domain Analytics, DevSecOps, Vuln Trends, Config Benchmarks
const CrossDomainAnalytics = lazy(() => import("@/pages/CrossDomainAnalytics"));
const DevSecOpsDashboard = lazy(() => import("@/pages/DevSecOpsDashboard"));
const VulnTrendDashboard = lazy(() => import("@/pages/VulnTrendDashboard"));
const ConfigBenchmarkDashboard = lazy(() => import("@/pages/ConfigBenchmarkDashboard"));

// New Beast Mode pages
const IncidentTimelineDashboard = lazy(() => import("@/pages/IncidentTimelineDashboard"));
const SecurityMetricsDashboard2 = lazy(() => import("@/pages/SecurityMetricsDashboard2"));
const ZeroTrustPolicyDashboard = lazy(() => import("@/pages/ZeroTrustPolicyDashboard"));
const ThreatModelDashboard = lazy(() => import("@/pages/ThreatModelDashboard"));

// OpenClaw + SOC Triage AI + SBOM Dashboard
const OpenClawDashboard = lazy(() => import("@/pages/OpenClawDashboard"));
const SOCTriageDashboard = lazy(() => import("@/pages/SOCTriageDashboard"));
const SBOMDashboard = lazy(() => import("@/pages/SBOMDashboard"));
const DASTDashboard = lazy(() => import("@/pages/DASTDashboard"));
const IRPlaybookDashboard = lazy(() => import("@/pages/IRPlaybookDashboard"));

// NDR / XDR / Awareness / EDR pages
const NDRDashboard = lazy(() => import("@/pages/NDRDashboard"));
const XDRDashboard = lazy(() => import("@/pages/XDRDashboard"));
const AwarenessScoreDashboard = lazy(() => import("@/pages/AwarenessScoreDashboard"));
const EDRDashboard = lazy(() => import("@/pages/EDRDashboard"));

// New Beast Mode pages — Identity Analytics, CNAPP, Pentest Mgmt, Supply Chain Intel
const IdentityAnalyticsDashboard = lazy(() => import("@/pages/IdentityAnalyticsDashboard"));
const CNAPPDashboard = lazy(() => import("@/pages/CNAPPDashboard"));
const PentestManagementDashboard = lazy(() => import("@/pages/PentestManagementDashboard"));
const SupplyChainIntelDashboard = lazy(() => import("@/pages/SupplyChainIntelDashboard"));

// Governance + Executive pages
const SecurityExceptionDashboard = lazy(() => import("@/pages/SecurityExceptionDashboard"));
const RegulatoryTrackerDashboard = lazy(() => import("@/pages/RegulatoryTrackerDashboard"));
const SecurityScorecardDashboard = lazy(() => import("@/pages/SecurityScorecardDashboard"));
const CCMDashboard = lazy(() => import("@/pages/CCMDashboard"));

// System Health Dashboard
const SystemHealthDashboard = lazy(() => import("@/pages/SystemHealthDashboard"));

// Security Maturity, Privacy/GDPR, Network Traffic, Container Security
const SecurityMaturityDashboard = lazy(() => import("@/pages/SecurityMaturityDashboard"));
const PrivacyGDPRDashboard = lazy(() => import("@/pages/PrivacyGDPRDashboard"));
const NetworkTrafficDashboard = lazy(() => import("@/pages/NetworkTrafficDashboard"));
const ContainerSecurityDashboard = lazy(() => import("@/pages/ContainerSecurityDashboard"));

// Threat Actor Intelligence + Security Champions
const ThreatActorDashboard = lazy(() => import("@/pages/ThreatActorDashboard"));
const SecurityChampionsDashboard = lazy(() => import("@/pages/SecurityChampionsDashboard"));

// Compliance Dashboard — standalone P07 view (route: /compliance)
const StandaloneComplianceDashboard = lazy(() => import("@/pages/ComplianceDashboard"));

// Threat Geolocation + IP Reputation dashboards
const ThreatGeolocationDashboard = lazy(() => import("@/pages/ThreatGeolocationDashboard"));

// Secret Scanner, TIP, Attack Surface dashboards (wave 9)
const SecretScannerDashboard = lazy(() => import("@/pages/SecretScannerDashboard"));
const ContainerRegistryDashboard = lazy(() => import("@/pages/ContainerRegistryDashboard"));
const NetworkMonitoringDashboard = lazy(() => import("@/pages/NetworkMonitoringDashboard"));
const SCADashboard = lazy(() => import("@/pages/SCADashboard"));
const ServiceAccountAuditDashboard = lazy(() => import("@/pages/ServiceAccountAuditDashboard"));
const ThreatIntelPlatformDashboard = lazy(() => import("@/pages/ThreatIntelPlatformDashboard"));
const AttackSurfaceDashboard = lazy(() => import("@/pages/AttackSurfaceDashboard"));

// API Security Management + Vuln Intelligence
const APISecurityMgmtDashboard = lazy(() => import("@/pages/APISecurityMgmtDashboard"));
const VulnIntelligenceDashboard = lazy(() => import("@/pages/VulnIntelligenceDashboard"));

// AI Security Advisor
const AISecurityAdvisor = lazy(() => import("@/pages/AISecurityAdvisor"));

// AI Security Advisor Dashboard + Scheduled Reports Dashboard
const AISecurityAdvisorDashboard = lazy(() => import("@/pages/AISecurityAdvisorDashboard"));
const ScheduledReportsDashboard = lazy(() => import("@/pages/ScheduledReportsDashboard"));

// Crypto Key, Certificate, Privilege Escalation, Security Automation dashboards
const CryptoKeyDashboard = lazy(() => import("@/pages/CryptoKeyDashboard"));
const CertificateDashboard = lazy(() => import("@/pages/CertificateDashboard"));
const PrivilegeEscalationDashboard = lazy(() => import("@/pages/PrivilegeEscalationDashboard"));
const SecurityAutomationDashboard = lazy(() => import("@/pages/SecurityAutomationDashboard"));

// Cloud Compliance + Endpoint Compliance dashboards
const CloudComplianceDashboard = lazy(() => import("@/pages/CloudComplianceDashboard"));
const EndpointComplianceDashboard = lazy(() => import("@/pages/EndpointComplianceDashboard"));

// Firewall Policy, Network Segmentation dashboards
const FirewallPolicyDashboard = lazy(() => import("@/pages/FirewallPolicyDashboard"));
const NetworkSegmentationDashboard = lazy(() => import("@/pages/NetworkSegmentationDashboard"));

// MFA Management, Threat Scores, Security Budget, Compliance Gaps
const MFAManagementDashboard = lazy(() => import("@/pages/MFAManagementDashboard"));
const ThreatScoreDashboard = lazy(() => import("@/pages/ThreatScoreDashboard"));
const SecurityBudgetDashboard = lazy(() => import("@/pages/SecurityBudgetDashboard"));
const ComplianceGapDashboard = lazy(() => import("@/pages/ComplianceGapDashboard"));

// AI Copilot & AI Engine
const CopilotDashboard = lazy(() => import("@/pages/ai/CopilotDashboard"));
const BrainPipeline = lazy(() => import("@/pages/ai/BrainPipeline"));
const MultiLLM = lazy(() => import("@/pages/ai/MultiLLM"));
const AlgorithmicLab = lazy(() => import("@/pages/ai/AlgorithmicLab"));
const MLDashboard = lazy(() => import("@/pages/ai/MLDashboard"));
const Predictions = lazy(() => import("@/pages/ai/Predictions"));

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageSkeleton />}>
        <Routes>
          {/* Public routes */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/onboarding" element={<OnboardingWizard />} />

          {/* Protected workspace */}
          <Route element={<RequireAuth><WorkspaceLayout /></RequireAuth>}>
            {/* Space 1: Mission Control */}
            <Route path="/" element={<CommandDashboard />} />
            <Route path="/mission-control" element={<CommandDashboard />} />
            <Route path="/mission-control/ciso" element={<RequireRole roles={["admin"]} fallback={<AccessDenied />}><CISODashboard /></RequireRole>} />
            <Route path="/mission-control/executive" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><ExecutiveView /></RequireRole>} />
            <Route path="/mission-control/sla" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><SLADashboard /></RequireRole>} />
            <Route path="/mission-control/live-feed" element={<LiveFeed />} />
            <Route path="/mission-control/risk" element={<RiskOverview />} />
            <Route path="/mission-control/soc" element={<SOCDashboard />} />
            <Route path="/mission-control/soc-t1" element={<SOCT1Dashboard />} />
            <Route path="/mission-control/compliance" element={<MissionControlComplianceDashboard />} />
            <Route path="/mission-control/dev-security" element={<DevSecurityDashboard />} />
            <Route path="/mission-control/threat-intel" element={<ThreatIntelDashboard />} />
            <Route path="/mission-control/risk-register" element={<RiskRegister />} />

            {/* Space 2: Discover */}
            <Route path="/discover" element={<FindingExplorer />} />
            <Route path="/discover/code" element={<CodeScanning />} />
            <Route path="/discover/secrets" element={<SecretsDetection />} />
            <Route path="/discover/iac" element={<IaCScanning />} />
            <Route path="/discover/cloud" element={<CloudPosture />} />
            <Route path="/discover/containers" element={<ContainerSecurity />} />
            <Route path="/discover/sbom" element={<SBOMInventory />} />
            <Route path="/discover/graph" element={<KnowledgeGraph />} />
            <Route path="/discover/attack-paths" element={<AttackPaths />} />
            <Route path="/discover/threats" element={<ThreatFeeds />} />
            <Route path="/discover/correlation" element={<CorrelationEngine />} />
            <Route path="/discover/data-fabric" element={<DataFabric />} />

            {/* Space 3: Validate — admin + security_analyst only (except Reachability) */}
            <Route path="/validate" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><MPTEConsole /></RequireRole>} />
            <Route path="/validate/mpte" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><MPTEConsole /></RequireRole>} />
            <Route path="/validate/simulation" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><AttackSimulation /></RequireRole>} />
            <Route path="/validate/fail" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><FAILEngine /></RequireRole>} />
            <Route path="/validate/playbooks" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><Playbooks /></RequireRole>} />
            <Route path="/validate/playbooks/editor" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><PlaybookEditor /></RequireRole>} />
            <Route path="/validate/reachability" element={<Reachability />} />

            {/* Space 4: Remediate */}
            <Route path="/remediate" element={<RemediationCenter />} />
            <Route path="/remediate/autofix" element={<AutoFix />} />
            <Route path="/remediate/bulk" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><BulkOperations /></RequireRole>} />
            <Route path="/remediate/collaborate" element={<Collaboration />} />
            <Route path="/remediate/workflows" element={<Workflows />} />
            <Route path="/remediate/cases" element={<ExposureCases />} />
            <Route path="/remediate/tickets" element={<TicketIntegration />} />

            {/* Space 5: Comply */}
            <Route path="/comply" element={<ComplianceDashboard />} />
            <Route path="/comply/evidence" element={<EvidenceVault />} />
            <Route path="/comply/bundles" element={<EvidenceBundles />} />
            <Route path="/comply/soc2" element={<SOC2Evidence />} />
            <Route path="/comply/slsa" element={<SLSAProvenance />} />
            <Route path="/comply/audit" element={<AuditTrail />} />
            <Route path="/comply/reports" element={<Reports />} />
            <Route path="/comply/analytics" element={<Analytics />} />
            <Route path="/comply/export" element={<EvidenceExportCenter />} />

            {/* Settings */}
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/settings/integrations" element={<Integrations />} />
            <Route path="/settings/users" element={<RequireRole roles={["admin"]} fallback={<AccessDenied />}><UsersPage /></RequireRole>} />
            <Route path="/settings/teams" element={<RequireRole roles={["admin"]} fallback={<AccessDenied />}><Teams /></RequireRole>} />
            <Route path="/settings/marketplace" element={<Marketplace />} />
            <Route path="/settings/policies" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><Policies /></RequireRole>} />
            <Route path="/settings/health" element={<SystemHealth />} />
            <Route path="/settings/logs" element={<LogViewer />} />

            {/* AI Security Advisor */}
            <Route path="/ai-advisor" element={<AISecurityAdvisor />} />
            <Route path="/ai-advisor-dashboard" element={<AISecurityAdvisorDashboard />} />

            {/* Scheduled Reports */}
            <Route path="/scheduled-reports" element={<ScheduledReportsDashboard />} />

            {/* AI Copilot & AI Engine */}
            <Route path="/ai" element={<CopilotDashboard />} />
            <Route path="/ai/brain" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><BrainPipeline /></RequireRole>} />
            <Route path="/ai/consensus" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><MultiLLM /></RequireRole>} />
            <Route path="/ai/algorithms" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><AlgorithmicLab /></RequireRole>} />
            <Route path="/ai/ml" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><MLDashboard /></RequireRole>} />
            <Route path="/ai/predictions" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><Predictions /></RequireRole>} />

            {/* Findings Explorer — universal, all personas */}
            <Route path="/findings" element={<FindingsExplorer />} />

            {/* Attack Surface */}
            <Route path="/attack-surface" element={<AttackSurface />} />

            {/* Integration Health */}
            <Route path="/integrations" element={<IntegrationHealth />} />

            {/* Threat Hunting */}
            <Route path="/hunting" element={<ThreatHunting />} />
            <Route path="/threat-hunting" element={<ThreatHuntingPage />} />

            {/* Developer Portal */}
            <Route path="/developer" element={<DeveloperPortal />} />

            {/* Vendor Management */}
            <Route path="/vendors" element={<VendorManagement />} />

            {/* Incident Response */}
            <Route path="/incidents" element={<IncidentResponse />} />

            {/* Risk Acceptance */}
            <Route path="/risk-acceptance" element={<RiskAcceptance />} />

            {/* SBOM Management */}
            <Route path="/sbom" element={<SBOMManagement />} />

            {/* Compliance Dashboard — P07 standalone */}
            <Route path="/compliance" element={<StandaloneComplianceDashboard />} />

            {/* DLP & API Abuse Detection */}
            <Route path="/dlp" element={<DLPDashboard />} />
            <Route path="/api-abuse" element={<APIAbuseDashboard />} />

            {/* Crypto Key, Certificate, Privilege Escalation, Security Automation */}
            <Route path="/crypto-keys" element={<CryptoKeyDashboard />} />
            <Route path="/certificates" element={<CertificateDashboard />} />
            <Route path="/privilege-escalation" element={<PrivilegeEscalationDashboard />} />
            <Route path="/security-automation" element={<SecurityAutomationDashboard />} />

            {/* Secret Scanner, Threat Intel Platform, Attack Surface Dashboard */}
            <Route path="/secret-scanner" element={<SecretScannerDashboard />} />
            <Route path="/dast" element={<DASTDashboard />} />
            <Route path="/ir-playbook" element={<IRPlaybookDashboard />} />
            <Route path="/container-registry" element={<ContainerRegistryDashboard />} />
            <Route path="/network-monitoring" element={<NetworkMonitoringDashboard />} />
            <Route path="/sca" element={<SCADashboard />} />
            <Route path="/service-account-audit" element={<ServiceAccountAuditDashboard />} />
            <Route path="/threat-intel-platform" element={<ThreatIntelPlatformDashboard />} />
            <Route path="/attack-surface-dashboard" element={<AttackSurfaceDashboard />} />

            {/* New standalone pages */}
            <Route path="/threat-intel" element={<ThreatIntelDashboardPage />} />
            <Route path="/assets" element={<AssetInventoryPage />} />
            <Route path="/vuln-lifecycle" element={<VulnLifecyclePage />} />
            <Route path="/insider-threats" element={<InsiderThreatMonitor />} />
            <Route path="/security-kpis" element={<SecurityKPIDashboard />} />
            <Route path="/posture-advisor" element={<PostureAdvisor />} />
            <Route path="/patch-prioritizer" element={<PatchPrioritizer />} />
            <Route path="/vendor-risk" element={<VendorRiskDashboard />} />
            <Route path="/cve-search" element={<CVESearch />} />
            <Route path="/ip-reputation" element={<IPReputationDashboard />} />
            <Route path="/threat-geolocation" element={<ThreatGeolocationDashboard />} />
            <Route path="/secrets-rotation" element={<SecretsRotation />} />
            <Route path="/security-awareness" element={<SecurityAwareness />} />
            <Route path="/supply-chain" element={<SupplyChainSecurity />} />
            <Route path="/zero-trust" element={<ZeroTrustDashboard />} />
            <Route path="/threat-modeling" element={<ThreatModeling />} />
            <Route path="/attack-paths" element={<AttackPathAnalysis />} />
            <Route path="/incident-timeline" element={<IncidentTimeline />} />
            <Route path="/identity-governance" element={<IdentityGovernance />} />
            <Route path="/executive-report" element={<ExecutiveRiskReport />} />
            <Route path="/network-analysis" element={<NetworkAnalysis />} />
            <Route path="/vuln-heatmap" element={<VulnHeatmap />} />
            <Route path="/audit-log" element={<AuditLog />} />
            <Route path="/cspm" element={<CSPMDashboard />} />
            <Route path="/pentest" element={<PentestManagement />} />
            <Route path="/deception" element={<DeceptionEngine />} />
            <Route path="/certificates" element={<CertificateManager />} />
            <Route path="/firewall" element={<FirewallAnalyzer />} />
            <Route path="/risk-register" element={<RiskRegisterPage />} />
            <Route path="/playbooks" element={<PlaybookLibraryPage />} />
            <Route path="/bug-bounty" element={<BugBounty />} />
            <Route path="/cloud-iam" element={<CloudIAM />} />
            <Route path="/email-security" element={<EmailSecurity />} />
            <Route path="/sla-dashboard" element={<SLADashboardPage />} />
            <Route path="/security-metrics" element={<SecurityMetricsDashboard />} />
            <Route path="/vuln-risk" element={<VulnRiskQueue />} />
            <Route path="/red-team" element={<RedTeamStatus />} />
            <Route path="/network-topology" element={<NetworkTopology />} />
            <Route path="/ioc-hunter" element={<IOCHunter />} />
            <Route path="/social-engineering" element={<SocialEngineering />} />
            <Route path="/mobile-security" element={<MobileSecurity />} />
            <Route path="/password-policy" element={<PasswordPolicy />} />
            <Route path="/app-security" element={<AppSecurity />} />
            <Route path="/soar" element={<SOARDashboard />} />
            <Route path="/grc" element={<GRCDashboard />} />
            <Route path="/api-security" element={<APISecurityDashboard />} />
            <Route path="/threat-correlation" element={<ThreatCorrelation />} />
            <Route path="/supply-chain-risk" element={<SupplyChainDashboard />} />
            <Route path="/cloud-security" element={<CloudSecurityDashboard />} />
            <Route path="/breach-response" element={<BreachResponse />} />
            <Route path="/soc" element={<SecurityOperationsCenter />} />
            <Route path="/watchlist" element={<WatchlistManager />} />
            <Route path="/uba" element={<UBADashboard />} />
            <Route path="/cmdb" element={<CMDBDashboard />} />
            <Route path="/incident-response" element={<IncidentResponseDashboard />} />
            <Route path="/phishing" element={<PhishingSimulation />} />
            <Route path="/api-sec" element={<APISecurityPage />} />
            <Route path="/data-classification" element={<DataClassificationDashboard />} />
            <Route path="/security-training" element={<SecurityTrainingDashboard />} />
            <Route path="/pam" element={<PAMDashboard />} />
            <Route path="/cyber-insurance" element={<CyberInsuranceDashboard />} />
            <Route path="/cyber-insurance-legacy" element={<CyberInsurance />} />
            <Route path="/executive-reporting" element={<ExecutiveReportingDashboard />} />
            <Route path="/vuln-scanner" element={<VulnerabilityScanner />} />
            <Route path="/risk-quantification" element={<RiskQuantification />} />
            <Route path="/attack-simulation" element={<AttackSimulationPage />} />
            <Route path="/vuln-scanner-mgmt" element={<VulnerabilityScannerPage />} />
            <Route path="/security-posture" element={<SecurityPostureDashboard />} />
            <Route path="/executive-briefing" element={<ExecutiveBriefing />} />
            <Route path="/threat-feeds" element={<ThreatFeedDashboard />} />
            <Route path="/cwpp" element={<CWPPDashboard />} />
            <Route path="/digital-forensics" element={<DigitalForensicsDashboard />} />
            <Route path="/grc-assessment" element={<GRCAssessment />} />
            <Route path="/data-governance" element={<DataGovernanceDashboard />} />
            <Route path="/security-roadmap" element={<SecurityRoadmap />} />
            <Route path="/threat-hunting-dashboard" element={<ThreatHuntingDashboard />} />
            <Route path="/compliance-scanner" element={<ComplianceScannerDashboard />} />
            <Route path="/asset-risk" element={<AssetRiskDashboard />} />
            <Route path="/security-health" element={<SecurityHealthDashboard />} />
            <Route path="/cross-domain-analytics" element={<CrossDomainAnalytics />} />
            <Route path="/devsecops" element={<DevSecOpsDashboard />} />
            <Route path="/vuln-trends" element={<VulnTrendDashboard />} />
            <Route path="/config-benchmark" element={<ConfigBenchmarkDashboard />} />
            <Route path="/incident-timeline-dashboard" element={<IncidentTimelineDashboard />} />
            <Route path="/security-metrics-live" element={<SecurityMetricsDashboard2 />} />
            <Route path="/zero-trust-policies" element={<ZeroTrustPolicyDashboard />} />
            <Route path="/threat-models" element={<ThreatModelDashboard />} />
            <Route path="/security-exceptions" element={<SecurityExceptionDashboard />} />
            <Route path="/regulatory-tracker" element={<RegulatoryTrackerDashboard />} />
            <Route path="/security-scorecard" element={<SecurityScorecardDashboard />} />
            <Route path="/ccm" element={<CCMDashboard />} />
            <Route path="/system-health" element={<SystemHealthDashboard />} />

            {/* OpenClaw + SOC Triage AI + SBOM */}
            <Route path="/openclaw" element={<Suspense fallback={<div>Loading...</div>}><OpenClawDashboard /></Suspense>} />
            <Route path="/soc-triage" element={<Suspense fallback={<div>Loading...</div>}><SOCTriageDashboard /></Suspense>} />
            <Route path="/sbom-dashboard" element={<Suspense fallback={<div>Loading...</div>}><SBOMDashboard /></Suspense>} />

            {/* NDR / XDR / Awareness / EDR */}
            <Route path="/ndr" element={<NDRDashboard />} />
            <Route path="/xdr" element={<XDRDashboard />} />
            <Route path="/awareness-score" element={<AwarenessScoreDashboard />} />
            <Route path="/edr" element={<EDRDashboard />} />

            {/* Identity Analytics, CNAPP, Pentest Mgmt, Supply Chain Intel */}
            <Route path="/identity-analytics" element={<IdentityAnalyticsDashboard />} />
            <Route path="/cnapp" element={<CNAPPDashboard />} />
            <Route path="/pentest-mgmt" element={<PentestManagementDashboard />} />
            <Route path="/supply-chain-intel" element={<SupplyChainIntelDashboard />} />

            {/* Threat Actor Intelligence + Security Champions */}
            <Route path="/threat-actors" element={<ThreatActorDashboard />} />
            <Route path="/security-champions" element={<SecurityChampionsDashboard />} />

            {/* Security Maturity, Privacy/GDPR, Network Traffic, Container Security */}
            <Route path="/security-maturity" element={<SecurityMaturityDashboard />} />
            <Route path="/privacy-gdpr" element={<PrivacyGDPRDashboard />} />
            <Route path="/network-traffic" element={<NetworkTrafficDashboard />} />
            <Route path="/container-security" element={<ContainerSecurityDashboard />} />

            {/* Cloud Compliance + Endpoint Compliance */}
            <Route path="/cloud-compliance" element={<CloudComplianceDashboard />} />
            <Route path="/endpoint-compliance" element={<EndpointComplianceDashboard />} />

            {/* API Security Management + Vuln Intelligence */}
            <Route path="/api-security-mgmt" element={<APISecurityMgmtDashboard />} />
            <Route path="/vuln-intelligence" element={<VulnIntelligenceDashboard />} />

            {/* Firewall Policy, Network Segmentation */}
            <Route path="/firewall-policy" element={<FirewallPolicyDashboard />} />
            <Route path="/network-segmentation" element={<NetworkSegmentationDashboard />} />

            {/* MFA Management, Threat Scores, Security Budget, Compliance Gaps */}
            <Route path="/mfa-management" element={<MFAManagementDashboard />} />
            <Route path="/threat-scores" element={<ThreatScoreDashboard />} />
            <Route path="/security-budget" element={<SecurityBudgetDashboard />} />
            <Route path="/compliance-gaps" element={<ComplianceGapDashboard />} />

            {/* Legacy redirects */}
            <Route path="/core/dashboard" element={<Navigate to="/" replace />} />
            <Route path="/code/*" element={<Navigate to="/discover" replace />} />
            <Route path="/cloud/*" element={<Navigate to="/discover/cloud" replace />} />
            <Route path="/attack/*" element={<Navigate to="/validate" replace />} />
            <Route path="/protect/*" element={<Navigate to="/remediate" replace />} />
            <Route path="/evidence/*" element={<Navigate to="/comply" replace />} />

            {/* 404 — show proper Not Found page instead of silent redirect */}
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}
