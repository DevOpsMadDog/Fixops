import { lazy, Suspense } from "react";
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
const AssetInventoryPage = lazy(() => import("@/pages/AssetInventory"));
const VulnLifecyclePage = lazy(() => import("@/pages/VulnLifecycle"));
const InsiderThreatMonitor = lazy(() => import("@/pages/InsiderThreatMonitor"));
const SecurityKPIDashboard = lazy(() => import("@/pages/SecurityKPIDashboard"));
const VendorRiskDashboard = lazy(() => import("@/pages/VendorRiskDashboard"));
const PostureAdvisor = lazy(() => import("@/pages/PostureAdvisor"));
const ZeroTrustDashboard = lazy(() => import("@/pages/ZeroTrustDashboard"));
const PatchPrioritizer = lazy(() => import("@/pages/PatchPrioritizer"));
const AutomationOrchestrationHub = lazy(() => import("@/pages/AutomationOrchestrationHub"));
const CVESearch = lazy(() => import("@/pages/CVESearch"));
const IPReputationDashboard = lazy(() => import("@/pages/IPReputationDashboard"));
const SecretsRotation = lazy(() => import("@/pages/SecretsRotation"));
const SupplyChainSecurity = lazy(() => import("@/pages/SupplyChainSecurity"));
const DLPDashboard = lazy(() => import("@/pages/DLPDashboard"));
const APIAbuseDashboard = lazy(() => import("@/pages/APIAbuseDashboard"));
const ThreatModeling = lazy(() => import("@/pages/ThreatModeling"));
const ThreatModelingHub = lazy(() => import("@/pages/ThreatModelingHub"));
const AttackPathAnalysis = lazy(() => import("@/pages/AttackPathAnalysis"));
const IncidentTimeline = lazy(() => import("@/pages/IncidentTimeline"));
const IdentityGovernance = lazy(() => import("@/pages/IdentityGovernance"));
const IdentityGovernanceHub = lazy(() => import("@/pages/IdentityGovernanceHub"));
const SecurityAwareness = lazy(() => import("@/pages/SecurityAwareness"));
const ExecutiveRiskReport = lazy(() => import("@/pages/ExecutiveRiskReport"));
const NetworkAnalysis = lazy(() => import("@/pages/NetworkAnalysis"));
const VulnHeatmap = lazy(() => import("@/pages/VulnHeatmap"));
const AuditLog = lazy(() => import("@/pages/AuditLog"));
const CSPMDashboard = lazy(() => import("@/pages/CSPMDashboard"));
const ThreatHuntingPage = lazy(() => import("@/pages/ThreatHunting"));
const PentestManagement = lazy(() => import("@/pages/PentestManagement"));
const OffensiveValidationHub = lazy(() => import("@/pages/OffensiveValidationHub"));
const DeceptionEngine = lazy(() => import("@/pages/DeceptionEngine"));
const CertificateManager = lazy(() => import("@/pages/CertificateManager"));
const FirewallAnalyzer = lazy(() => import("@/pages/FirewallAnalyzer"));
const RiskRegisterPage = lazy(() => import("@/pages/RiskRegister"));
const PlaybookLibraryPage = lazy(() => import("@/pages/PlaybookLibrary"));
const BugBounty = lazy(() => import("@/pages/BugBounty"));
const CloudIAM = lazy(() => import("@/pages/CloudIAM"));
const EmailSecurity = lazy(() => import("@/pages/EmailSecurity"));
const EmailThreatProtectionHub = lazy(() => import("@/pages/EmailThreatProtectionHub"));
const SLADashboardPage = lazy(() => import("@/pages/SLADashboard"));
const SecurityMetricsDashboard = lazy(() => import("@/pages/SecurityMetricsDashboard"));
const MobileSecurity = lazy(() => import("@/pages/MobileSecurity"));
const PasswordPolicy = lazy(() => import("@/pages/PasswordPolicy"));
const AppSecurity = lazy(() => import("@/pages/AppSecurity"));
// S10 Application Security hub — Phase 3 cluster (2026-05-02): 3 pages folded
const AppLayerSecurityHub = lazy(() => import("@/pages/AppLayerSecurityHub"));
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
const CloudPostureUnifiedHub = lazy(() => import("@/pages/CloudPostureUnifiedHub"));
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
// P3 fold 2026-05-02 — Risk Quant cluster hub (folds RiskQuantification, RiskQuantDashboard, RiskScenarioDashboard)
const RiskQuantHub = lazy(() => import("@/pages/RiskQuantHub"));
// P3 fold 2026-05-02 — Strategic Posture cluster hub (folds SecurityPostureDashboard, SecurityRoadmap, GRCAssessment)
const StrategicPostureHub = lazy(() => import("@/pages/StrategicPostureHub"));
const AttackSimulationPage = lazy(() => import("@/pages/AttackSimulation"));
const VulnerabilityScannerPage = lazy(() => import("@/pages/VulnerabilityScannerPage"));
const SecurityPostureDashboard = lazy(() => import("@/pages/SecurityPostureDashboard"));
const ExecutiveBriefing = lazy(() => import("@/pages/ExecutiveBriefing"));
const ThreatFeedDashboard = lazy(() => import("@/pages/ThreatFeedDashboard"));
const CWPPDashboard = lazy(() => import("@/pages/CWPPDashboard"));
// FOLDED 2026-05-02 → ForensicsHub#digital. Hub re-imports lazily.
// const DigitalForensicsDashboard = lazy(() => import("@/pages/DigitalForensicsDashboard"));
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

// Awareness hub (Phase 3 fold 2026-05-02 — folds 4 awareness dashboards)
const AwarenessHub = lazy(() => import("@/pages/AwarenessHub"));

// Training & Culture hub (Phase 3 fold 2026-05-02 — folds 3 training/culture dashboards)
const TrainingCultureHub = lazy(() => import("@/pages/TrainingCultureHub"));

// New Beast Mode pages — Identity Analytics, CNAPP, Pentest Mgmt, Supply Chain Intel
const IdentityAnalyticsDashboard = lazy(() => import("@/pages/IdentityAnalyticsDashboard"));
const CNAPPDashboard = lazy(() => import("@/pages/CNAPPDashboard"));
const PentestManagementDashboard = lazy(() => import("@/pages/PentestManagementDashboard"));
const SupplyChainIntelDashboard = lazy(() => import("@/pages/SupplyChainIntelDashboard"));
const SupplyChainHub = lazy(() => import("@/pages/SupplyChainHub"));

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
const NetworkMonitoringHub = lazy(() => import("@/pages/NetworkMonitoringHub"));
const SCADashboard = lazy(() => import("@/pages/SCADashboard"));
const ServiceAccountAuditDashboard = lazy(() => import("@/pages/ServiceAccountAuditDashboard"));
const ThreatIntelPlatformDashboard = lazy(() => import("@/pages/ThreatIntelPlatformDashboard"));
const AttackSurfaceDashboard = lazy(() => import("@/pages/AttackSurfaceDashboard"));

// API Security Management + Vuln Intelligence
const APISecurityMgmtDashboard = lazy(() => import("@/pages/APISecurityMgmtDashboard"));
const VulnIntelligenceDashboard = lazy(() => import("@/pages/VulnIntelligenceDashboard"));

// Phase 3 UX consolidation 2026-05-02 — Vuln Intelligence hub (S7 sub-cluster)
const VulnIntelHub = lazy(() => import("@/pages/VulnIntelHub"));
const ExternalThreatIntelHub = lazy(() => import("@/pages/ExternalThreatIntelHub"));

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

// Wave 18 domain dashboards
const AIGovernanceDashboard = lazy(() => import("@/pages/AIGovernanceDashboard"));
const DigitalIdentityDashboard = lazy(() => import("@/pages/DigitalIdentityDashboard"));
const AttackChainDashboard = lazy(() => import("@/pages/AttackChainDashboard"));
const ThreatExposureDashboard = lazy(() => import("@/pages/ThreatExposureDashboard"));
const SoftwareLicenseDashboard = lazy(() => import("@/pages/SoftwareLicenseDashboard"));
const CloudIdentityDashboard = lazy(() => import("@/pages/CloudIdentityDashboard"));
const ThreatScoreDashboard = lazy(() => import("@/pages/ThreatScoreDashboard"));
const SecurityBudgetDashboard = lazy(() => import("@/pages/SecurityBudgetDashboard"));
const ComplianceGapDashboard = lazy(() => import("@/pages/ComplianceGapDashboard"));

// Wave 19 domain dashboards
const DarkWebMonitoringDashboard = lazy(() => import("@/pages/DarkWebMonitoringDashboard"));
const ITDRDashboard = lazy(() => import("@/pages/ITDRDashboard"));
const ContainerRuntimeSecurityDashboard = lazy(() => import("@/pages/ContainerRuntimeSecurityDashboard"));
const APIDiscoveryDashboard = lazy(() => import("@/pages/APIDiscoveryDashboard"));
const SecurityChaosDashboard = lazy(() => import("@/pages/SecurityChaosDashboard"));
const IncidentMetricsDashboard = lazy(() => import("@/pages/IncidentMetricsDashboard"));

// Wave 20 domain dashboards
const ZeroDayIntelligenceDashboard = lazy(() => import("@/pages/ZeroDayIntelligenceDashboard"));
const SecurityTabletopDashboard = lazy(() => import("@/pages/SecurityTabletopDashboard"));
const BrowserSecurityDashboard = lazy(() => import("@/pages/BrowserSecurityDashboard"));
const DataExfiltrationDashboard = lazy(() => import("@/pages/DataExfiltrationDashboard"));
const PKIManagementDashboard = lazy(() => import("@/pages/PKIManagementDashboard"));
const SecurityToolInventoryDashboard = lazy(() => import("@/pages/SecurityToolInventoryDashboard"));

// Wave 21 domain dashboards
const FirmwareSecurityDashboard = lazy(() => import("@/pages/FirmwareSecurityDashboard"));
const IoTSecurityDashboard = lazy(() => import("@/pages/IoTSecurityDashboard"));
const MobileAppSecurityDashboard = lazy(() => import("@/pages/MobileAppSecurityDashboard"));
const SupplyChainAttackDashboard = lazy(() => import("@/pages/SupplyChainAttackDashboard"));
const CloudWorkloadProtectionDashboard = lazy(() => import("@/pages/CloudWorkloadProtectionDashboard"));

// Wave 22 domain dashboards
const AutonomousRemediationDashboard = lazy(() => import("@/pages/AutonomousRemediationDashboard"));
const VulnerabilityCorrelationDashboard = lazy(() => import("@/pages/VulnerabilityCorrelationDashboard"));
const PostureBenchmarkingDashboard = lazy(() => import("@/pages/PostureBenchmarkingDashboard"));
const QuantumCryptoDashboard = lazy(() => import("@/pages/QuantumCryptoDashboard"));

// Phase 3 UX consolidation: CryptoTrustHub folds CryptoKey/Certificate/CertManager/PKI/QuantumCrypto
const CryptoTrustHub = lazy(() => import("@/pages/CryptoTrustHub"));
const AIPoweredSOCDashboard = lazy(() => import("@/pages/AIPoweredSOCDashboard"));
const DeceptionAnalyticsDashboard = lazy(() => import("@/pages/DeceptionAnalyticsDashboard"));

// Wave 23 domain dashboards
const ThreatIntelAutomation = lazy(() => import("@/pages/ThreatIntelAutomation"));
const MetricsAggregatorDashboard = lazy(() => import("@/pages/MetricsAggregatorDashboard"));
const EndpointHuntingDashboard = lazy(() => import("@/pages/EndpointHuntingDashboard"));
const CloudSecurityAnalyticsDashboard = lazy(() => import("@/pages/CloudSecurityAnalyticsDashboard"));
const IdentityRiskDashboard = lazy(() => import("@/pages/IdentityRiskDashboard"));
const OTSecurityDashboard = lazy(() => import("@/pages/OTSecurityDashboard"));

// Wave 24 domain dashboards
// FOLDED 2026-05-02 → ForensicsHub uses FindingsExplorerView from FINDINGS_EXPLORER_ROUTES.
// Standalone dashboards retained on disk for git history; previously unrouted.
// const NetworkForensicsDashboard = lazy(() => import("@/pages/NetworkForensicsDashboard"));
// const MalwareAnalysisDashboard = lazy(() => import("@/pages/MalwareAnalysisDashboard"));
const ApplicationRiskDashboard = lazy(() => import("@/pages/ApplicationRiskDashboard"));
const PAGDashboard = lazy(() => import("@/pages/PAGDashboard"));
const SecurityGamificationDashboard = lazy(() => import("@/pages/SecurityGamificationDashboard"));
const VulnPrioritizationDashboard = lazy(() => import("@/pages/VulnPrioritizationDashboard"));

// Wave 25 domain dashboards
const ThreatDeceptionDashboard = lazy(() => import("@/pages/ThreatDeceptionDashboard"));
const DeceptionHub = lazy(() => import("@/pages/DeceptionHub"));
const PostureScoringDashboard = lazy(() => import("@/pages/PostureScoringDashboard"));
const CloudPostureDashboard = lazy(() => import("@/pages/CloudPostureDashboard"));
const APIThreatProtectionDashboard = lazy(() => import("@/pages/APIThreatProtectionDashboard"));
const RiskRegisterDashboard = lazy(() => import("@/pages/RiskRegisterDashboard"));
const ChangeManagementDashboard = lazy(() => import("@/pages/ChangeManagementDashboard"));

// Wave 26 domain dashboards
const ComplianceAutomationDashboard = lazy(() => import("@/pages/ComplianceAutomationDashboard"));
const ThreatAttributionDashboard = lazy(() => import("@/pages/ThreatAttributionDashboard"));
const CloudAccessSecurityDashboard = lazy(() => import("@/pages/CloudAccessSecurityDashboard"));
const BehavioralAnalyticsDashboard = lazy(() => import("@/pages/BehavioralAnalyticsDashboard"));
const VulnWorkflowDashboard = lazy(() => import("@/pages/VulnWorkflowDashboard"));
const DataPipelineDashboard = lazy(() => import("@/pages/DataPipelineDashboard"));

// Wave 27 domain dashboards
const AlertTriageDashboard = lazy(() => import("@/pages/AlertTriageDashboard"));
const AwarenessMetricsDashboard = lazy(() => import("@/pages/AwarenessMetricsDashboard"));
const PatchManagementDashboard = lazy(() => import("@/pages/PatchManagementDashboard"));
const ContainerPostureDashboard = lazy(() => import("@/pages/ContainerPostureDashboard"));
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
const PrivilegedSessionRecordingDashboard = lazy(() => import("@/pages/PrivilegedSessionRecordingDashboard"));
// Phase 3 UX consolidation — Privileged Access hub (folds MFA + PAM + Sessions, 2026-05-02)
const PrivilegedAccessHub = lazy(() => import("@/pages/PrivilegedAccessHub"));
const CloudResourceInventoryDashboard = lazy(() => import("@/pages/CloudResourceInventoryDashboard"));
const SecurityTelemetryDashboard = lazy(() => import("@/pages/SecurityTelemetryDashboard"));
const MicrosegmentationPolicyDashboard = lazy(() => import("@/pages/MicrosegmentationPolicyDashboard"));
// Phase 3 UX consolidation — Network Segmentation hub (folds Microseg + FirewallAnalyzer + FirewallPolicy, 2026-05-02)
const NetworkSegmentationHub = lazy(() => import("@/pages/NetworkSegmentationHub"));
const ThirdPartyVendorDashboard = lazy(() => import("@/pages/ThirdPartyVendorDashboard"));

// Wave 29 domain dashboards
const SaasSecurityPostureDashboard = lazy(() => import("@/pages/SaasSecurityPostureDashboard"));
const APIInventoryDashboard = lazy(() => import("@/pages/APIInventoryDashboard"));
const ThreatVectorDashboard = lazy(() => import("@/pages/ThreatVectorDashboard"));
const AwarenessCampaignDashboard = lazy(() => import("@/pages/AwarenessCampaignDashboard"));
const RiskTreatmentDashboard = lazy(() => import("@/pages/RiskTreatmentDashboard"));
const DataDiscoveryDashboard = lazy(() => import("@/pages/DataDiscoveryDashboard"));

// Wave 30 domain dashboards
const ComplianceMappingDashboard = lazy(() => import("@/pages/ComplianceMappingDashboard"));
const VulnScanDashboard = lazy(() => import("@/pages/VulnScanDashboard"));
const ThreatBriefDashboard = lazy(() => import("@/pages/ThreatBriefDashboard"));
const IncidentCommsDashboard = lazy(() => import("@/pages/IncidentCommsDashboard"));
const AssetTagsDashboard = lazy(() => import("@/pages/AssetTagsDashboard"));
const SecurityRegistryDashboard = lazy(() => import("@/pages/SecurityRegistryDashboard"));
// P3 fold 2026-05-02 — Asset metadata sub-cluster (groups/tags/criticality) hub
const AssetInventoryHub = lazy(() => import("@/pages/AssetInventoryHub"));

// Strategic engine dashboards (2026-04-25)
const AirGapBundleDashboard = lazy(() => import("@/pages/AirGapBundleDashboard"));
const OrgHierarchyDashboard = lazy(() => import("@/pages/OrgHierarchyDashboard"));
const DeepCodeAnalysisDashboard = lazy(() => import("@/pages/DeepCodeAnalysisDashboard"));
const AgentlessSnapshotDashboard = lazy(() => import("@/pages/AgentlessSnapshotDashboard"));
const SecurityQueryLanguageDashboard = lazy(() => import("@/pages/SecurityQueryLanguageDashboard"));
const ViolationLifecycleDashboard = lazy(() => import("@/pages/ViolationLifecycleDashboard"));
const ArchAwareGraphDashboard = lazy(() => import("@/pages/ArchAwareGraphDashboard"));
const IDEBackendDashboard = lazy(() => import("@/pages/IDEBackendDashboard"));

// Strategic engine dashboards — batch 2 (2026-04-25)
const UpgradePathDashboard = lazy(() => import("@/pages/UpgradePathDashboard"));
const BinaryFingerprintDashboard = lazy(() => import("@/pages/BinaryFingerprintDashboard"));
// Phase 3 UX consolidation — S21 unified hero (2026-05-02)
const UpgradePathsHub = lazy(() => import("@/pages/UpgradePathsHub"));
const SBOMProvenanceHub = lazy(() => import("@/pages/SBOMProvenanceHub"));
const CodeToRuntimeDashboard = lazy(() => import("@/pages/CodeToRuntimeDashboard"));
const PipelineBomDashboard = lazy(() => import("@/pages/PipelineBomDashboard"));
const SlsaProvenanceDashboard = lazy(() => import("@/pages/SlsaProvenanceDashboard"));
const FipsComplianceDashboard = lazy(() => import("@/pages/FipsComplianceDashboard"));
const LocalFileStoreDashboard = lazy(() => import("@/pages/LocalFileStoreDashboard"));
const DynamicRuleDSLDashboard = lazy(() => import("@/pages/DynamicRuleDSLDashboard"));

// Wave 35 domain dashboards
const ExceptionWorkflowDashboard = lazy(() => import("@/pages/ExceptionWorkflowDashboard"));
const ActorTrackingDashboard = lazy(() => import("@/pages/ActorTrackingDashboard"));
const VulnScoringDashboard = lazy(() => import("@/pages/VulnScoringDashboard"));
const SecurityBenchmarksDashboard = lazy(() => import("@/pages/SecurityBenchmarksDashboard"));
const IncidentCostsDashboard = lazy(() => import("@/pages/IncidentCostsDashboard"));
const SecurityCultureDashboard = lazy(() => import("@/pages/SecurityCultureDashboard"));

// Wave 42 domain dashboards (frontend pages for Wave 41 engines)
const PrivacyImpactDashboard = lazy(() => import("@/pages/PrivacyImpactDashboard"));
const ThreatIndicatorDashboard = lazy(() => import("@/pages/ThreatIndicatorDashboard"));
const RansomwareProtectionDashboard = lazy(() => import("@/pages/RansomwareProtectionDashboard"));
const AccessAnomalyDashboard = lazy(() => import("@/pages/AccessAnomalyDashboard"));
const TrainingEffectivenessDashboard = lazy(() => import("@/pages/TrainingEffectivenessDashboard"));
const CloudCostOptimizationDashboard = lazy(() => import("@/pages/CloudCostOptimizationDashboard"));

// Phase 3 UX consolidation hubs (2026-05-02)
const ThreatActorsHub = lazy(() => import("@/pages/ThreatActorsHub"));
const PolicyAuthoringHub = lazy(() => import("@/pages/PolicyAuthoringHub"));
const PolicyLifecycleHub = lazy(() => import("@/pages/PolicyLifecycleHub"));
const SecretsHub = lazy(() => import("@/pages/SecretsHub"));

// Sales & Marketing
const CompetitiveComparisonPage = lazy(() => import("@/pages/CompetitiveComparisonPage"));
const LandingPage = lazy(() => import("@/pages/LandingPage"));

// Security Graph — interactive force-directed security relationship canvas
const SecurityGraph = lazy(() => import("@/pages/SecurityGraph"));

// Wave 41 domain dashboards (frontend pages for Wave 40 engines)
const ArchReviewDashboard = lazy(() => import("@/pages/ArchReviewDashboard"));
const HuntingPlaybookDashboard = lazy(() => import("@/pages/HuntingPlaybookDashboard"));
const ProgramMaturityDashboard = lazy(() => import("@/pages/ProgramMaturityDashboard"));
const CloudIRDashboard = lazy(() => import("@/pages/CloudIRDashboard"));
const IdentityLifecycleDashboard = lazy(() => import("@/pages/IdentityLifecycleDashboard"));
const DependencyMappingDashboard = lazy(() => import("@/pages/DependencyMappingDashboard"));

// Wave 40 domain dashboards (frontend pages for Wave 39 engines)
const RiskQuantDashboard = lazy(() => import("@/pages/RiskQuantDashboard"));
const CyberThreatModelingDashboard = lazy(() => import("@/pages/CyberThreatModelingDashboard"));
const CapacityPlanningDashboard = lazy(() => import("@/pages/CapacityPlanningDashboard"));
const TprmExchangeDashboard = lazy(() => import("@/pages/TprmExchangeDashboard"));
const EventTimelineDashboard = lazy(() => import("@/pages/EventTimelineDashboard"));
const VulnIntelFusionDashboard = lazy(() => import("@/pages/VulnIntelFusionDashboard"));

// Wave 39 domain dashboards
const PostureReportingDashboard = lazy(() => import("@/pages/PostureReportingDashboard"));
const NetworkAnomalyDashboard = lazy(() => import("@/pages/NetworkAnomalyDashboard"));
const PrivilegedIdentityDashboard = lazy(() => import("@/pages/PrivilegedIdentityDashboard"));
const HuntingAutomationDashboard = lazy(() => import("@/pages/HuntingAutomationDashboard"));
const EvidenceVaultDashboard = lazy(() => import("@/pages/EvidenceVaultDashboard"));
const ServiceCatalogDashboard = lazy(() => import("@/pages/ServiceCatalogDashboard"));

// Wave 38 domain dashboards
const SBOMExportDashboard = lazy(() => import("@/pages/SBOMExportDashboard"));
const GapAnalysisDashboard = lazy(() => import("@/pages/GapAnalysisDashboard"));
const AlertEnrichmentDashboard = lazy(() => import("@/pages/AlertEnrichmentDashboard"));
const SecurityBaselineDashboard = lazy(() => import("@/pages/SecurityBaselineDashboard"));
const ThreatResponseDashboard = lazy(() => import("@/pages/ThreatResponseDashboard"));
const AwarenessProgramDashboard = lazy(() => import("@/pages/AwarenessProgramDashboard"));

// Wave 37 domain dashboards
const SecurityPostureMaturityDashboard = lazy(() => import("@/pages/SecurityPostureMaturityDashboard"));
const CloudSecurityFindingsDashboard = lazy(() => import("@/pages/CloudSecurityFindingsDashboard"));
const SecurityOperationsMetricsDashboard = lazy(() => import("@/pages/SecurityOperationsMetricsDashboard"));
const VulnerabilityAgeDashboard = lazy(() => import("@/pages/VulnerabilityAgeDashboard"));
const VulnLifecyclePipelineHub = lazy(() => import("@/pages/VulnLifecyclePipelineHub"));
const ThreatIntelConfidenceDashboard = lazy(() => import("@/pages/ThreatIntelConfidenceDashboard"));
const SecurityDependencyRiskDashboard = lazy(() => import("@/pages/SecurityDependencyRiskDashboard"));

// Wave 36 domain dashboards
const SecurityHealthScorecardDashboard = lazy(() => import("@/pages/SecurityHealthScorecardDashboard"));
const ComplianceCalendarDashboard = lazy(() => import("@/pages/ComplianceCalendarDashboard"));
const CyberResilienceDashboard = lazy(() => import("@/pages/CyberResilienceDashboard"));
const AssetCriticalityDashboard = lazy(() => import("@/pages/AssetCriticalityDashboard"));
const SecurityInvestmentDashboard = lazy(() => import("@/pages/SecurityInvestmentDashboard"));
const ThreatModelingPipelineDashboard = lazy(() => import("@/pages/ThreatModelingPipelineDashboard"));

// Wave 34 domain dashboards
const SecurityQuestionnaireDashboard = lazy(() => import("@/pages/SecurityQuestionnaireDashboard"));
const RiskScenarioDashboard = lazy(() => import("@/pages/RiskScenarioDashboard"));
const FeedSubscriptionsDashboard = lazy(() => import("@/pages/FeedSubscriptionsDashboard"));
// Phase 3 — Threat Intel Operations hero (combined 4-page fold 2026-05-02)
const ThreatIntelOpsHub = lazy(() => import("@/pages/ThreatIntelOpsHub"));
const AssetGroupsDashboard = lazy(() => import("@/pages/AssetGroupsDashboard"));
const SecurityFindingsDashboard = lazy(() => import("@/pages/SecurityFindingsDashboard"));
const ControlTestingDashboard = lazy(() => import("@/pages/ControlTestingDashboard"));

// Wave 32 domain dashboards
const ComplianceWorkflowDashboard = lazy(() => import("@/pages/ComplianceWorkflowDashboard"));
const ThreatLandscapeDashboard = lazy(() => import("@/pages/ThreatLandscapeDashboard"));
const PostureTrendsDashboard = lazy(() => import("@/pages/PostureTrendsDashboard"));
// Phase 3 §2.11 (Posture Metrics sub-cluster) — PostureMetricsHub at /discover/posture-metrics
const PostureMetricsHub = lazy(() => import("@/pages/PostureMetricsHub"));
const AccessGovernanceDashboard = lazy(() => import("@/pages/AccessGovernanceDashboard"));
const NetworkThreatsDashboard = lazy(() => import("@/pages/NetworkThreatsDashboard"));
const IncidentKBDashboard = lazy(() => import("@/pages/IncidentKBDashboard"));

// Wave 31 domain dashboards
const UserAccessReviewDashboard = lazy(() => import("@/pages/UserAccessReviewDashboard"));
const PostureHistoryDashboard = lazy(() => import("@/pages/PostureHistoryDashboard"));
const IncidentLessonsDashboard = lazy(() => import("@/pages/IncidentLessonsDashboard"));
// Phase 3 hub fold 2026-05-02 — IncidentMetrics + IncidentKB + IncidentLessons
const IncidentKnowledgeHub = lazy(() => import("@/pages/IncidentKnowledgeHub"));
const CloudAccountsDashboard = lazy(() => import("@/pages/CloudAccountsDashboard"));
const IntelEnrichmentDashboard = lazy(() => import("@/pages/IntelEnrichmentDashboard"));
const SecurityOKRDashboard = lazy(() => import("@/pages/SecurityOKRDashboard"));

// Connector dashboards — Prowler, ServiceNow, SIEM Output
// FOLDED into IntegrationTargetsHub at /connect/targets (2026-05-02) — kept as lazy imports for hub composition
const IntegrationTargetsHub = lazy(() => import("@/pages/IntegrationTargetsHub"));
// FOLDED into WebhookIngestionHub at /connect/webhook-ingestion (2026-05-02)
const WebhookIngestionHub = lazy(() => import("@/pages/WebhookIngestionHub"));

// Neural Brain Visualization
const BrainVisualization = lazy(() => import("@/pages/BrainVisualization"));

// Main Overview Dashboard
const MainOverviewDashboard = lazy(() => import("@/pages/MainOverviewDashboard"));

// Wave 3 — risk / dashboards / runtime (15 screens, 2026-04-26)
const BRSExecutiveDashboard = lazy(() => import("@/pages/BRSExecutiveDashboard"));
const BUDollarRiskHeatmap = lazy(() => import("@/pages/BUDollarRiskHeatmap"));
// Phase 3 UX consolidation S2 — Executive Brief Finance/Investment hub (2026-05-02)
const FinanceHub = lazy(() => import("@/pages/FinanceHub"));
const ForensicsHub = lazy(() => import("@/pages/ForensicsHub"));
const ChokePointDashboard = lazy(() => import("@/pages/ChokePointDashboard"));
const AttackPathInteractiveGraph = lazy(() => import("@/pages/AttackPathInteractiveGraph"));
const ToxicCombinationIssueView = lazy(() => import("@/pages/ToxicCombinationIssueView"));
const IssueQueue = lazy(() => import("@/pages/IssueQueue"));
const ScoreTransparencyPanel = lazy(() => import("@/pages/ScoreTransparencyPanel"));
const FactorWeightsView = lazy(() => import("@/pages/FactorWeightsView"));
const DriftTrackingPanel = lazy(() => import("@/pages/DriftTrackingPanel"));
const MaterialChangeDashboard = lazy(() => import("@/pages/MaterialChangeDashboard"));
const PRChangeRiskPanel = lazy(() => import("@/pages/PRChangeRiskPanel"));
const SBOMContinuousMonitoring = lazy(() => import("@/pages/SBOMContinuousMonitoring"));
const SnapshotFindingsView = lazy(() => import("@/pages/SnapshotFindingsView"));
const AgentlessScanStatus = lazy(() => import("@/pages/AgentlessScanStatus"));
const RuntimeCodeTrace = lazy(() => import("@/pages/RuntimeCodeTrace"));

// ── Phase 3 P0 hero pages (UX_CONSOLIDATION_PLAN_2026-04-26.md) ──
const IssuesHero = lazy(() => import("@/pages/Issues"));
const BrainHero = lazy(() => import("@/pages/Brain"));
const ComplianceHero = lazy(() => import("@/pages/Compliance"));
const AssetGraphHero = lazy(() => import("@/pages/AssetGraph"));
// ── Phase 3 P1 hero (Remediate) ──
const RemediateHero = lazy(() => import("@/pages/Remediate"));
// ── Phase 3 P0 Wave 3 hero pages (Command + Admin) ──
const CommandHero = lazy(() => import("@/pages/Command"));
const AdminHero = lazy(() => import("@/pages/Admin"));

// AI Copilot & AI Engine
const CopilotDashboard = lazy(() => import("@/pages/ai/CopilotDashboard"));
const BrainPipeline = lazy(() => import("@/pages/ai/BrainPipeline"));
const MultiLLM = lazy(() => import("@/pages/ai/MultiLLM"));
const AlgorithmicLab = lazy(() => import("@/pages/ai/AlgorithmicLab"));
const MLDashboard = lazy(() => import("@/pages/ai/MLDashboard"));
const Predictions = lazy(() => import("@/pages/ai/Predictions"));

// Frontend Wave 1 — AI / discovery / code-intel screens
const CodeSemanticExplorer = lazy(() => import("@/pages/discover/CodeSemanticExplorer"));
const CallGraphExplorer = lazy(() => import("@/pages/discover/CallGraphExplorer"));
const ReachabilityProof = lazy(() => import("@/pages/validate/ReachabilityProof"));
const GraphPerfDashboard = lazy(() => import("@/pages/discover/GraphPerfDashboard"));
const ArchitectureLayerGraph = lazy(() => import("@/pages/discover/ArchitectureLayerGraph"));
const PIIFieldInventory = lazy(() => import("@/pages/discover/PIIFieldInventory"));
const ComponentIdentityView = lazy(() => import("@/pages/discover/ComponentIdentityView"));
const ShadowAIInventory = lazy(() => import("@/pages/ai/ShadowAIInventory"));
const AIAttackPathView = lazy(() => import("@/pages/ai/AIAttackPathView"));
const MCPToolRegistry = lazy(() => import("@/pages/ai/MCPToolRegistry"));
const AIAgentsConsole = lazy(() => import("@/pages/ai/AIAgentsConsole"));
const AgentTaskQueue = lazy(() => import("@/pages/ai/AgentTaskQueue"));
const Copilot = lazy(() => import("@/pages/ai/Copilot"));
const CopilotGraphChat = lazy(() => import("@/pages/ai/CopilotGraphChat"));
const TraversalExplanationPanel = lazy(() => import("@/pages/ai/TraversalExplanationPanel"));
const AICopilotAgentsHub = lazy(() => import("@/pages/AICopilotAgentsHub"));

// Frontend Wave 4 — final cleanup wave (35 screens, 2026-04-26)
const AirGapBundleConsole = lazy(() => import("@/pages/AirGapBundleConsole"));
const OfflineFeedRegistry = lazy(() => import("@/pages/OfflineFeedRegistry"));
const OfflineUpdateStatus = lazy(() => import("@/pages/OfflineUpdateStatus"));
// Phase 3 §2.28 (Air-Gap operational sub-cluster) — AirGapHub at /connect/mcp/air-gap
const AirGapHub = lazy(() => import("@/pages/AirGapHub"));
const ClaudeSkillsRegistry = lazy(() => import("@/pages/ClaudeSkillsRegistry"));
const SkillsInstallPrompt = lazy(() => import("@/pages/SkillsInstallPrompt"));
const LocalStoreStatus = lazy(() => import("@/pages/LocalStoreStatus"));
const ComponentVersionGraph = lazy(() => import("@/pages/ComponentVersionGraph"));
const UpgradePathExplorer = lazy(() => import("@/pages/UpgradePathExplorer"));
const DBConnectionOverlay = lazy(() => import("@/pages/DBConnectionOverlay"));
const DiffModeGraphCanvas = lazy(() => import("@/pages/DiffModeGraphCanvas"));
const CopilotGraphChatRoot = lazy(() => import("@/pages/CopilotGraphChat"));
const RQLQueryBuilder = lazy(() => import("@/pages/RQLQueryBuilder"));
const SavedInvestigations = lazy(() => import("@/pages/SavedInvestigations"));
const ScopeManager = lazy(() => import("@/pages/ScopeManager"));
const DomainSeedDiscoveryWizard = lazy(() => import("@/pages/DomainSeedDiscoveryWizard"));
const SubsidiaryAttributionGraph = lazy(() => import("@/pages/SubsidiaryAttributionGraph"));
const UserTokenManager = lazy(() => import("@/pages/UserTokenManager"));
const LLMContextTierBadge = lazy(() => import("@/pages/LLMContextTierBadge"));
const LLMPreFlightEstimateModal = lazy(() => import("@/pages/LLMPreFlightEstimateModal"));
const LLMRuleContextEditor = lazy(() => import("@/pages/LLMRuleContextEditor"));
const HooksPolicyEditor = lazy(() => import("@/pages/HooksPolicyEditor"));
const HooksStatusPanel = lazy(() => import("@/pages/HooksStatusPanel"));
const ConnectorMappingUI = lazy(() => import("@/pages/ConnectorMappingUI"));
const UniversalIngestionTester = lazy(() => import("@/pages/UniversalIngestionTester"));
const PBOMViewer = lazy(() => import("@/pages/PBOMViewer"));
const PipelineAttestationGraph = lazy(() => import("@/pages/PipelineAttestationGraph"));
const SLSAAttestationSigner = lazy(() => import("@/pages/SLSAAttestationSigner"));
const WebhookEventCatalogExplorer = lazy(() => import("@/pages/WebhookEventCatalogExplorer"));
const WebhookRetryConsole = lazy(() => import("@/pages/WebhookRetryConsole"));
const CrownJewelConfigurator = lazy(() => import("@/pages/CrownJewelConfigurator"));
const OrgHierarchyExplorer = lazy(() => import("@/pages/OrgHierarchyExplorer"));
const StaleBaselineBanner = lazy(() => import("@/pages/StaleBaselineBanner"));
const TracedFlowViewer = lazy(() => import("@/pages/TracedFlowViewer"));
const ZeroSetupOnboarding = lazy(() => import("@/pages/ZeroSetupOnboarding"));

// Frontend Wave 2 — policy / waivers / rules / audit (14 screens, 2026-04-26)
const StagePolicyMatrix = lazy(() => import("@/pages/StagePolicyMatrix"));
const PolicyStageEditor = lazy(() => import("@/pages/PolicyStageEditor"));
const WaiversExplorer = lazy(() => import("@/pages/WaiversExplorer"));
const WaiverRequestModal = lazy(() => import("@/pages/WaiverRequestModal"));
const AutoWaiverRules = lazy(() => import("@/pages/AutoWaiverRules"));
const PolicyInheritanceView = lazy(() => import("@/pages/PolicyInheritanceView"));
const PolicyLibraryBrowser = lazy(() => import("@/pages/PolicyLibraryBrowser"));
const RuleDSLAuthoringStudio = lazy(() => import("@/pages/RuleDSLAuthoringStudio"));
const RuleDSLValidator = lazy(() => import("@/pages/RuleDSLValidator"));
const UnifiedRulesCatalog = lazy(() => import("@/pages/UnifiedRulesCatalog"));
const RuleTaxonomyInspector = lazy(() => import("@/pages/RuleTaxonomyInspector"));
// Phase 3 §2.26 (Rules sub-cluster) — RulesCatalogHub at /comply/rules
const RulesCatalogHub = lazy(() => import("@/pages/RulesCatalogHub"));
// Phase 3 §2.23 (Maturity sub-cluster) — MaturityHub at /comply/maturity
const MaturityHub = lazy(() => import("@/pages/MaturityHub"));
// Phase 3 §2.3 (Behavior sub-cluster) — BehaviorAnalyticsHub at /mission-control/behavior
const BehaviorAnalyticsHub = lazy(() => import("@/pages/BehaviorAnalyticsHub"));
// Phase 3 §2.23 (Privacy/Controls sub-cluster) — PrivacyComplianceHub at /comply/privacy
const PrivacyComplianceHub = lazy(() => import("@/pages/PrivacyComplianceHub"));
// Phase 3 §2.20 (Exceptions sub-cluster) — ExceptionsHub at /remediate/exceptions
const ExceptionsHub = lazy(() => import("@/pages/ExceptionsHub"));
// Phase 3 §2.22 (Incident Extensions sub-cluster) — IncidentExtensionsHub at /remediate/incidents/extensions
const IncidentExtensionsHub = lazy(() => import("@/pages/IncidentExtensionsHub"));
// Phase 3 §2.23 (Compliance Coverage / Gap sub-cluster) — ComplianceCoverageHub at /comply/coverage
const ComplianceCoverageHub = lazy(() => import("@/pages/ComplianceCoverageHub"));
// Phase 3 Data Discovery / DSPM sub-cluster — DataDiscoveryHub at /discover/dspm (2026-05-02)
const DataDiscoveryHub = lazy(() => import("@/pages/DataDiscoveryHub"));
const AuditLogExplorer = lazy(() => import("@/pages/AuditLogExplorer"));
const FIPSModeStatus = lazy(() => import("@/pages/FIPSModeStatus"));
const ViolationLifecycleTimeline = lazy(() => import("@/pages/ViolationLifecycleTimeline"));

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageSkeleton />}>
        <Routes>
          {/* Public routes */}
          <Route path="/tour" element={<Tour />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/onboarding" element={<OnboardingWizard />} />
          <Route path="/landing" element={<LandingPage />} />

          {/* Protected workspace */}
          <Route element={<RequireAuth><WorkspaceLayout /></RequireAuth>}>
            {/* Space 1: Mission Control — Phase 3 P0 Wave 3: root → CommandHero, legacy → redirects */}
            <Route path="/" element={<CommandHero />} />
            <Route path="/mission-control" element={<Navigate to="/" replace />} />
            <Route path="/mission-control/ciso" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/mission-control/executive" element={<Navigate to="/?view=executive" replace />} />
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
            {/* Wave 1 — Discover */}
            <Route path="/discover/code-semantic" element={<CodeSemanticExplorer />} />
            <Route path="/discover/callgraph" element={<CallGraphExplorer />} />
            {/* /discover/graph-perf, /discover/arch-layers → consolidated into /assets hero */}
            <Route path="/discover/pii-inventory" element={<PIIFieldInventory />} />
            <Route path="/discover/component-identity" element={<ComponentIdentityView />} />

            {/* Space 3: Validate — admin + security_analyst only (except Reachability) */}
            <Route path="/validate" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><MPTEConsole /></RequireRole>} />
            <Route path="/validate/mpte" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><MPTEConsole /></RequireRole>} />
            <Route path="/validate/simulation" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><AttackSimulation /></RequireRole>} />
            <Route path="/validate/fail" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><FAILEngine /></RequireRole>} />
            <Route path="/validate/playbooks" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><Playbooks /></RequireRole>} />
            <Route path="/validate/playbooks/editor" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><PlaybookEditor /></RequireRole>} />
            <Route path="/validate/reachability" element={<Reachability />} />
            {/* Wave 1 — Validate */}
            <Route path="/validate/reachability-proof" element={<ReachabilityProof />} />

            {/* Space 4: Remediate — /remediate is now the Phase 3 P1 RemediateHero (S19) */}
            <Route path="/remediate" element={<RemediateHero />} />
            <Route path="/remediate/autofix" element={<Navigate to="/remediate?tab=suggested" replace />} />
            <Route path="/remediate/bulk" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><BulkOperations /></RequireRole>} />
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

            {/* Settings */}
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/settings/integrations" element={<Integrations />} />
            <Route path="/settings/users" element={<RequireRole roles={["admin"]} fallback={<AccessDenied />}><UsersPage /></RequireRole>} />
            <Route path="/settings/teams" element={<RequireRole roles={["admin"]} fallback={<AccessDenied />}><Teams /></RequireRole>} />
            <Route path="/settings/marketplace" element={<Marketplace />} />
            <Route path="/settings/policies" element={<RequireRole roles={["admin", "security_analyst"]} fallback={<AccessDenied />}><Policies /></RequireRole>} />
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
            {/* P2 Wave: Waivers + Policies → Compliance hero (S20/S26) */}
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

            {/* Developer Portal */}
            <Route path="/developer" element={<DeveloperPortal />} />
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
            <Route path="/playbooks" element={<PlaybookLibraryPage />} />
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
            {/* S19 fold 2026-05-02: SOARDashboard → AutomationOrchestrationHub#soar */}
            <Route path="/soar" element={<Navigate to="/remediate/automation?tab=soar" replace />} />
            <Route path="/grc" element={<GRCDashboard />} />
            {/* S10 fold 2026-05-02: APISecurityDashboard → APISecurityHub#inventory */}
            <Route path="/discover/api-security" element={<APISecurityHub />} />
            <Route path="/api-security" element={<Navigate to="/discover/api-security?tab=inventory" replace />} />
            <Route path="/threat-correlation" element={<ThreatCorrelation />} />
            <Route path="/supply-chain-risk" element={<Navigate to="/discover/supply-chain?tab=risk" replace />} />
            {/* S11 fold 2026-05-02: CloudSecurityDashboard → CloudPostureUnifiedHub#posture */}
            <Route path="/cloud-security" element={<Navigate to="/discover/cloud-posture?tab=posture" replace />} />
            <Route path="/discover/cloud-posture" element={<CloudPostureUnifiedHub />} />
            {/* S22 fold 2026-05-02: BreachResponse → IncidentExtensionsHub#breach */}
            <Route path="/breach-response" element={<Navigate to="/remediate/incidents/extensions?tab=breach" replace />} />
            <Route path="/soc" element={<Navigate to="/?view=soc" replace />} />
            {/* P3 fold 2026-05-02: WatchlistManager → ThreatIntelOpsHub#watchlist */}
            <Route path="/watchlist" element={<Navigate to="/attack/intel/ops?tab=watchlist" replace />} />
            {/* Canonical hub route — Threat Intel Operations (combined 4-page fold) */}
            <Route path="/attack/intel/ops" element={<ThreatIntelOpsHub />} />
            <Route path="/uba" element={<Navigate to="/mission-control/behavior?tab=uba" replace />} />
            {/* P3 fold 2026-05-02 — CMDBDashboard folded into AssetInventoryHub */}
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
            {/* P3 fold 2026-05-02: RiskQuantification → RiskQuantHub#fair */}
            <Route path="/risk-quantification" element={<Navigate to="/comply/risk-quant?tab=fair" replace />} />
            {/* Canonical Risk Quant hub route */}
            <Route path="/comply/risk-quant" element={<RiskQuantHub />} />
            <Route path="/attack-simulation" element={<AttackSimulationPage />} />
            <Route path="/vuln-scanner-mgmt" element={<VulnerabilityScannerPage />} />
            {/* Phase 3 Strategic Posture hub — Comply space (2026-05-02): 3 pages folded */}
            <Route path="/comply/strategic-posture" element={<StrategicPostureHub />} />
            <Route path="/security-posture" element={<Navigate to="/comply/strategic-posture?tab=posture" replace />} />
            <Route path="/executive-briefing" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/threat-feeds" element={<Navigate to="/issues?tab=threat-feed" replace />} />
            {/* S11 fold 2026-05-02: CWPPDashboard → CloudPostureUnifiedHub#platform */}
            <Route path="/cwpp" element={<Navigate to="/discover/cloud-posture?tab=platform" replace />} />
            {/* S22 fold 2026-05-02: /digital-forensics → ForensicsHub#digital (canonical mounted later) */}
            <Route path="/grc-assessment" element={<Navigate to="/comply/strategic-posture?tab=grc" replace />} />
            <Route path="/data-governance" element={<DataGovernanceDashboard />} />
            <Route path="/security-roadmap" element={<Navigate to="/comply/strategic-posture?tab=roadmap" replace />} />
            <Route path="/threat-hunting-dashboard" element={<ThreatHuntingDashboard />} />
            <Route path="/compliance-scanner" element={<ComplianceScannerDashboard />} />
            {/* P3 fold 2026-05-02 — AssetRiskDashboard folded into AssetInventoryHub */}
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
            {/* S12 fold 2026-05-02: ThreatModelDashboard → ThreatModelingHub#models */}
            <Route path="/threat-models" element={<Navigate to="/attack/threat-modeling?tab=models" replace />} />
            {/* S12 fold 2026-05-02: ThreatModelingPipelineDashboard → ThreatModelingHub#pipeline */}
            <Route path="/threat-modeling-pipeline" element={<Navigate to="/attack/threat-modeling?tab=pipeline" replace />} />
            {/* Phase 3 §2.20 — Exceptions sub-cluster folded into ExceptionsHub at /remediate/exceptions */}
            <Route path="/remediate/exceptions" element={<ExceptionsHub />} />
            {/* S20 fold 2026-05-02: SecurityExceptionDashboard → ExceptionsHub#exceptions */}
            <Route path="/security-exceptions" element={<Navigate to="/remediate/exceptions?tab=exceptions" replace />} />
            <Route path="/regulatory-tracker" element={<RegulatoryTrackerDashboard />} />
            {/* P3 fold 2026-04-27 — SecurityScorecardDashboard folded into /compliance#scorecard */}
            <Route path="/security-scorecard" element={<Navigate to="/compliance?tab=scorecard" replace />} />
            <Route path="/ccm" element={<CCMDashboard />} />
            <Route path="/system-health" element={<SystemHealthDashboard />} />

            {/* OpenClaw + SOC Triage AI + SBOM */}
            <Route path="/openclaw" element={<Suspense fallback={<div>Loading...</div>}><OpenClawDashboard /></Suspense>} />
            <Route path="/soc-triage" element={<Navigate to="/?view=soc" replace />} />
            <Route path="/sbom-dashboard" element={<Suspense fallback={<div>Loading...</div>}><SBOMDashboard /></Suspense>} />

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
            {/* S11 fold 2026-05-02: CNAPPDashboard → CloudPostureUnifiedHub#unified */}
            <Route path="/cnapp" element={<Navigate to="/discover/cloud-posture?tab=unified" replace />} />
            {/* S13 MPTE Offensive Validation hub — folded 2026-05-02 (PentestManagementDashboard alias → pentest tab) */}
            <Route path="/pentest-mgmt" element={<Navigate to="/validate/offensive?tab=pentest" replace />} />
            <Route path="/supply-chain-intel" element={<Navigate to="/discover/supply-chain?tab=intel" replace />} />

            {/* Threat Actor Intelligence + Security Champions */}
            {/* S14 Threat Actors hub — folded 2026-05-02 (FOLDED ThreatActorDashboard) */}
            <Route path="/attack/intel/actors" element={<ThreatActorsHub />} />

            {/* S13 MPTE Offensive Validation hub — folded 2026-05-02 (canonical) */}
            <Route path="/validate/offensive" element={<OffensiveValidationHub />} />
            <Route path="/threat-actors" element={<Navigate to="/attack/intel/actors?tab=actors" replace />} />
            <Route path="/security-champions" element={<SecurityChampionsDashboard />} />

            {/* Phase 3 §2.23 — Maturity sub-cluster folded into MaturityHub at /comply/maturity */}
            <Route path="/comply/maturity" element={<MaturityHub />} />
            {/* Phase 3 §2.23 — Privacy/Controls sub-cluster folded into PrivacyComplianceHub at /comply/privacy */}
            <Route path="/comply/privacy" element={<PrivacyComplianceHub />} />
            {/* Security Maturity, Privacy/GDPR, Network Traffic, Container Security */}
            {/* S23 fold 2026-05-02: SecurityMaturityDashboard → MaturityHub#security */}
            <Route path="/security-maturity" element={<Navigate to="/comply/maturity?tab=security" replace />} />
            {/* S23 fold 2026-05-02: SecurityPostureMaturityDashboard → MaturityHub#posture */}
            <Route path="/posture-maturity" element={<Navigate to="/comply/maturity?tab=posture" replace />} />
            {/* S23 fold 2026-05-02: PrivacyGDPRDashboard → PrivacyComplianceHub#gdpr */}
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
            {/* S10 fold 2026-05-02: APISecurityMgmtDashboard → APISecurityHub#management */}
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
            {/* S10 fold 2026-05-02: APIDiscoveryDashboard → APISecurityHub#discovery */}
            <Route path="/api-discovery" element={<Navigate to="/discover/api-security?tab=discovery" replace />} />
            <Route path="/security-chaos" element={<SecurityChaosDashboard />} />
            {/* S22 fold 2026-05-02: IncidentMetricsDashboard → IncidentKnowledgeHub#metrics */}
            <Route path="/remediate/incidents/knowledge" element={<IncidentKnowledgeHub />} />
            <Route path="/incident-metrics" element={<Navigate to="/remediate/incidents/knowledge?tab=metrics" replace />} />

            {/* Wave 20 domain dashboards */}
            <Route path="/zero-day" element={<Navigate to="/attack/intel/external?tab=zeroday" replace />} />
            <Route path="/security-tabletop" element={<SecurityTabletopDashboard />} />
            {/* S10 fold 2026-05-02: BrowserSecurityDashboard → AppLayerSecurityHub#browser */}
            <Route path="/browser-security" element={<Navigate to="/discover/app-security?tab=browser" replace />} />
            <Route path="/data-exfiltration" element={<Navigate to="/discover/dspm?tab=exfiltration" replace />} />
            <Route path="/pki-management" element={<Navigate to="/discover/crypto?tab=pki" replace />} />
            <Route path="/tool-inventory" element={<Navigate to="/assets?tab=tool-inventory" replace />} />

            {/* Wave 21 domain dashboards */}
            <Route path="/firmware-security" element={<FirmwareSecurityDashboard />} />
            <Route path="/iot-security" element={<Navigate to="/assets?tab=iot-security" replace />} />
            {/* S10 fold 2026-05-02: MobileAppSecurityDashboard → AppLayerSecurityHub#mobile */}
            <Route path="/mobile-app-security" element={<Navigate to="/discover/app-security?tab=mobile" replace />} />
            <Route path="/supply-chain-attacks" element={<SupplyChainAttackDashboard />} />
            {/* S11 fold 2026-05-02: CloudWorkloadProtectionDashboard → CloudPostureUnifiedHub#workloads */}
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
            {/* S19 fold 2026-05-02: PatchManagementDashboard → AutomationOrchestrationHub#patch */}
            <Route path="/patch-management" element={<Navigate to="/remediate/automation?tab=patch" replace />} />
            <Route path="/container-posture" element={<Navigate to="/discover/container-security?tab=posture" replace />} />
            <Route path="/cyber-threat-intel" element={<CyberThreatIntelDashboard />} />
            <Route path="/digital-twin" element={<DigitalTwinDashboard />} />

            {/* Wave 28 domain dashboards */}
            <Route path="/access-requests" element={<AccessRequestManagementDashboard />} />
            <Route path="/session-recording" element={<Navigate to="/discover/privileged-access?tab=sessions" replace />} />
            {/* P3 fold 2026-05-02 — CloudResourceInventoryDashboard folded into AssetInventoryHub */}
            <Route path="/cloud-inventory" element={<Navigate to="/discover/assets/inventory?tab=cloud-res" replace />} />
            <Route path="/security-telemetry" element={<SecurityTelemetryDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/third-party-vendor" element={<ThirdPartyVendorDashboard />} />

            {/* Wave 29 domain dashboards */}
            <Route path="/sspm" element={<SaasSecurityPostureDashboard />} />
            <Route path="/api-inventory" element={<Navigate to="/asset-graph?tab=api-inventory" replace />} />
            <Route path="/threat-vectors" element={<ThreatVectorDashboard />} />
            <Route path="/awareness-campaigns" element={<Navigate to="/comply/awareness?tab=campaigns" replace />} />
            <Route path="/risk-treatment" element={<RiskTreatmentDashboard />} />
            <Route path="/data-discovery" element={<Navigate to="/discover/dspm?tab=discovery" replace />} />

            {/* Wave 30 domain dashboards */}
            <Route path="/compliance-mapping" element={<ComplianceMappingDashboard />} />
            <Route path="/vuln-scans" element={<VulnScanDashboard />} />
            {/* P3 fold 2026-05-02: ThreatBriefDashboard → ThreatIntelOpsHub#briefs */}
            <Route path="/threat-briefs" element={<Navigate to="/attack/intel/ops?tab=briefs" replace />} />
            {/* S22 fold 2026-05-02: IncidentCommsDashboard → IncidentExtensionsHub#comms */}
            <Route path="/incident-comms" element={<Navigate to="/remediate/incidents/extensions?tab=comms" replace />} />
            {/* P3 fold 2026-05-02 — AssetTagsDashboard folded into AssetInventoryHub */}
            <Route path="/asset-tags" element={<Navigate to="/discover/assets/inventory?tab=tags" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}

            {/* Security Graph — Wiz-killer interactive relationship canvas */}
            {/* /security-graph → consolidated into /assets hero */}

            {/* Wave 42 domain dashboards (pages for Wave 41 engines) */}
            {/* S23 fold 2026-05-02: PrivacyImpactDashboard → PrivacyComplianceHub#impact */}
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
            {/* S23 fold 2026-05-02: ProgramMaturityDashboard → MaturityHub#program */}
            <Route path="/program-maturity" element={<Navigate to="/comply/maturity?tab=program" replace />} />
            {/* Phase 3 §2.22 — Incident Extensions sub-cluster folded into IncidentExtensionsHub */}
            <Route path="/remediate/incidents/extensions" element={<IncidentExtensionsHub />} />
            {/* S22 fold 2026-05-02: CloudIRDashboard → IncidentExtensionsHub#cloud */}
            <Route path="/cloud-ir" element={<Navigate to="/remediate/incidents/extensions?tab=cloud" replace />} />
            <Route path="/identity-lifecycle" element={<IdentityLifecycleDashboard />} />
            {/* S21 fold 2026-05-02: was DependencyMappingDashboard */}
            <Route path="/dependency-mapping" element={<Navigate to="/remediate/upgrade?tab=dep-map" replace />} />

            {/* Wave 40 domain dashboards (pages for Wave 39 engines) */}
            {/* P3 fold 2026-05-02 — RiskQuantDashboard → RiskQuantHub#dashboard (supersedes 2026-04-27 dangling redirect) */}
            <Route path="/risk-quant" element={<Navigate to="/comply/risk-quant?tab=dashboard" replace />} />
            {/* S12 fold 2026-05-02: CyberThreatModelingDashboard → ThreatModelingHub (cyber tab) */}
            <Route path="/cyber-threat-modeling" element={<Navigate to="/attack/threat-modeling?tab=cyber" replace />} />
            <Route path="/capacity-planning" element={<CapacityPlanningDashboard />} />
            {/* P3 fold 2026-04-27 — TprmExchangeDashboard folded into /compliance#tprm */}
            <Route path="/tprm-exchange" element={<Navigate to="/compliance?tab=tprm" replace />} />
            <Route path="/event-timeline" element={<EventTimelineDashboard />} />
            {/* P3 fold 2026-04-27 — VulnIntelFusionDashboard folded into /issues#vuln-intel-fusion */}
            <Route path="/vuln-intel-fusion" element={<Navigate to="/issues?tab=vuln-intel-fusion" replace />} />

            {/* Wave 39 domain dashboards */}
            <Route path="/posture-reports" element={<Navigate to="/compliance?tab=posture-reports" replace />} />
            <Route path="/network-anomaly" element={<Navigate to="/discover/network?tab=anomaly" replace />} />
            <Route path="/privileged-identity" element={<Navigate to="/admin?tab=privileged-access" replace />} />
            <Route path="/hunting-automation" element={<Navigate to="/mission-control/hunt?tab=automation" replace />} />
            {/* P3 fold 2026-04-27 — ServiceCatalogDashboard folded into /assets#catalog */}
            <Route path="/service-catalog" element={<Navigate to="/assets?tab=catalog" replace />} />

            {/* Wave 38 domain dashboards */}
            {/* S25 fold 2026-05-02: SBOMExportDashboard → SBOMProvenanceHub#export */}
            <Route path="/sbom-export" element={<Navigate to="/comply/provenance?tab=export" replace />} />
            <Route path="/gap-analysis" element={<GapAnalysisDashboard />} />
            <Route path="/alert-enrichment" element={<Navigate to="/brain?tab=alert-enrichment" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* P3 fold 2026-05-02: ThreatResponseDashboard → ThreatIntelOpsHub#response */}
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
            {/* P3 fold 2026-05-02 — AssetCriticalityDashboard folded into AssetInventoryHub */}
            <Route path="/asset-criticality" element={<Navigate to="/discover/assets/inventory?tab=criticality" replace />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}

            {/* Wave 35 domain dashboards */}
            {/* S20 fold 2026-05-02: ExceptionWorkflowDashboard → ExceptionsHub#workflow */}
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
            {/* P3 fold 2026-05-02: RiskScenarioDashboard → RiskQuantHub#scenarios */}
            <Route path="/risk-scenarios" element={<Navigate to="/comply/risk-quant?tab=scenarios" replace />} />
            {/* P3 fold 2026-05-02: FeedSubscriptionsDashboard → ThreatIntelOpsHub#feeds */}
            <Route path="/feed-subscriptions" element={<Navigate to="/attack/intel/ops?tab=feeds" replace />} />
            {/* P3 fold 2026-05-02 — AssetGroupsDashboard folded into AssetInventoryHub */}
            <Route path="/asset-groups" element={<Navigate to="/discover/assets/inventory?tab=groups" replace />} />
            {/* Canonical hub route — Asset metadata workspace (groups/tags/criticality) */}
            <Route path="/discover/assets/inventory" element={<AssetInventoryHub />} />
            <Route path="/security-findings" element={<Navigate to="/issues" replace />} />
            {/* S23 fold 2026-05-02: ControlTestingDashboard → PrivacyComplianceHub#controls */}
            <Route path="/control-testing" element={<Navigate to="/comply/privacy?tab=controls" replace />} />

            {/* Wave 32 domain dashboards */}
            <Route path="/compliance-workflows" element={<ComplianceWorkflowDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/posture-trends" element={<Navigate to="/discover/posture-metrics?tab=trends" replace />} />
            <Route path="/access-governance" element={<Navigate to="/asset-graph?tab=access-governance" replace />} />
            <Route path="/network-threats" element={<Navigate to="/discover/network?tab=threats" replace />} />
            {/* S22 fold 2026-05-02: IncidentKBDashboard → IncidentKnowledgeHub#knowledge */}
            <Route path="/incident-kb" element={<Navigate to="/remediate/incidents/knowledge?tab=knowledge" replace />} />

            {/* Wave 31 domain dashboards */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            {/* S22 fold 2026-05-02: IncidentLessonsDashboard → IncidentKnowledgeHub#lessons */}
            <Route path="/incident-lessons" element={<Navigate to="/remediate/incidents/knowledge?tab=lessons" replace />} />
            {/* P3 fold 2026-05-02 — CloudAccountsDashboard folded into AssetInventoryHub */}
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
            {/* P3 fold 2026-05-02 — AgentlessSnapshotDashboard folded into AssetInventoryHub */}
            <Route path="/agentless-snapshot" element={<Navigate to="/discover/assets/inventory?tab=snapshot" replace />} />
            <Route path="/security-query" element={<SecurityQueryLanguageDashboard />} />
            {/* REPLACED by FindingsExplorerView Pattern-2 2026-04-27 */}
            <Route path="/arch-graph" element={<ArchAwareGraphDashboard />} />
            <Route path="/ide-backend" element={<IDEBackendDashboard />} />

            {/* Strategic engine dashboards — batch 2 (2026-04-25) */}
            {/* S21 hero (Phase 3 UX consolidation, 2026-05-02): merges 6 pages into one tabbed screen. */}
            <Route path="/remediate/upgrade" element={<UpgradePathsHub />} />
            {/* S21 fold 2026-05-02: was UpgradePathDashboard */}
            <Route path="/upgrade-path" element={<Navigate to="/remediate/upgrade?tab=resolver" replace />} />
            {/* S21 fold 2026-05-02: was BinaryFingerprintDashboard */}
            <Route path="/binary-fingerprint" element={<Navigate to="/remediate/upgrade?tab=binary-fp" replace />} />
            {/* S21 fold 2026-05-02: SecurityDependencyRiskDashboard surface restored under hub */}
            <Route path="/dependency-risk" element={<Navigate to="/remediate/upgrade?tab=dep-risk" replace />} />
            <Route path="/code-to-runtime" element={<CodeToRuntimeDashboard />} />
            {/* S25 fold 2026-05-02: PipelineBomDashboard → SBOMProvenanceHub#pipeline-bom */}
            <Route path="/pipeline-bom" element={<Navigate to="/comply/provenance?tab=pipeline-bom" replace />} />
            {/* S25 fold 2026-05-02: SlsaProvenanceDashboard → SBOMProvenanceHub#slsa */}
            <Route path="/slsa-provenance" element={<Navigate to="/comply/provenance?tab=slsa" replace />} />
            <Route path="/fips-compliance" element={<FipsComplianceDashboard />} />
            <Route path="/local-file-store" element={<LocalFileStoreDashboard />} />
            <Route path="/dynamic-rule-dsl" element={<DynamicRuleDSLDashboard />} />

            {/* ─── Phase 3 P0 hero pages (Wiz/Apiiro pattern) ─── */}
            <Route path="/issues" element={<IssuesHero />} />
            <Route path="/brain" element={<BrainHero />} />
            <Route path="/compliance" element={<ComplianceHero />} />
            <Route path="/comply" element={<ComplianceHero />} />
            <Route path="/assets" element={<AssetGraphHero />} />

            {/* ─── Phase 3 P0 Wave 3 hero pages (Command + Admin) ─── */}
            <Route path="/command" element={<CommandHero />} />
            <Route path="/admin" element={<RequireRole roles={["admin"]} fallback={<AccessDenied />}><AdminHero /></RequireRole>} />

            {/* 90-day muscle-memory redirects → Command hero */}
            <Route path="/main" element={<Navigate to="/" replace />} />
            <Route path="/overview" element={<Navigate to="/" replace />} />
            <Route path="/executive-brief" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/executive-briefing" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/executive-report" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/executive-reporting" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/mission-control" element={<Navigate to="/" replace />} />
            <Route path="/mission-control/ciso" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/mission-control/executive" element={<Navigate to="/?view=executive" replace />} />
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

            {/* P1 Wave 3 — Executive Brief redirects → Command hero executive tab (S2) */}
            <Route path="/ciso" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/ciso-report" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/bu-risk-heatmap" element={<Navigate to="/?view=executive" replace />} />
            <Route path="/executive-risk-report" element={<Navigate to="/?view=executive" replace />} />

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
            {/* S21 fold 2026-05-02: was UpgradePathExplorer */}
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
            {/* S26 fold 2026-05-02: HooksPolicyEditor + HooksStatusPanel + StagePolicyMatrix → PolicyAuthoringHub */}
            <Route path="/hooks/policy" element={<Navigate to="/comply/policies/authoring?tab=hooks-policy" replace />} />
            <Route path="/hooks/status" element={<Navigate to="/comply/policies/authoring?tab=hooks-status" replace />} />
            <Route path="/connectors/mapping" element={<Navigate to="/admin?tab=connectors" replace />} />
            <Route path="/connectors/mapping/dry-run" element={<Navigate to="/connect/webhook-ingestion?tab=dry-run" replace />} />
            {/* S25 fold 2026-05-02: PBOMViewer/PipelineAttestationGraph/SLSAAttestationSigner → SBOMProvenanceHub */}
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
            {/* S20 fold 2026-05-02: AutoWaiverRules → ExceptionsHub#auto-rules */}
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
