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
const IPReputation = lazy(() => import("@/pages/IPReputation"));
const SecretsRotation = lazy(() => import("@/pages/SecretsRotation"));
const SupplyChainSecurity = lazy(() => import("@/pages/SupplyChainSecurity"));
const DLPDashboard = lazy(() => import("@/pages/DLPDashboard"));
const APIAbuseDashboard = lazy(() => import("@/pages/APIAbuseDashboard"));
const ThreatModeling = lazy(() => import("@/pages/ThreatModeling"));
const AttackPathAnalysis = lazy(() => import("@/pages/AttackPathAnalysis"));

// Compliance Dashboard — standalone P07 view (route: /compliance)
const StandaloneComplianceDashboard = lazy(() => import("@/pages/ComplianceDashboard"));

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
            <Route path="/ip-reputation" element={<IPReputation />} />
            <Route path="/secrets-rotation" element={<SecretsRotation />} />
            <Route path="/supply-chain" element={<SupplyChainSecurity />} />
            <Route path="/zero-trust" element={<ZeroTrustDashboard />} />
            <Route path="/threat-modeling" element={<ThreatModeling />} />
            <Route path="/attack-paths" element={<AttackPathAnalysis />} />

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
