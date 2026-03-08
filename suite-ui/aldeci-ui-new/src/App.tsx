import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { WorkspaceLayout } from "@/components/layout/WorkspaceLayout";
import { ErrorBoundary } from "@/components/shared/ErrorBoundary";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import NotFound from "@/pages/NotFound";

// ── Lazy-loaded pages ──

// Space 1: Mission Control
const CommandDashboard = lazy(() => import("@/pages/mission-control/CommandDashboard"));
const ExecutiveView = lazy(() => import("@/pages/mission-control/ExecutiveView"));
const SLADashboard = lazy(() => import("@/pages/mission-control/SLADashboard"));
const LiveFeed = lazy(() => import("@/pages/mission-control/LiveFeed"));
const RiskOverview = lazy(() => import("@/pages/mission-control/RiskOverview"));

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
const Integrations = lazy(() => import("@/pages/settings/Integrations"));
const UsersPage = lazy(() => import("@/pages/settings/Users"));
const Teams = lazy(() => import("@/pages/settings/Teams"));
const Marketplace = lazy(() => import("@/pages/settings/Marketplace"));
const Policies = lazy(() => import("@/pages/settings/Policies"));
const SystemHealth = lazy(() => import("@/pages/settings/SystemHealth"));
const LogViewer = lazy(() => import("@/pages/settings/LogViewer"));

// Onboarding
const OnboardingWizard = lazy(() => import("@/pages/onboarding/OnboardingWizard"));

// AI Copilot
const CopilotDashboard = lazy(() => import("@/pages/ai/CopilotDashboard"));

export default function App() {
  return (
    <ErrorBoundary>
      <Suspense fallback={<PageSkeleton />}>
        <Routes>
          {/* Onboarding */}
          <Route path="/onboarding" element={<OnboardingWizard />} />

          {/* Main workspace */}
          <Route element={<WorkspaceLayout />}>
            {/* Space 1: Mission Control */}
            <Route path="/" element={<CommandDashboard />} />
            <Route path="/mission-control" element={<CommandDashboard />} />
            <Route path="/mission-control/executive" element={<ExecutiveView />} />
            <Route path="/mission-control/sla" element={<SLADashboard />} />
            <Route path="/mission-control/live-feed" element={<LiveFeed />} />
            <Route path="/mission-control/risk" element={<RiskOverview />} />

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

            {/* Space 3: Validate */}
            <Route path="/validate" element={<MPTEConsole />} />
            <Route path="/validate/mpte" element={<MPTEConsole />} />
            <Route path="/validate/simulation" element={<AttackSimulation />} />
            <Route path="/validate/fail" element={<FAILEngine />} />
            <Route path="/validate/playbooks" element={<Playbooks />} />
            <Route path="/validate/playbooks/editor" element={<PlaybookEditor />} />
            <Route path="/validate/reachability" element={<Reachability />} />

            {/* Space 4: Remediate */}
            <Route path="/remediate" element={<RemediationCenter />} />
            <Route path="/remediate/autofix" element={<AutoFix />} />
            <Route path="/remediate/bulk" element={<BulkOperations />} />
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
            <Route path="/settings" element={<SettingsHub />} />
            <Route path="/settings/integrations" element={<Integrations />} />
            <Route path="/settings/users" element={<UsersPage />} />
            <Route path="/settings/teams" element={<Teams />} />
            <Route path="/settings/marketplace" element={<Marketplace />} />
            <Route path="/settings/policies" element={<Policies />} />
            <Route path="/settings/health" element={<SystemHealth />} />
            <Route path="/settings/logs" element={<LogViewer />} />

            {/* AI Copilot */}
            <Route path="/ai" element={<CopilotDashboard />} />

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
