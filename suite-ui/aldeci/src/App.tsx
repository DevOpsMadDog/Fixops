import { lazy, Suspense, useEffect, useRef } from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { QueryClientProvider, QueryClient } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import MainLayout from './layouts/MainLayout';
import { ErrorBoundary } from './components/ErrorBoundary';
import ApiActivityPanel from './components/ApiActivityPanel';
import { logNavigation, logClick } from './lib/api';

// Lazy load pages for better performance
const Dashboard = lazy(() => import('./pages/Dashboard'));
const DataFabric = lazy(() => import('./pages/DataFabric'));
const IntelligenceHub = lazy(() => import('./pages/IntelligenceHub'));
const DecisionEngine = lazy(() => import('./pages/DecisionEngine'));
const AttackLab = lazy(() => import('./pages/AttackLab'));
const RemediationCenter = lazy(() => import('./pages/RemediationCenter'));
const EvidenceVault = lazy(() => import('./pages/EvidenceVault'));
const Settings = lazy(() => import('./pages/Settings'));
const Copilot = lazy(() => import('./pages/Copilot'));

// Code Suite Pages
const CodeScanning = lazy(() => import('./pages/code/CodeScanning'));
const SecretsDetection = lazy(() => import('./pages/code/SecretsDetection'));
const IaCScanning = lazy(() => import('./pages/code/IaCScanning'));
const Inventory = lazy(() => import('./pages/code/Inventory'));

// Cloud Suite Pages
const CloudPosture = lazy(() => import('./pages/cloud/CloudPosture'));
const ThreatFeeds = lazy(() => import('./pages/cloud/ThreatFeeds'));
const CorrelationEngine = lazy(() => import('./pages/cloud/CorrelationEngine'));

// Attack Suite Pages
const AttackSimulation = lazy(() => import('./pages/attack/AttackSimulation'));
const AttackPaths = lazy(() => import('./pages/attack/AttackPaths'));
const MPTEConsole = lazy(() => import('./pages/attack/MPTEConsole'));
const MicroPentest = lazy(() => import('./pages/attack/MicroPentest'));
const Reachability = lazy(() => import('./pages/attack/Reachability'));

// Protect Suite Pages
const Integrations = lazy(() => import('./pages/protect/Integrations'));
const Playbooks = lazy(() => import('./pages/protect/Playbooks'));
const BulkOperations = lazy(() => import('./pages/protect/BulkOperations'));
const Remediation = lazy(() => import('./pages/protect/Remediation'));
const Workflows = lazy(() => import('./pages/protect/Workflows'));
const Collaboration = lazy(() => import('./pages/protect/Collaboration'));

// AI Engine Pages
const MultiLLMPage = lazy(() => import('./pages/ai-engine/MultiLLMPage'));
const AlgorithmicLab = lazy(() => import('./pages/ai-engine/AlgorithmicLab'));
const Predictions = lazy(() => import('./pages/ai-engine/Predictions'));
const Policies = lazy(() => import('./pages/ai-engine/Policies'));

// Evidence Pages
const ComplianceReports = lazy(() => import('./pages/evidence/ComplianceReports'));
const EvidenceBundles = lazy(() => import('./pages/evidence/EvidenceBundles'));
const AuditLogs = lazy(() => import('./pages/evidence/AuditLogs'));
const Reports = lazy(() => import('./pages/evidence/Reports'));

// Nerve Center (The Brain)
const NerveCenter = lazy(() => import('./pages/NerveCenter'));

// Settings Pages
const Users = lazy(() => import('./pages/settings/Users'));
const Teams = lazy(() => import('./pages/settings/Teams'));
const IntegrationsSettings = lazy(() => import('./pages/settings/IntegrationsSettings'));
const Marketplace = lazy(() => import('./pages/settings/Marketplace'));
const SystemHealth = lazy(() => import('./pages/settings/SystemHealth'));
const Webhooks = lazy(() => import('./pages/settings/Webhooks'));
const OverlayConfig = lazy(() => import('./pages/settings/OverlayConfig'));

// Playbook Editor (Full)
const PlaybookEditor = lazy(() => import('./pages/protect/PlaybookEditor'));

// Log Viewer (Phase 17)
const LogViewer = lazy(() => import('./pages/settings/LogViewer'));

// Phase 9 — Dedicated pages replacing stubs + new feature pages
const AutoFixDashboard = lazy(() => import('./pages/protect/AutoFixDashboard'));
const KnowledgeGraphExplorer = lazy(() => import('./pages/core/KnowledgeGraphExplorer'));
const LiveFeedDashboard = lazy(() => import('./pages/feeds/LiveFeedDashboard'));
const MLDashboard = lazy(() => import('./pages/ai-engine/MLDashboard'));
const SBOMGeneration = lazy(() => import('./pages/code/SBOMGeneration'));
const ContainerSecurity = lazy(() => import('./pages/cloud/ContainerSecurity'));
const RuntimeProtection = lazy(() => import('./pages/cloud/RuntimeProtection'));
const SLSAProvenance = lazy(() => import('./pages/evidence/SLSAProvenance'));
const EvidenceAnalytics = lazy(() => import('./pages/evidence/EvidenceAnalytics'));
const BrainPipelineDashboard = lazy(() => import('./pages/core/BrainPipelineDashboard'));
const ExposureCaseCenter = lazy(() => import('./pages/core/ExposureCaseCenter'));
const SOC2EvidenceUI = lazy(() => import('./pages/evidence/SOC2EvidenceUI'));

// Loading fallback
const PageLoader = () => (
  <div className="flex items-center justify-center h-full">
    <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary"></div>
  </div>
);

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// ── Navigation Logger — tracks every page change ──────────────────────
function NavigationLogger() {
  const location = useLocation();
  const prevPath = useRef(location.pathname);
  useEffect(() => {
    if (prevPath.current !== location.pathname) {
      logNavigation(prevPath.current, location.pathname);
      prevPath.current = location.pathname;
    }
  }, [location.pathname]);
  return null;
}

// ── Global Click Logger — captures button/link clicks via event delegation ──
function GlobalClickLogger({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const handleClick = (e: React.MouseEvent) => {
    const el = (e.target as HTMLElement).closest('button, a, [role="button"], [data-track]');
    if (!el) return;
    const label =
      el.getAttribute('data-track') ||
      el.getAttribute('aria-label') ||
      el.textContent?.trim().slice(0, 60) ||
      el.tagName;
    logClick(label, location.pathname, {
      tag: el.tagName,
      href: el.getAttribute('href'),
    });
  };
  return <div onClick={handleClick} className="contents">{children}</div>;
}

// Animated routes wrapper
function AnimatedRoutes() {
  const location = useLocation();

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        transition={{ duration: 0.2 }}
        className="h-full"
      >
        <Suspense fallback={<PageLoader />}>
          <Routes location={location}>
            {/* Core Pages */}
            <Route path="/" element={<Dashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/nerve-center" element={<NerveCenter />} />
            <Route path="/ingest" element={<DataFabric />} />
            <Route path="/intelligence" element={<IntelligenceHub />} />
            <Route path="/decisions" element={<DecisionEngine />} />
            <Route path="/remediation" element={<RemediationCenter />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/copilot" element={<Copilot />} />
            
            {/* Code Suite */}
            <Route path="/code/code-scanning" element={<CodeScanning />} />
            <Route path="/code/secrets-detection" element={<SecretsDetection />} />
            <Route path="/code/iac-scanning" element={<IaCScanning />} />
            <Route path="/code/sbom-generation" element={<SBOMGeneration />} />
            <Route path="/code/inventory" element={<Inventory />} />
            
            {/* Cloud Suite */}
            <Route path="/cloud/cloud-posture" element={<CloudPosture />} />
            <Route path="/cloud/container-security" element={<ContainerSecurity />} />
            <Route path="/cloud/runtime-protection" element={<RuntimeProtection />} />
            <Route path="/cloud/threat-feeds" element={<ThreatFeeds />} />
            <Route path="/cloud/correlation" element={<CorrelationEngine />} />
            
            {/* Attack Suite */}
            <Route path="/attack/attack-simulation" element={<AttackSimulation />} />
            <Route path="/attack/attack-paths" element={<AttackPaths />} />
            <Route path="/attack/mpte" element={<MPTEConsole />} />
            <Route path="/attack/mpte-chat" element={<MPTEConsole />} />
            <Route path="/attack/micro-pentest" element={<MicroPentest />} />
            <Route path="/attack/reachability" element={<Reachability />} />
            <Route path="/attack/exploit-research" element={<AttackLab />} />
            
            {/* Protect Suite */}
            <Route path="/protect/remediation" element={<Remediation />} />
            <Route path="/protect/playbooks" element={<Playbooks />} />
            <Route path="/protect/playbook-editor" element={<PlaybookEditor />} />
            <Route path="/protect/bulk-operations" element={<BulkOperations />} />
            <Route path="/protect/workflows" element={<Workflows />} />
            <Route path="/protect/collaboration" element={<Collaboration />} />
            <Route path="/protect/integrations" element={<Integrations />} />
            
            {/* AI Engine */}
            <Route path="/ai-engine/multi-llm" element={<MultiLLMPage />} />
            <Route path="/ai-engine/algorithmic-lab" element={<AlgorithmicLab />} />
            <Route path="/ai-engine/predictions" element={<Predictions />} />
            <Route path="/ai-engine/policies" element={<Policies />} />
            <Route path="/ai-engine/automation" element={<DecisionEngine />} />
            <Route path="/ai-engine/policy-engine" element={<Policies />} />
            
            {/* Evidence */}
            <Route path="/evidence/bundles" element={<EvidenceBundles />} />
            <Route path="/evidence/slsa-provenance" element={<SLSAProvenance />} />
            <Route path="/evidence/compliance" element={<ComplianceReports />} />
            <Route path="/evidence/audit-trail" element={<AuditLogs />} />
            <Route path="/evidence/audit-logs" element={<AuditLogs />} />
            <Route path="/evidence/reports" element={<Reports />} />
            <Route path="/evidence/analytics" element={<EvidenceAnalytics />} />
            
            {/* Settings */}
            <Route path="/settings/users" element={<Users />} />
            <Route path="/settings/teams" element={<Teams />} />
            <Route path="/settings/integrations" element={<IntegrationsSettings />} />
            <Route path="/settings/marketplace" element={<Marketplace />} />
            <Route path="/settings/system-health" element={<SystemHealth />} />
            <Route path="/settings/webhooks" element={<Webhooks />} />
            <Route path="/settings/overlay-config" element={<OverlayConfig />} />
            <Route path="/settings/logs" element={<LogViewer />} />
            
            {/* Phase 9 — New feature routes */}
            <Route path="/protect/autofix" element={<AutoFixDashboard />} />
            <Route path="/core/knowledge-graph" element={<KnowledgeGraphExplorer />} />
            <Route path="/feeds/live" element={<LiveFeedDashboard />} />
            <Route path="/ai-engine/ml-dashboard" element={<MLDashboard />} />
            <Route path="/core/brain-pipeline" element={<BrainPipelineDashboard />} />
            <Route path="/core/exposure-cases" element={<ExposureCaseCenter />} />
            <Route path="/evidence/soc2" element={<SOC2EvidenceUI />} />

            {/* Legacy routes for backwards compatibility */}
            <Route path="/data-fabric" element={<DataFabric />} />
            <Route path="/intelligence-hub" element={<IntelligenceHub />} />
            <Route path="/decision-engine" element={<DecisionEngine />} />
            <Route path="/attack-lab" element={<AttackLab />} />
            <Route path="/remediation-center" element={<RemediationCenter />} />
            <Route path="/evidence-vault" element={<EvidenceVault />} />
            
            {/* Fallback */}
            <Route path="*" element={<Dashboard />} />
          </Routes>
        </Suspense>
      </motion.div>
    </AnimatePresence>
  );
}

function App() {
  return (
    <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <NavigationLogger />
        <GlobalClickLogger>
        <MainLayout>
          <ErrorBoundary>
            <AnimatedRoutes />
          </ErrorBoundary>
        </MainLayout>
        </GlobalClickLogger>
      </BrowserRouter>
      <Toaster
        position="bottom-right"
        theme="dark"
        toastOptions={{
          style: {
            background: 'hsl(222.2 84% 4.9%)',
            border: '1px solid hsl(217.2 32.6% 17.5%)',
            color: 'hsl(210 40% 98%)',
          },
        }}
      />
      <ApiActivityPanel />
    </QueryClientProvider>
    </ErrorBoundary>
  );
}

export default App;
