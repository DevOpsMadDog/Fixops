import { lazy, Suspense } from 'react';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { QueryClientProvider, QueryClient } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import MainLayout from './layouts/MainLayout';

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
const PentAGIConsole = lazy(() => import('./pages/attack/PentAGIConsole'));
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

// Settings Pages
const Users = lazy(() => import('./pages/settings/Users'));
const Teams = lazy(() => import('./pages/settings/Teams'));
const IntegrationsSettings = lazy(() => import('./pages/settings/IntegrationsSettings'));
const Marketplace = lazy(() => import('./pages/settings/Marketplace'));
const SystemHealth = lazy(() => import('./pages/settings/SystemHealth'));

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
            <Route path="/code/sbom-generation" element={<DataFabric />} />
            <Route path="/code/inventory" element={<Inventory />} />
            
            {/* Cloud Suite */}
            <Route path="/cloud/cloud-posture" element={<CloudPosture />} />
            <Route path="/cloud/container-security" element={<IntelligenceHub />} />
            <Route path="/cloud/runtime-protection" element={<IntelligenceHub />} />
            <Route path="/cloud/threat-feeds" element={<ThreatFeeds />} />
            <Route path="/cloud/correlation" element={<CorrelationEngine />} />
            
            {/* Attack Suite */}
            <Route path="/attack/attack-simulation" element={<AttackSimulation />} />
            <Route path="/attack/attack-paths" element={<AttackPaths />} />
            <Route path="/attack/pentagi" element={<PentAGIConsole />} />
            <Route path="/attack/pentagi-chat" element={<PentAGIConsole />} />
            <Route path="/attack/micro-pentest" element={<MicroPentest />} />
            <Route path="/attack/reachability" element={<Reachability />} />
            <Route path="/attack/exploit-research" element={<AttackLab />} />
            
            {/* Protect Suite */}
            <Route path="/protect/remediation" element={<Remediation />} />
            <Route path="/protect/playbooks" element={<Playbooks />} />
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
            <Route path="/evidence/slsa-provenance" element={<EvidenceVault />} />
            <Route path="/evidence/compliance" element={<ComplianceReports />} />
            <Route path="/evidence/audit-trail" element={<AuditLogs />} />
            <Route path="/evidence/audit-logs" element={<AuditLogs />} />
            <Route path="/evidence/reports" element={<Reports />} />
            <Route path="/evidence/analytics" element={<EvidenceVault />} />
            
            {/* Settings */}
            <Route path="/settings/users" element={<Users />} />
            <Route path="/settings/teams" element={<Teams />} />
            <Route path="/settings/integrations" element={<IntegrationsSettings />} />
            <Route path="/settings/marketplace" element={<Marketplace />} />
            <Route path="/settings/system-health" element={<SystemHealth />} />
            
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
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <MainLayout>
          <AnimatedRoutes />
        </MainLayout>
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
    </QueryClientProvider>
  );
}

export default App;
