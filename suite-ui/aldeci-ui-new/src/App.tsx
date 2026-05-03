// App.tsx — Phase 1 skeleton (31 screens)
// Generated 2026-05-03 | consolidation/phase-1-skeleton
// Legacy routes preserved in LegacyRoutes.tsx

import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { WorkspaceLayout } from "@/components/layout/WorkspaceLayout";
import { ErrorBoundary } from "@/components/shared/ErrorBoundary";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import NotFound from "@/pages/NotFound";
import { RequireAuth } from "@/lib/auth";

// ── v2 screens (Phase 1 stubs) ──
const S01LoginAuth = lazy(() => import("@/pages/v2/S01LoginAndAuth"));
const S02OnboardingWizard = lazy(() => import("@/pages/v2/S02OnboardingWizard"));
const S03MissionControl = lazy(() => import("@/pages/v2/S03MissionControl"));
const S04ASPMCode = lazy(() => import("@/pages/v2/S04ASPMCode"));
const S05ASPMAPISecurity = lazy(() => import("@/pages/v2/S05ASPMAPISecurity"));
const S06ASPMAppRuntime = lazy(() => import("@/pages/v2/S06ASPMAppRuntime"));
const S07SoftwareSupplyChain = lazy(() => import("@/pages/v2/S07SoftwareSupplyChain"));
const S08SecretsAndCrypto = lazy(() => import("@/pages/v2/S08SecretsAndCrypto"));
const S09CSPMPosture = lazy(() => import("@/pages/v2/S09CSPMPosture"));
const S10CloudAccounts = lazy(() => import("@/pages/v2/S10CloudAccounts"));
const S11CloudWorkloads = lazy(() => import("@/pages/v2/S11CloudWorkloads"));
const S12NetworkSecurity = lazy(() => import("@/pages/v2/S12NetworkSecurity"));
const S13IdentityAndAccess = lazy(() => import("@/pages/v2/S13IdentityAndAccess"));
const S14AttackSurface = lazy(() => import("@/pages/v2/S14AttackSurface"));
const S15TrustGraph = lazy(() => import("@/pages/v2/S15TrustGraph"));
const S16CTEMCycles = lazy(() => import("@/pages/v2/S16CTEMCycles"));
const S17FindingsExplorer = lazy(() => import("@/pages/v2/S17FindingsExplorer"));
const S18RiskAcceptanceAndWaivers = lazy(() => import("@/pages/v2/S18RiskAcceptanceAndWaivers"));
const S19ThreatIntelligence = lazy(() => import("@/pages/v2/S19ThreatIntelligence"));
const S20DetectionsAndAlerts = lazy(() => import("@/pages/v2/S20DetectionsAndAlerts"));
const S21IncidentsAndResponse = lazy(() => import("@/pages/v2/S21IncidentsAndResponse"));
const S22RansomwareAndMalware = lazy(() => import("@/pages/v2/S22RansomwareAndMalware"));
const S23DataSecurity = lazy(() => import("@/pages/v2/S23DataSecurity"));
const S24Privacy = lazy(() => import("@/pages/v2/S24Privacy"));
const S25ComplianceAndEvidence = lazy(() => import("@/pages/v2/S25ComplianceAndEvidence"));
const S26VendorAndSaaSRisk = lazy(() => import("@/pages/v2/S26VendorAndSaaSRisk"));
const S27IoTOTAndEndpoints = lazy(() => import("@/pages/v2/S27IoTOTAndEndpoints"));
const S28AISecurity = lazy(() => import("@/pages/v2/S28AISecurity"));
const S29Integrations = lazy(() => import("@/pages/v2/S29Integrations"));
const S30CollaborationAndAwareness = lazy(() => import("@/pages/v2/S30CollaborationAndAwareness"));
const S31SettingsAndAdmin = lazy(() => import("@/pages/v2/S31SettingsAndAdmin"));

const wrap = (Component: React.ComponentType) => (
  <ErrorBoundary>
    <Suspense fallback={<PageSkeleton />}>
      <Component />
    </Suspense>
  </ErrorBoundary>
);

export default function App() {
  return (
    <Routes>
      {/* Public */}
      <Route path="/login" element={wrap(S01LoginAuth)} />

      {/* Authenticated */}
      <Route element={<RequireAuth />}>
        <Route path="/onboarding" element={wrap(S02OnboardingWizard)} />
        <Route element={<WorkspaceLayout />}>
          <Route index element={<Navigate to="/" replace />} />
          <Route path="/" element={wrap(S03MissionControl)} />
          <Route path="/aspm/code" element={wrap(S04ASPMCode)} />
          <Route path="/aspm/api" element={wrap(S05ASPMAPISecurity)} />
          <Route path="/aspm/runtime" element={wrap(S06ASPMAppRuntime)} />
          <Route path="/aspm/supply-chain" element={wrap(S07SoftwareSupplyChain)} />
          <Route path="/aspm/secrets" element={wrap(S08SecretsAndCrypto)} />
          <Route path="/cspm/posture" element={wrap(S09CSPMPosture)} />
          <Route path="/cloud/accounts" element={wrap(S10CloudAccounts)} />
          <Route path="/cloud/workloads" element={wrap(S11CloudWorkloads)} />
          <Route path="/cloud/network" element={wrap(S12NetworkSecurity)} />
          <Route path="/identity" element={wrap(S13IdentityAndAccess)} />
          <Route path="/exposure/asm" element={wrap(S14AttackSurface)} />
          <Route path="/exposure/trustgraph" element={wrap(S15TrustGraph)} />
          <Route path="/exposure/ctem" element={wrap(S16CTEMCycles)} />
          <Route path="/findings" element={wrap(S17FindingsExplorer)} />
          <Route path="/findings/waivers" element={wrap(S18RiskAcceptanceAndWaivers)} />
          <Route path="/threats/intel" element={wrap(S19ThreatIntelligence)} />
          <Route path="/threats/detections" element={wrap(S20DetectionsAndAlerts)} />
          <Route path="/threats/incidents" element={wrap(S21IncidentsAndResponse)} />
          <Route path="/threats/malware" element={wrap(S22RansomwareAndMalware)} />
          <Route path="/data/security" element={wrap(S23DataSecurity)} />
          <Route path="/data/privacy" element={wrap(S24Privacy)} />
          <Route path="/compliance" element={wrap(S25ComplianceAndEvidence)} />
          <Route path="/risk/vendor" element={wrap(S26VendorAndSaaSRisk)} />
          <Route path="/risk/endpoints" element={wrap(S27IoTOTAndEndpoints)} />
          <Route path="/risk/ai-security" element={wrap(S28AISecurity)} />
          <Route path="/platform/integrations" element={wrap(S29Integrations)} />
          <Route path="/platform/collab" element={wrap(S30CollaborationAndAwareness)} />
          <Route path="/admin" element={wrap(S31SettingsAndAdmin)} />
        </Route>
      </Route>

      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
