import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const PostureAdvisor = lazy(() => import("@/pages/PostureAdvisor"));
const GapAnalysisDashboard = lazy(() => import("@/pages/GapAnalysisDashboard"));
const CyberResilienceDashboard = lazy(() => import("@/pages/CyberResilienceDashboard"));
const MaturityHub = lazy(() => import("@/pages/MaturityHub"));
const StrategicPostureHub = lazy(() => import("@/pages/StrategicPostureHub"));

export default function S16CtemCycles() {
  const [tab, setTab] = useState("posture-advisor");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S16 · CTEM Cycles"
        description="Continuous threat exposure management — posture, gaps, resilience, maturity and strategy"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="posture-advisor">Posture Advisor</TabsTrigger>
          <TabsTrigger value="gap-analysis">Gap Analysis</TabsTrigger>
          <TabsTrigger value="resilience">Cyber Resilience</TabsTrigger>
          <TabsTrigger value="maturity">Maturity</TabsTrigger>
          <TabsTrigger value="strategic">Strategic Posture</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="posture-advisor"><PostureAdvisor /></TabsContent>
          <TabsContent value="gap-analysis"><GapAnalysisDashboard /></TabsContent>
          <TabsContent value="resilience"><CyberResilienceDashboard /></TabsContent>
          <TabsContent value="maturity"><MaturityHub /></TabsContent>
          <TabsContent value="strategic"><StrategicPostureHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
