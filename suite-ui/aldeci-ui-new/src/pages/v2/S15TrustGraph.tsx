import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const BrainVisualization = lazy(() => import("@/pages/BrainVisualization"));
const ArchAwareGraphDashboard = lazy(() => import("@/pages/ArchAwareGraphDashboard"));
// CopilotGraphChat lives at ai/CopilotGraphChat — use that canonical path
const CopilotGraphChat = lazy(() => import("@/pages/ai/CopilotGraphChat"));
const CorrelationEngine = lazy(() => import("@/pages/discover/CorrelationEngine"));

export default function S15TrustGraph() {
  const [tab, setTab] = useState("brain");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S15 · TrustGraph"
        description="Brain visualization, arch-aware graph, copilot chat and correlation engine"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="brain">Brain Visualization</TabsTrigger>
          <TabsTrigger value="arch-graph">Arch-Aware Graph</TabsTrigger>
          <TabsTrigger value="copilot">Copilot Chat</TabsTrigger>
          <TabsTrigger value="correlation">Correlation</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="brain"><BrainVisualization /></TabsContent>
          <TabsContent value="arch-graph"><ArchAwareGraphDashboard /></TabsContent>
          <TabsContent value="copilot"><CopilotGraphChat /></TabsContent>
          <TabsContent value="correlation"><CorrelationEngine /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
