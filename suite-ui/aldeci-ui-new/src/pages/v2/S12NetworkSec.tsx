import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const NetworkAnalysis = lazy(() => import("@/pages/NetworkAnalysis"));
const NetworkTopology = lazy(() => import("@/pages/NetworkTopology"));
const NetworkMonitoringHub = lazy(() => import("@/pages/NetworkMonitoringHub"));
const NetworkTrafficDashboard = lazy(() => import("@/pages/NetworkTrafficDashboard"));
const NDRDashboard = lazy(() => import("@/pages/NDRDashboard"));
const NetworkSegmentationHub = lazy(() => import("@/pages/NetworkSegmentationHub"));

export default function S12NetworkSec() {
  const [tab, setTab] = useState("analysis");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S12 · Network Security"
        description="Network analysis, topology, monitoring, traffic, NDR and segmentation"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="analysis">Analysis</TabsTrigger>
          <TabsTrigger value="topology">Topology</TabsTrigger>
          <TabsTrigger value="monitoring">Monitoring</TabsTrigger>
          <TabsTrigger value="traffic">Traffic</TabsTrigger>
          <TabsTrigger value="ndr">NDR</TabsTrigger>
          <TabsTrigger value="segmentation">Segmentation</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="analysis"><NetworkAnalysis /></TabsContent>
          <TabsContent value="topology"><NetworkTopology /></TabsContent>
          <TabsContent value="monitoring"><NetworkMonitoringHub /></TabsContent>
          <TabsContent value="traffic"><NetworkTrafficDashboard /></TabsContent>
          <TabsContent value="ndr"><NDRDashboard /></TabsContent>
          <TabsContent value="segmentation"><NetworkSegmentationHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
