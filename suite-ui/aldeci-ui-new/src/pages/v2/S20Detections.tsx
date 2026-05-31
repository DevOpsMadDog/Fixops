import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const BehaviorAnalyticsHub = lazy(() => import("@/pages/BehaviorAnalyticsHub"));
const DetectAndRespondHub = lazy(() => import("@/pages/DetectAndRespondHub"));
const SecurityTelemetryDashboard = lazy(() => import("@/pages/SecurityTelemetryDashboard"));
const EventTimelineDashboard = lazy(() => import("@/pages/EventTimelineDashboard"));

export default function S20Detections() {
  const [tab, setTab] = useState("behavior");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S20 · Detections"
        description="Behavior analytics, detect-and-respond, security telemetry, and event timeline."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="behavior">Behavior Analytics</TabsTrigger>
          <TabsTrigger value="detect">Detect &amp; Respond</TabsTrigger>
          <TabsTrigger value="telemetry">Telemetry</TabsTrigger>
          <TabsTrigger value="timeline">Event Timeline</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="behavior"><BehaviorAnalyticsHub /></TabsContent>
          <TabsContent value="detect"><DetectAndRespondHub /></TabsContent>
          <TabsContent value="telemetry"><SecurityTelemetryDashboard /></TabsContent>
          <TabsContent value="timeline"><EventTimelineDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
