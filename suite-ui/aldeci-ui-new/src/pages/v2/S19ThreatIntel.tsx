import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const ThreatIntelDashboard = lazy(() => import("@/pages/mission-control/ThreatIntelDashboard"));
const ThreatActorsHub = lazy(() => import("@/pages/ThreatActorsHub"));
const ExternalThreatIntelHub = lazy(() => import("@/pages/ExternalThreatIntelHub"));
const IntelEnrichmentDashboard = lazy(() => import("@/pages/IntelEnrichmentDashboard"));
const ThreatIntelOpsHub = lazy(() => import("@/pages/ThreatIntelOpsHub"));

export default function S19ThreatIntel() {
  const [tab, setTab] = useState("intel");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S19 · Threat Intelligence"
        description="Consolidated threat intelligence: dashboard, actors, external feeds, enrichment, and ops."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="intel">Intel Dashboard</TabsTrigger>
          <TabsTrigger value="actors">Threat Actors</TabsTrigger>
          <TabsTrigger value="external">External Feeds</TabsTrigger>
          <TabsTrigger value="enrichment">Enrichment</TabsTrigger>
          <TabsTrigger value="ops">Intel Ops</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="intel"><ThreatIntelDashboard /></TabsContent>
          <TabsContent value="actors"><ThreatActorsHub /></TabsContent>
          <TabsContent value="external"><ExternalThreatIntelHub /></TabsContent>
          <TabsContent value="enrichment"><IntelEnrichmentDashboard /></TabsContent>
          <TabsContent value="ops"><ThreatIntelOpsHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
