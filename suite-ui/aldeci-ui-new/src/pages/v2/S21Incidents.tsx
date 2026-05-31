import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const IncidentResponse = lazy(() => import("@/pages/incidents/IncidentResponse"));
const IncidentTimeline = lazy(() => import("@/pages/IncidentTimeline"));
const ForensicsHub = lazy(() => import("@/pages/ForensicsHub"));
const IRPlaybookDashboard = lazy(() => import("@/pages/IRPlaybookDashboard"));
const AutomationOrchestrationHub = lazy(() => import("@/pages/AutomationOrchestrationHub"));

export default function S21Incidents() {
  const [tab, setTab] = useState("response");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S21 · Incidents"
        description="Incident response, timeline, forensics, IR playbooks, and automation orchestration."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="response">Incident Response</TabsTrigger>
          <TabsTrigger value="timeline">Timeline</TabsTrigger>
          <TabsTrigger value="forensics">Forensics</TabsTrigger>
          <TabsTrigger value="playbooks">IR Playbooks</TabsTrigger>
          <TabsTrigger value="automation">Automation</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="response"><IncidentResponse /></TabsContent>
          <TabsContent value="timeline"><IncidentTimeline /></TabsContent>
          <TabsContent value="forensics"><ForensicsHub /></TabsContent>
          <TabsContent value="playbooks"><IRPlaybookDashboard /></TabsContent>
          <TabsContent value="automation"><AutomationOrchestrationHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
