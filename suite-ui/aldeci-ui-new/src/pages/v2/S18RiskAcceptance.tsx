import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const RiskAcceptance = lazy(() => import("@/pages/risk/RiskAcceptance"));
const ExceptionsHub = lazy(() => import("@/pages/ExceptionsHub"));
const WaiverRequestModal = lazy(() => import("@/pages/WaiverRequestModal"));
const RiskTreatmentDashboard = lazy(() => import("@/pages/RiskTreatmentDashboard"));

export default function S18RiskAcceptance() {
  const [tab, setTab] = useState("acceptance");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S18 · Risk Acceptance"
        description="Risk acceptance decisions, exceptions, waiver requests, and treatment plans."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="acceptance">Risk Acceptance</TabsTrigger>
          <TabsTrigger value="exceptions">Exceptions</TabsTrigger>
          <TabsTrigger value="waivers">Waiver Requests</TabsTrigger>
          <TabsTrigger value="treatment">Treatment</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="acceptance"><RiskAcceptance /></TabsContent>
          <TabsContent value="exceptions"><ExceptionsHub /></TabsContent>
          <TabsContent value="waivers"><WaiverRequestModal /></TabsContent>
          <TabsContent value="treatment"><RiskTreatmentDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
