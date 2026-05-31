import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const DPOPrivacyHub = lazy(() => import("@/pages/DPOPrivacyHub"));
const PrivacyComplianceHub = lazy(() => import("@/pages/PrivacyComplianceHub"));
const DataGovernanceDashboard = lazy(() => import("@/pages/DataGovernanceDashboard"));

export default function S24Privacy() {
  const [tab, setTab] = useState("dpo");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S24 · Privacy"
        description="DPO privacy operations, privacy compliance monitoring, and data governance."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="dpo">DPO Hub</TabsTrigger>
          <TabsTrigger value="compliance">Privacy Compliance</TabsTrigger>
          <TabsTrigger value="governance">Data Governance</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="dpo"><DPOPrivacyHub /></TabsContent>
          <TabsContent value="compliance"><PrivacyComplianceHub /></TabsContent>
          <TabsContent value="governance"><DataGovernanceDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
