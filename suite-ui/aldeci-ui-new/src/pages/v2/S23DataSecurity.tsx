import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const DataDiscoveryHub = lazy(() => import("@/pages/DataDiscoveryHub"));
const DataGovernanceDashboard = lazy(() => import("@/pages/DataGovernanceDashboard"));
const DLPDashboard = lazy(() => import("@/pages/DLPDashboard"));
const PrivacyComplianceHub = lazy(() => import("@/pages/PrivacyComplianceHub"));

export default function S23DataSecurity() {
  const [tab, setTab] = useState("discovery");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S23 · Data Security"
        description="Data discovery, governance, DLP controls, and privacy compliance."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="discovery">Data Discovery</TabsTrigger>
          <TabsTrigger value="governance">Governance</TabsTrigger>
          <TabsTrigger value="dlp">DLP</TabsTrigger>
          <TabsTrigger value="privacy">Privacy Compliance</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="discovery"><DataDiscoveryHub /></TabsContent>
          <TabsContent value="governance"><DataGovernanceDashboard /></TabsContent>
          <TabsContent value="dlp"><DLPDashboard /></TabsContent>
          <TabsContent value="privacy"><PrivacyComplianceHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
