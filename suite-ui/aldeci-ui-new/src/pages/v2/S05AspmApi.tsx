import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const APISecurityHub = lazy(() => import("@/pages/APISecurityHub"));
const DASTDashboard = lazy(() => import("@/pages/DASTDashboard"));
const APIThreatProtectionDashboard = lazy(() => import("@/pages/APIThreatProtectionDashboard"));

export default function S05AspmApi() {
  const [tab, setTab] = useState("api-security");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S05 · ASPM API"
        description="Unified API security — inventory, DAST and threat protection"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="api-security">API Security</TabsTrigger>
          <TabsTrigger value="dast">DAST</TabsTrigger>
          <TabsTrigger value="threat-protection">Threat Protection</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="api-security"><APISecurityHub /></TabsContent>
          <TabsContent value="dast"><DASTDashboard /></TabsContent>
          <TabsContent value="threat-protection"><APIThreatProtectionDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
