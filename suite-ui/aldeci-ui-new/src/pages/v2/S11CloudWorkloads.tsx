import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const ContainerSecurity = lazy(() => import("@/pages/discover/ContainerSecurity"));
const ContainerRegistryDashboard = lazy(() => import("@/pages/ContainerRegistryDashboard"));
const FirmwareSecurityDashboard = lazy(() => import("@/pages/FirmwareSecurityDashboard"));
const OTSecurityDashboard = lazy(() => import("@/pages/OTSecurityDashboard"));

export default function S11CloudWorkloads() {
  const [tab, setTab] = useState("containers");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S11 · Cloud Workloads"
        description="Container security, registry, firmware and OT security"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="containers">Container Security</TabsTrigger>
          <TabsTrigger value="registry">Container Registry</TabsTrigger>
          <TabsTrigger value="firmware">Firmware</TabsTrigger>
          <TabsTrigger value="ot">OT Security</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="containers"><ContainerSecurity /></TabsContent>
          <TabsContent value="registry"><ContainerRegistryDashboard /></TabsContent>
          <TabsContent value="firmware"><FirmwareSecurityDashboard /></TabsContent>
          <TabsContent value="ot"><OTSecurityDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
