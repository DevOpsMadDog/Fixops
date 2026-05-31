import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const OTSecurityDashboard = lazy(() => import("@/pages/OTSecurityDashboard"));
const FirmwareSecurityDashboard = lazy(() => import("@/pages/FirmwareSecurityDashboard"));
const MobileSecurity = lazy(() => import("@/pages/MobileSecurity"));
const EndpointHuntingDashboard = lazy(() => import("@/pages/EndpointHuntingDashboard"));

export default function S27IotOtEndpoints() {
  const [tab, setTab] = useState("ot");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S27 · IoT / OT / Endpoints"
        description="OT security, firmware analysis, mobile security, and endpoint threat hunting."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="ot">OT Security</TabsTrigger>
          <TabsTrigger value="firmware">Firmware</TabsTrigger>
          <TabsTrigger value="mobile">Mobile</TabsTrigger>
          <TabsTrigger value="endpoint">Endpoint Hunting</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="ot"><OTSecurityDashboard /></TabsContent>
          <TabsContent value="firmware"><FirmwareSecurityDashboard /></TabsContent>
          <TabsContent value="mobile"><MobileSecurity /></TabsContent>
          <TabsContent value="endpoint"><EndpointHuntingDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
