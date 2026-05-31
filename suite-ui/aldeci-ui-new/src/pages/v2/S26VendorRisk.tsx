import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const VendorRiskDashboard = lazy(() => import("@/pages/VendorRiskDashboard"));
const VendorManagement = lazy(() => import("@/pages/vendors/VendorManagement"));
const ThirdPartyVendorDashboard = lazy(() => import("@/pages/ThirdPartyVendorDashboard"));
const SaasSecurityPostureDashboard = lazy(() => import("@/pages/SaasSecurityPostureDashboard"));

export default function S26VendorRisk() {
  const [tab, setTab] = useState("risk");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S26 · Vendor Risk"
        description="Vendor risk scoring, vendor management, third-party assessment, and SaaS security posture."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="risk">Vendor Risk</TabsTrigger>
          <TabsTrigger value="management">Management</TabsTrigger>
          <TabsTrigger value="third-party">Third Party</TabsTrigger>
          <TabsTrigger value="saas">SaaS Posture</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="risk"><VendorRiskDashboard /></TabsContent>
          <TabsContent value="management"><VendorManagement /></TabsContent>
          <TabsContent value="third-party"><ThirdPartyVendorDashboard /></TabsContent>
          <TabsContent value="saas"><SaasSecurityPostureDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
