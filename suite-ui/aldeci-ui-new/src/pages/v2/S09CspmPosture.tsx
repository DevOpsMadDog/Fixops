import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const CloudPosture = lazy(() => import("@/pages/discover/CloudPosture"));
const CloudPostureUnifiedHub = lazy(() => import("@/pages/CloudPostureUnifiedHub"));
const CloudAccessSecurityDashboard = lazy(() => import("@/pages/CloudAccessSecurityDashboard"));
const CloudSecurityAnalyticsDashboard = lazy(() => import("@/pages/CloudSecurityAnalyticsDashboard"));
const SystemHealthDashboard = lazy(() => import("@/pages/SystemHealthDashboard"));

export default function S09CspmPosture() {
  const [tab, setTab] = useState("posture");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S09 · CSPM Posture"
        description="Cloud security posture — unified hub, access security and analytics"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="posture">Cloud Posture</TabsTrigger>
          <TabsTrigger value="unified">Unified Hub</TabsTrigger>
          <TabsTrigger value="access">Access Security</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="it-ops">IT Ops</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="posture"><CloudPosture /></TabsContent>
          <TabsContent value="unified"><CloudPostureUnifiedHub /></TabsContent>
          <TabsContent value="access"><CloudAccessSecurityDashboard /></TabsContent>
          <TabsContent value="analytics"><CloudSecurityAnalyticsDashboard /></TabsContent>
          <TabsContent value="it-ops"><SystemHealthDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
