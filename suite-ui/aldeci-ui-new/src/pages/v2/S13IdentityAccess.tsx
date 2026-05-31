import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const IdentityGovernanceHub = lazy(() => import("@/pages/IdentityGovernanceHub"));
const IdentityLifecycleDashboard = lazy(() => import("@/pages/IdentityLifecycleDashboard"));
const IdentityRiskDashboard = lazy(() => import("@/pages/IdentityRiskDashboard"));
const PrivilegedAccessHub = lazy(() => import("@/pages/PrivilegedAccessHub"));
const CloudIAM = lazy(() => import("@/pages/CloudIAM"));

export default function S13IdentityAccess() {
  const [tab, setTab] = useState("governance");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S13 · Identity & Access"
        description="Identity governance, lifecycle, risk, privileged access and cloud IAM"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="governance">Governance</TabsTrigger>
          <TabsTrigger value="lifecycle">Lifecycle</TabsTrigger>
          <TabsTrigger value="risk">Identity Risk</TabsTrigger>
          <TabsTrigger value="privileged">Privileged Access</TabsTrigger>
          <TabsTrigger value="iam">Cloud IAM</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="governance"><IdentityGovernanceHub /></TabsContent>
          <TabsContent value="lifecycle"><IdentityLifecycleDashboard /></TabsContent>
          <TabsContent value="risk"><IdentityRiskDashboard /></TabsContent>
          <TabsContent value="privileged"><PrivilegedAccessHub /></TabsContent>
          <TabsContent value="iam"><CloudIAM /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
