import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const CloudIAM = lazy(() => import("@/pages/CloudIAM"));
const CloudIdentityDashboard = lazy(() => import("@/pages/CloudIdentityDashboard"));
const OrgHierarchyExplorer = lazy(() => import("@/pages/OrgHierarchyExplorer"));

export default function S10CloudAccounts() {
  const [tab, setTab] = useState("iam");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S10 · Cloud Accounts"
        description="Cloud IAM, identity dashboards and org hierarchy"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="iam">Cloud IAM</TabsTrigger>
          <TabsTrigger value="identity">Identity Dashboard</TabsTrigger>
          <TabsTrigger value="org">Org Hierarchy</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="iam"><CloudIAM /></TabsContent>
          <TabsContent value="identity"><CloudIdentityDashboard /></TabsContent>
          <TabsContent value="org"><OrgHierarchyExplorer /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
