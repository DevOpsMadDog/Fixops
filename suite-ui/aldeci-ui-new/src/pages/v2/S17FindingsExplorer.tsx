import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const FindingsExplorer = lazy(() => import("@/pages/findings/FindingsExplorer"));
const VulnRiskQueue = lazy(() => import("@/pages/VulnRiskQueue"));
const ExceptionsHub = lazy(() => import("@/pages/ExceptionsHub"));
const RQLQueryBuilder = lazy(() => import("@/pages/RQLQueryBuilder"));
const SavedInvestigations = lazy(() => import("@/pages/SavedInvestigations"));

export default function S17FindingsExplorer() {
  const [tab, setTab] = useState("findings");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S17 · Findings Explorer"
        description="Unified findings triage, vulnerability queue, exceptions, RQL queries, and saved investigations."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="vuln-queue">Vuln Queue</TabsTrigger>
          <TabsTrigger value="exceptions">Exceptions</TabsTrigger>
          <TabsTrigger value="rql">RQL Builder</TabsTrigger>
          <TabsTrigger value="saved">Saved Investigations</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="findings"><FindingsExplorer /></TabsContent>
          <TabsContent value="vuln-queue"><VulnRiskQueue /></TabsContent>
          <TabsContent value="exceptions"><ExceptionsHub /></TabsContent>
          <TabsContent value="rql"><RQLQueryBuilder /></TabsContent>
          <TabsContent value="saved"><SavedInvestigations /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
