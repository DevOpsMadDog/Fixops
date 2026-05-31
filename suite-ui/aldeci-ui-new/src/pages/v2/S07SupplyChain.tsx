import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const SBOMManagement = lazy(() => import("@/pages/sbom/SBOMManagement"));
const SBOMProvenanceHub = lazy(() => import("@/pages/SBOMProvenanceHub"));
const SupplyChainHub = lazy(() => import("@/pages/SupplyChainHub"));

export default function S07SupplyChain() {
  const [tab, setTab] = useState("sbom-mgmt");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S07 · Supply Chain"
        description="SBOM management, provenance tracking and supply-chain risk"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="sbom-mgmt">SBOM Management</TabsTrigger>
          <TabsTrigger value="provenance">Provenance</TabsTrigger>
          <TabsTrigger value="supply-chain">Supply Chain</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="sbom-mgmt"><SBOMManagement /></TabsContent>
          <TabsContent value="provenance"><SBOMProvenanceHub /></TabsContent>
          <TabsContent value="supply-chain"><SupplyChainHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
