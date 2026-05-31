import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const CodeScanning = lazy(() => import("@/pages/discover/CodeScanning"));
const IaCScanning = lazy(() => import("@/pages/discover/IaCScanning"));
const SBOMInventory = lazy(() => import("@/pages/discover/SBOMInventory"));
const CorrelationEngine = lazy(() => import("@/pages/discover/CorrelationEngine"));

export default function S04AspmCode() {
  const [tab, setTab] = useState("code");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S04 · ASPM Code"
        description="Unified ASPM code-security view — scanning, IaC, SBOM and correlation"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="code">Code Scanning</TabsTrigger>
          <TabsTrigger value="iac">IaC</TabsTrigger>
          <TabsTrigger value="sbom">SBOM</TabsTrigger>
          <TabsTrigger value="correlation">Correlation</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="code"><CodeScanning /></TabsContent>
          <TabsContent value="iac"><IaCScanning /></TabsContent>
          <TabsContent value="sbom"><SBOMInventory /></TabsContent>
          <TabsContent value="correlation"><CorrelationEngine /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
