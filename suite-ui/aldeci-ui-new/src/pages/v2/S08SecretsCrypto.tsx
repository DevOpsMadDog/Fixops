import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const SecretsHub = lazy(() => import("@/pages/SecretsHub"));
const CryptoTrustHub = lazy(() => import("@/pages/CryptoTrustHub"));
const PIIFieldInventory = lazy(() => import("@/pages/discover/PIIFieldInventory"));

export default function S08SecretsCrypto() {
  const [tab, setTab] = useState("secrets");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S08 · Secrets & Crypto"
        description="Secrets detection, cryptographic trust and PII field inventory"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="secrets">Secrets</TabsTrigger>
          <TabsTrigger value="crypto">Crypto Trust</TabsTrigger>
          <TabsTrigger value="pii">PII Inventory</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="secrets"><SecretsHub /></TabsContent>
          <TabsContent value="crypto"><CryptoTrustHub /></TabsContent>
          <TabsContent value="pii"><PIIFieldInventory /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
