import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const IntegrationHealth = lazy(() => import("@/pages/integrations/IntegrationHealth"));
const WebhookIngestionHub = lazy(() => import("@/pages/WebhookIngestionHub"));
const SettingsIntegrations = lazy(() => import("@/pages/settings/Integrations"));
const Marketplace = lazy(() => import("@/pages/settings/Marketplace"));
const WebhooksOutboundPage = lazy(() => import("@/pages/admin/WebhooksOutboundPage"));
const SystemHealthDashboard = lazy(() => import("@/pages/SystemHealthDashboard"));
const SecurityHealthDashboard = lazy(() => import("@/pages/SecurityHealthDashboard"));

export default function S29Integrations() {
  const [tab, setTab] = useState("health");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S29 · Integrations"
        description="Integration health, webhook ingestion, connector settings, marketplace, and outbound webhooks."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="health">Integration Health</TabsTrigger>
          <TabsTrigger value="webhooks">Webhook Ingestion</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="marketplace">Marketplace</TabsTrigger>
          <TabsTrigger value="outbound">Outbound Webhooks</TabsTrigger>
          <TabsTrigger value="platform-health">Platform Health</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="health"><IntegrationHealth /></TabsContent>
          <TabsContent value="webhooks"><WebhookIngestionHub /></TabsContent>
          <TabsContent value="settings"><SettingsIntegrations /></TabsContent>
          <TabsContent value="marketplace"><Marketplace /></TabsContent>
          <TabsContent value="outbound"><WebhooksOutboundPage /></TabsContent>
          <TabsContent value="platform-health">
            <div className="space-y-6">
              <SystemHealthDashboard />
              <SecurityHealthDashboard />
            </div>
          </TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
