import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const OnboardingWizard = lazy(() => import("@/pages/onboarding/OnboardingWizard"));
const ZeroSetupOnboarding = lazy(() => import("@/pages/ZeroSetupOnboarding"));
const DomainSeedDiscoveryWizard = lazy(() => import("@/pages/DomainSeedDiscoveryWizard"));
const IntegrationHealth = lazy(() => import("@/pages/integrations/IntegrationHealth"));

export default function S02Onboarding() {
  const [tab, setTab] = useState("wizard");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S02 · Onboarding"
        description="Guided setup, zero-config quickstart, and integration health"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="wizard">Onboarding Wizard</TabsTrigger>
          <TabsTrigger value="zero-setup">Zero Setup</TabsTrigger>
          <TabsTrigger value="domain-seed">Domain Discovery</TabsTrigger>
          <TabsTrigger value="integrations">Integration Health</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="wizard"><OnboardingWizard /></TabsContent>
          <TabsContent value="zero-setup"><ZeroSetupOnboarding /></TabsContent>
          <TabsContent value="domain-seed"><DomainSeedDiscoveryWizard /></TabsContent>
          <TabsContent value="integrations"><IntegrationHealth /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
