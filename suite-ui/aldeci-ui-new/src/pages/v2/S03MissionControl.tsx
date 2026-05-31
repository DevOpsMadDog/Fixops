import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const CISODashboard = lazy(() => import("@/pages/mission-control/CISODashboard"));
const LiveFeed = lazy(() => import("@/pages/mission-control/LiveFeed"));
const RiskOverview = lazy(() => import("@/pages/mission-control/RiskOverview"));
const SLADashboard = lazy(() => import("@/pages/mission-control/SLADashboard"));
// P2 VP Engineering — per-team debt + DORA metrics (wire real component when built)
const EngineeringSecurityPlaceholder = () => (
  <div className="p-6 text-muted-foreground text-sm">
    Engineering Security — Per-team debt + DORA metrics — wire when component exists
  </div>
);

export default function S03MissionControl() {
  const [tab, setTab] = useState("ciso");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S03 · Mission Control"
        description="Unified CISO command centre with live feed, risk and SLA views"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="ciso">CISO Dashboard</TabsTrigger>
          <TabsTrigger value="live-feed">Live Feed</TabsTrigger>
          <TabsTrigger value="risk">Risk Overview</TabsTrigger>
          <TabsTrigger value="sla">SLA Dashboard</TabsTrigger>
          <TabsTrigger value="eng-security">Engineering Security</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="ciso"><CISODashboard /></TabsContent>
          <TabsContent value="live-feed"><LiveFeed /></TabsContent>
          <TabsContent value="risk"><RiskOverview /></TabsContent>
          <TabsContent value="sla"><SLADashboard /></TabsContent>
          <TabsContent value="eng-security"><EngineeringSecurityPlaceholder /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
