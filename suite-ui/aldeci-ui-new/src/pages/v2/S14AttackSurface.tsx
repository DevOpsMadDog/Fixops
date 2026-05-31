import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const AttackSurface = lazy(() => import("@/pages/attack-surface/AttackSurface"));
const AttackPaths = lazy(() => import("@/pages/discover/AttackPaths"));
const AttackSimulation = lazy(() => import("@/pages/validate/AttackSimulation"));
const Reachability = lazy(() => import("@/pages/validate/Reachability"));
const OffensiveValidationHub = lazy(() => import("@/pages/OffensiveValidationHub"));

export default function S14AttackSurface() {
  const [tab, setTab] = useState("surface");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S14 · Attack Surface"
        description="Attack surface management — paths, simulation, reachability and offensive validation"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="surface">Attack Surface</TabsTrigger>
          <TabsTrigger value="paths">Attack Paths</TabsTrigger>
          <TabsTrigger value="simulation">Simulation</TabsTrigger>
          <TabsTrigger value="reachability">Reachability</TabsTrigger>
          <TabsTrigger value="offensive">Offensive Validation</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="surface"><AttackSurface /></TabsContent>
          <TabsContent value="paths"><AttackPaths /></TabsContent>
          <TabsContent value="simulation"><AttackSimulation /></TabsContent>
          <TabsContent value="reachability"><Reachability /></TabsContent>
          <TabsContent value="offensive"><OffensiveValidationHub /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
