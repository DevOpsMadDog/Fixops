import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const Collaboration = lazy(() => import("@/pages/remediate/Collaboration"));
const TrainingCultureHub = lazy(() => import("@/pages/TrainingCultureHub"));
const AwarenessHub = lazy(() => import("@/pages/AwarenessHub"));
const SecurityChampionsDashboard = lazy(() => import("@/pages/SecurityChampionsDashboard"));

export default function S30Collaboration() {
  const [tab, setTab] = useState("collab");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S30 · Collaboration"
        description="Team collaboration, training culture, security awareness, and security champions program."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="collab">Collaboration</TabsTrigger>
          <TabsTrigger value="training">Training &amp; Culture</TabsTrigger>
          <TabsTrigger value="awareness">Awareness</TabsTrigger>
          <TabsTrigger value="champions">Security Champions</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="collab"><Collaboration /></TabsContent>
          <TabsContent value="training"><TrainingCultureHub /></TabsContent>
          <TabsContent value="awareness"><AwarenessHub /></TabsContent>
          <TabsContent value="champions"><SecurityChampionsDashboard /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
