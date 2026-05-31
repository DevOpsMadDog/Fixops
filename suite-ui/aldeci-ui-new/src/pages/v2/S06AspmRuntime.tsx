import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const AppLayerSecurityHub = lazy(() => import("@/pages/AppLayerSecurityHub"));
const CodeToRuntimeDashboard = lazy(() => import("@/pages/CodeToRuntimeDashboard"));
const RuntimeCodeTrace = lazy(() => import("@/pages/RuntimeCodeTrace"));
const TracedFlowViewer = lazy(() => import("@/pages/TracedFlowViewer"));

export default function S06AspmRuntime() {
  const [tab, setTab] = useState("app-layer");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S06 · ASPM Runtime"
        description="Application layer security — code-to-runtime tracing and flow analysis"
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="app-layer">App Layer Security</TabsTrigger>
          <TabsTrigger value="code-to-runtime">Code to Runtime</TabsTrigger>
          <TabsTrigger value="runtime-trace">Runtime Trace</TabsTrigger>
          <TabsTrigger value="traced-flows">Traced Flows</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="app-layer"><AppLayerSecurityHub /></TabsContent>
          <TabsContent value="code-to-runtime"><CodeToRuntimeDashboard /></TabsContent>
          <TabsContent value="runtime-trace"><RuntimeCodeTrace /></TabsContent>
          <TabsContent value="traced-flows"><TracedFlowViewer /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
