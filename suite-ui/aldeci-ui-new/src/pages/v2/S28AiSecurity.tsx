import { useState, lazy, Suspense } from "react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";

const CopilotDashboard = lazy(() => import("@/pages/ai/CopilotDashboard"));
const AICopilotAgentsHub = lazy(() => import("@/pages/AICopilotAgentsHub"));
const AISecurityAdvisor = lazy(() => import("@/pages/AISecurityAdvisor"));
const AIAttackPathView = lazy(() => import("@/pages/ai/AIAttackPathView"));
const MCPToolRegistry = lazy(() => import("@/pages/ai/MCPToolRegistry"));

export default function S28AiSecurity() {
  const [tab, setTab] = useState("copilot");
  return (
    <div className="space-y-4 p-6">
      <PageHeader
        title="S28 · AI Security"
        description="AI copilot, agents hub, security advisor, attack path analysis, and MCP tool registry."
      />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="copilot">Copilot</TabsTrigger>
          <TabsTrigger value="agents">AI Agents</TabsTrigger>
          <TabsTrigger value="advisor">Security Advisor</TabsTrigger>
          <TabsTrigger value="attack-path">Attack Paths</TabsTrigger>
          <TabsTrigger value="mcp">MCP Registry</TabsTrigger>
        </TabsList>
        <Suspense fallback={<div className="p-4">Loading…</div>}>
          <TabsContent value="copilot"><CopilotDashboard /></TabsContent>
          <TabsContent value="agents"><AICopilotAgentsHub /></TabsContent>
          <TabsContent value="advisor"><AISecurityAdvisor /></TabsContent>
          <TabsContent value="attack-path"><AIAttackPathView /></TabsContent>
          <TabsContent value="mcp"><MCPToolRegistry /></TabsContent>
        </Suspense>
      </Tabs>
    </div>
  );
}
