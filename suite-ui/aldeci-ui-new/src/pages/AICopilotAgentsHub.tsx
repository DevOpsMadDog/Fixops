/**
 * AICopilotAgentsHub — AI Copilot Agents unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone AI-agent surfaces into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.18 (S18 AI Copilot —
 * Agents Console + Task Queue + Shadow AI Inventory sub-cluster).
 *
 *   tab        | source page         | endpoint
 *   -----------|---------------------|--------------------------------------
 *   console    | AIAgentsConsole     | POST /api/v1/agents/{role}/task
 *   tasks      | AgentTaskQueue      | GET  /api/v1/agents/tasks
 *   shadow     | ShadowAIInventory   | GET  /api/v1/ai-exposure/shadow
 *
 * Route: /ai/agents
 * Persona target: AI Security Engineer (#19), Sec Architect (#9), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.18
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Bot, ListTodo, EyeOff } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "console" | "tasks" | "shadow";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "console",
    label: "Agents Console",
    icon: Bot,
    description:
      "Send a one-off task to a named AI agent role (Folded from AIAgentsConsole).",
  },
  {
    key: "tasks",
    label: "Task Queue",
    icon: ListTodo,
    description:
      "Live view of queued, running, and completed agent tasks (Folded from AgentTaskQueue).",
  },
  {
    key: "shadow",
    label: "Shadow AI",
    icon: EyeOff,
    description:
      "Discover unsanctioned LLM and model usage across the org (Folded from ShadowAIInventory).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AICopilotAgentsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "console";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with active tab so deep-links + redirects work.
  useEffect(() => {
    if (params.get("tab") !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  // React when query string changes externally.
  useEffect(() => {
    const incoming = params.get("tab");
    if (isTabKey(incoming) && incoming !== tab) setTab(incoming);
  }, [params, tab]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="AI Copilot Agents"
        description="Unified AI-agent workspace — dispatch tasks to agent roles, monitor the queue, and surface shadow LLM usage."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="console">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="tasks">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="shadow">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
