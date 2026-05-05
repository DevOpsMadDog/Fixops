/**
 * AutomationOrchestrationHub — Remediation Automation & Orchestration unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone patch/SOAR automation pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.19 (S19 Remediation Center —
 * Automation/Orchestration sub-cluster).
 *
 *   tab          | source page                | endpoint
 *   -------------|----------------------------|----------------------------------------------
 *   patch        | PatchManagementDashboard   | /api/v1/patch-management/{patches,stats}
 *   prioritize   | PatchPrioritizer           | /api/v1/patch-automation/{patches,stats}
 *   soar         | SOARDashboard              | /api/v1/soar/{stats,playbooks,executions,mttr}
 *
 * Route: /remediate/automation
 * Persona target: Remediation Engineer (#15), SOC T2 (#6), Platform Eng (#16)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.19
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Wrench, ListOrdered, Workflow } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "patch" | "prioritize" | "soar";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "patch",
    label: "Patch Management",
    icon: Wrench,
    description:
      "Patch lifecycle, deployment status and SLA tracking across managed assets (Folded from PatchManagementDashboard).",
  },
  {
    key: "prioritize",
    label: "Patch Prioritizer",
    icon: ListOrdered,
    description:
      "Risk-weighted patch queue with grouping, blast-radius and exploit-availability scoring (Folded from PatchPrioritizer).",
  },
  {
    key: "soar",
    label: "SOAR",
    icon: Workflow,
    description:
      "SOAR playbooks, executions, integrations and MTTR analytics for automated remediation (Folded from SOARDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AutomationOrchestrationHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "patch";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /patch-management → /remediate/automation?tab=patch) work.
  useEffect(() => {
    if (params.get("tab") !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  // React when query string changes (e.g. user clicks an old link in another tab).
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
        title="Automation & Orchestration"
        description="Unified remediation-automation workspace — patch management, risk-weighted patch queue, and SOAR playbook orchestration."
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

        <TabsContent value="patch">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="prioritize">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="soar">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
