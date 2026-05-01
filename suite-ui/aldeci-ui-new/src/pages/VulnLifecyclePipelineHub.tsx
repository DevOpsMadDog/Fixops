/**
 * VulnLifecyclePipelineHub — Vulnerability Lifecycle Pipeline unified hero
 * (Phase 3 UX consolidation, 2026-05-02 — combined 4-page pair)
 *
 * Folds 4 standalone vulnerability-pipeline dashboards into a single tabbed
 * hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10 (Vuln Lifecycle
 * Pipeline combined sub-cluster — backlog 53 / item 53 follow-up to
 * ThreatIntelOpsHub: pair-merge of two adjacent 2-page candidates into one
 * 4-page hero covering intake → triage → workflow → close-out).
 *
 *   tab           | source page                       | endpoint
 *   --------------|-----------------------------------|----------------------------------------------
 *   age           | VulnerabilityAgeDashboard         | /api/v1/vuln-age/{distribution,sla,oldest,snapshots}
 *   lifecycle     | VulnLifecycle                     | /api/v1/vuln-lifecycle/{stats,state/{state},{id}/transition}
 *   prioritize    | VulnPrioritizationDashboard       | /api/v1/vuln-prioritization/{queue,stats}
 *   workflow      | VulnWorkflowDashboard             | /api/v1/vuln-workflow/{workflows,stats}
 *
 * Route: /discover/vuln-pipeline
 * Persona target: Vuln Manager (#5), AppSec Engineer (#10), SOC Analyst (#7), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Hourglass, GitBranch, ListOrdered, Workflow } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const VulnerabilityAgeDashboard = lazy(() => import("@/pages/VulnerabilityAgeDashboard"));
const VulnLifecycle = lazy(() => import("@/pages/VulnLifecycle"));
const VulnPrioritizationDashboard = lazy(() => import("@/pages/VulnPrioritizationDashboard"));
const VulnWorkflowDashboard = lazy(() => import("@/pages/VulnWorkflowDashboard"));

type TabKey = "age" | "lifecycle" | "prioritize" | "workflow";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "age",
    label: "Age & SLA",
    icon: Hourglass,
    description:
      "Vulnerability age distribution, SLA breach tracking, oldest open finds and historical snapshots (Folded from VulnerabilityAgeDashboard).",
  },
  {
    key: "lifecycle",
    label: "Lifecycle",
    icon: GitBranch,
    description:
      "Per-state vulnerability lifecycle counts, state transitions and audit trail across new → triage → fix → verify → close (Folded from VulnLifecycle).",
  },
  {
    key: "prioritize",
    label: "Prioritization",
    icon: ListOrdered,
    description:
      "Risk-scored prioritization queue, exploitation signals and recommended next-actions for each open vuln (Folded from VulnPrioritizationDashboard).",
  },
  {
    key: "workflow",
    label: "Workflow",
    icon: Workflow,
    description:
      "Active remediation workflows, owners, due-dates and closed-today rollups across the open backlog (Folded from VulnWorkflowDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function VulnLifecyclePipelineHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "age";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with active tab so deep-links and old-route
  // redirects (e.g. /vuln-lifecycle → /discover/vuln-pipeline?tab=lifecycle) work.
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
        title="Vulnerability Lifecycle Pipeline"
        description="Unified vulnerability pipeline hero — age & SLA, lifecycle states, prioritization queue, and active remediation workflows."
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

        <TabsContent value="age">
          <Suspense fallback={<PageSkeleton />}>
            <VulnerabilityAgeDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="lifecycle">
          <Suspense fallback={<PageSkeleton />}>
            <VulnLifecycle />
          </Suspense>
        </TabsContent>
        <TabsContent value="prioritize">
          <Suspense fallback={<PageSkeleton />}>
            <VulnPrioritizationDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="workflow">
          <Suspense fallback={<PageSkeleton />}>
            <VulnWorkflowDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
