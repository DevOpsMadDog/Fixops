/**
 * ExceptionsHub — Waivers & Exceptions unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone exceptions / auto-waiver pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.20 (S20 Waivers & Exceptions —
 * Exceptions sub-cluster).
 *
 *   tab          | source page                    | endpoint
 *   -------------|--------------------------------|----------------------------------------------
 *   exceptions   | SecurityExceptionDashboard     | /api/v1/security-exceptions/{list,stats}
 *   workflow     | ExceptionWorkflowDashboard     | /api/v1/exception-workflow/{exceptions,stats}
 *   auto-rules   | AutoWaiverRules                | /api/v1/auto-waiver/{rules,rule}
 *
 * Route: /remediate/exceptions
 * Persona target: GRC Analyst (#12), SOC T2 (#6), AppSec Lead (#15)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.20
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldOff, GitPullRequest, ListChecks } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const SecurityExceptionDashboard = lazy(() => import("@/pages/SecurityExceptionDashboard"));
const ExceptionWorkflowDashboard = lazy(() => import("@/pages/ExceptionWorkflowDashboard"));
const AutoWaiverRules = lazy(() => import("@/pages/AutoWaiverRules"));

type TabKey = "exceptions" | "workflow" | "auto-rules";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "exceptions",
    label: "Exceptions",
    icon: ShieldOff,
    description:
      "Risk-accepted exceptions with approval queue and expiry tracking (Folded from SecurityExceptionDashboard).",
  },
  {
    key: "workflow",
    label: "Workflow",
    icon: GitPullRequest,
    description:
      "Approval workflow status across exception requests (Folded from ExceptionWorkflowDashboard).",
  },
  {
    key: "auto-rules",
    label: "Auto-Waiver Rules",
    icon: ListChecks,
    description:
      "Manage and publish auto-waiver rules that suppress matching findings (Folded from AutoWaiverRules).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ExceptionsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "exceptions";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /security-exceptions → /remediate/exceptions?tab=exceptions) work.
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
        title="Waivers & Exceptions"
        description="Unified exception governance — risk-accepted findings, approval workflows, and auto-waiver rules."
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

        <TabsContent value="exceptions">
          <Suspense fallback={<PageSkeleton />}>
            <SecurityExceptionDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="workflow">
          <Suspense fallback={<PageSkeleton />}>
            <ExceptionWorkflowDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="auto-rules">
          <Suspense fallback={<PageSkeleton />}>
            <AutoWaiverRules />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
