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
 *   workflow     | ExceptionWorkflowDashboard     | /api/v1/exception-workflow/{requests,summary}
 *   auto-rules   | AutoWaiverRules                | /api/v1/auto-waiver/{rules,stats}
 *
 * Route: /remediate/exceptions
 * Persona target: GRC Analyst (#12), SOC T2 (#6), AppSec Lead (#15)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.20
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldOff, GitPullRequest, ListChecks } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ExceptionsListPanel } from "@/components/exceptions/ExceptionsListPanel";
import { ExceptionWorkflowPanel } from "@/components/exceptions/ExceptionWorkflowPanel";
import { AutoWaiverRulesPanel } from "@/components/exceptions/AutoWaiverRulesPanel";

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
      "Risk-accepted exceptions with approval queue and expiry tracking (/api/v1/security-exceptions).",
  },
  {
    key: "workflow",
    label: "Workflow",
    icon: GitPullRequest,
    description:
      "Approval workflow status across exception requests (/api/v1/exception-workflow/requests).",
  },
  {
    key: "auto-rules",
    label: "Auto-Waiver Rules",
    icon: ListChecks,
    description:
      "Manage and publish auto-waiver rules that suppress matching findings (/api/v1/auto-waiver/rules).",
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

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

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
            <ExceptionsListPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="workflow">
          <Suspense fallback={<PageSkeleton />}>
            <ExceptionWorkflowPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="auto-rules">
          <Suspense fallback={<PageSkeleton />}>
            <AutoWaiverRulesPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
