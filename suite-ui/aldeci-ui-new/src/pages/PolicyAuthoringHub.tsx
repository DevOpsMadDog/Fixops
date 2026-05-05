/**
 * PolicyAuthoringHub — Policy & Hooks authoring/observability unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone policy/hook pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.26 (S26 Policies & Rules —
 * Authoring + Hooks sub-cluster).
 *
 *   tab          | source page              | endpoint
 *   -------------|--------------------------|----------------------------------------------
 *   stage-matrix | StagePolicyMatrix        | /api/v1/policies (stage × severity matrix)
 *   hooks-policy | HooksPolicyEditor        | GET/PUT /api/v1/hooks/policy
 *   hooks-status | HooksStatusPanel         | GET /api/v1/hooks/status
 *
 * Route: /comply/policies/authoring
 * Persona target: AppSec Engineer (#10), Security Architect (#11), GRC Analyst (#12), CTO (#3)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.26
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Grid3x3, FileEdit, Activity } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

const StagePolicyMatrixPanel = lazy(() => import("@/components/policy-authoring/StagePolicyMatrixPanel"));
const HooksPolicyPanel = lazy(() => import("@/components/policy-authoring/HooksPolicyPanel"));
const HooksStatusPanel = lazy(() => import("@/components/policy-authoring/HooksStatusPanel"));

type TabKey = "stage-matrix" | "hooks-policy" | "hooks-status";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "stage-matrix",
    label: "Stage Matrix",
    icon: Grid3x3,
    description:
      "Stage × severity policy matrix across active policies (Folded from StagePolicyMatrix).",
  },
  {
    key: "hooks-policy",
    label: "Hooks Policy",
    icon: FileEdit,
    description:
      "Edit pre/post hook policy JSON for active enforcement (Folded from HooksPolicyEditor).",
  },
  {
    key: "hooks-status",
    label: "Hooks Status",
    icon: Activity,
    description:
      "Live runtime status of registered hooks across the platform (Folded from HooksStatusPanel).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PolicyAuthoringHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "stage-matrix";
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
        title="Policy Authoring & Hooks"
        description="Unified policy authoring workspace — stage × severity matrix, hook policy JSON editor, and live hook runtime status."
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

        <TabsContent value="stage-matrix">
          <Suspense fallback={<PageSkeleton />}>
            <StagePolicyMatrixPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="hooks-policy">
          <Suspense fallback={<PageSkeleton />}>
            <HooksPolicyPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="hooks-status">
          <Suspense fallback={<PageSkeleton />}>
            <HooksStatusPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
