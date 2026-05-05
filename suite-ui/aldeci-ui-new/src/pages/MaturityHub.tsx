/**
 * MaturityHub — Security Program Maturity unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone maturity dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23 (S23 Compliance — Maturity sub-cluster).
 *
 *   tab        | source page                       | endpoint
 *   -----------|-----------------------------------|----------------------------------------------
 *   security   | SecurityMaturityDashboard         | /api/v1/security-maturity/{stats,assessments}
 *   posture    | SecurityPostureMaturityDashboard  | /api/v1/posture-maturity/overview
 *   program    | ProgramMaturityDashboard          | /api/v1/program-maturity/domains
 *
 * Route: /comply/maturity
 * Persona target: GRC Analyst (#12), Compliance Mgr (#13), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Gauge, ShieldCheck, Layers } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { SecurityMaturityPanel } from "@/components/maturity/SecurityMaturityPanel";
import { PostureMaturityPanel } from "@/components/maturity/PostureMaturityPanel";
import { ProgramMaturityPanel } from "@/components/maturity/ProgramMaturityPanel";

type TabKey = "security" | "posture" | "program";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "security",
    label: "Security Maturity",
    icon: Gauge,
    description:
      "Domain-level maturity scoring with assessments and historical trend (Folded from SecurityMaturityDashboard).",
  },
  {
    key: "posture",
    label: "Posture Maturity",
    icon: ShieldCheck,
    description:
      "Cross-control posture maturity overview against framework baselines (Folded from SecurityPostureMaturityDashboard).",
  },
  {
    key: "program",
    label: "Program Maturity",
    icon: Layers,
    description:
      "Per-domain program maturity rollup for board-level reporting (Folded from ProgramMaturityDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function MaturityHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "security";
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
        title="Security Maturity"
        description="Unified program maturity hero — security domains, posture baselines, and program-level rollup."
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

        <TabsContent value="security">
          <Suspense fallback={<PageSkeleton />}>
            <SecurityMaturityPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="posture">
          <Suspense fallback={<PageSkeleton />}>
            <PostureMaturityPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="program">
          <Suspense fallback={<PageSkeleton />}>
            <ProgramMaturityPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
