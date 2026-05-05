/**
 * AwarenessHub — Security Awareness unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 4 standalone awareness dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (Awareness sub-cluster — campaigns,
 * programs, metrics, and scoring).  All four sources hit real awareness backend
 * routers (awareness_campaign_router, security_awareness_program_router,
 * security_awareness_metrics_router, awareness_score_router) — zero mocks.
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|---------------------------------------------
 *   campaigns  | AwarenessCampaignDashboard   | /api/v1/awareness-campaigns/{campaigns,stats}
 *   program    | AwarenessProgramDashboard    | /api/v1/awareness-program/{programs,stats}
 *   metrics    | AwarenessMetricsDashboard    | /api/v1/awareness-metrics/{metrics,stats}
 *   score      | AwarenessScoreDashboard      | /api/v1/awareness-score/orgs/{id}/{scores,employees,stats}
 *
 * Route: /comply/awareness
 * Persona target: Security Awareness Lead (#21), GRC Analyst (#12), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (Awareness sub-cluster)
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Megaphone, GraduationCap, BarChart3, Trophy } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported panel components — each hits a real backend endpoint.
const CampaignsPanel = lazy(() => import("@/components/awareness/CampaignsPanel"));
const ProgramPanel = lazy(() => import("@/components/awareness/ProgramPanel"));
const MetricsPanel = lazy(() => import("@/components/awareness/MetricsPanel"));
const ScorePanel = lazy(() => import("@/components/awareness/ScorePanel"));

type TabKey = "campaigns" | "program" | "metrics" | "score";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "campaigns",
    label: "Campaigns",
    icon: Megaphone,
    description:
      "Active phishing simulations and awareness campaigns (Folded from AwarenessCampaignDashboard).",
  },
  {
    key: "program",
    label: "Program",
    icon: GraduationCap,
    description:
      "Long-running awareness program enrollment and curriculum (Folded from AwarenessProgramDashboard).",
  },
  {
    key: "metrics",
    label: "Metrics",
    icon: BarChart3,
    description:
      "Org-wide awareness KPIs — completion rates, click-through, repeat clickers (Folded from AwarenessMetricsDashboard).",
  },
  {
    key: "score",
    label: "Score",
    icon: Trophy,
    description:
      "Per-employee awareness scoring and leaderboard (Folded from AwarenessScoreDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AwarenessHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "campaigns";
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
        title="Security Awareness"
        description="Unified awareness workspace — campaigns, training programs, org-wide metrics, and per-employee scoring."
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

        <TabsContent value="campaigns">
          <Suspense fallback={<PageSkeleton />}>
            <CampaignsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="program">
          <Suspense fallback={<PageSkeleton />}>
            <ProgramPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="metrics">
          <Suspense fallback={<PageSkeleton />}>
            <MetricsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="score">
          <Suspense fallback={<PageSkeleton />}>
            <ScorePanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
