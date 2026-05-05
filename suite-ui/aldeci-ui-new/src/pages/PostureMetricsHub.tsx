/**
 * PostureMetricsHub — Security Posture Metrics unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone posture-metric pages into a single tabbed hero
 * per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * Posture Metrics sub-cluster).
 *
 *   tab           | source page                   | endpoint
 *   --------------|-------------------------------|----------------------------------------------
 *   benchmarking  | PostureBenchmarkingDashboard  | /api/v1/posture-benchmarking/{stats,benchmarks,controls}
 *   scoring       | PostureScoringDashboard       | /api/v1/posture-scoring/{score,controls,snapshots}
 *   trends        | PostureTrendsDashboard        | /api/v1/posture-trends/trends
 *
 * Route: /discover/posture-metrics
 * Persona target: CISO (#1), Security Architect (#3), Engineering Manager (#14),
 *                 Compliance Lead (#5)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { BarChart2, ShieldCheck, TrendingUp } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

import { PostureBenchmarkingPanel } from "@/components/posture/PostureBenchmarkingPanel";
import { PostureScoringPanel } from "@/components/posture/PostureScoringPanel";
import { PostureTrendsPanel } from "@/components/posture/PostureTrendsPanel";

type TabKey = "benchmarking" | "scoring" | "trends";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "benchmarking",
    label: "Benchmarking",
    icon: BarChart2,
    description:
      "Security posture benchmarking against industry standards and frameworks (CIS, NIST, SOC 2, PCI, ISO 27001) (Folded from PostureBenchmarkingDashboard).",
  },
  {
    key: "scoring",
    label: "Scoring",
    icon: ShieldCheck,
    description:
      "Weighted control implementation scoring with snapshots and gap tracking (Folded from PostureScoringDashboard).",
  },
  {
    key: "trends",
    label: "Trends",
    icon: TrendingUp,
    description:
      "Posture trends across categories with velocity (improving/declining/stable) (Folded from PostureTrendsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PostureMetricsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "benchmarking";
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
        title="Posture Metrics"
        description="Unified security-posture metrics workspace — industry benchmarking, weighted scoring, and category trends."
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

        <TabsContent value="benchmarking">
          <Suspense fallback={<PageSkeleton />}>
            <PostureBenchmarkingPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="scoring">
          <Suspense fallback={<PageSkeleton />}>
            <PostureScoringPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="trends">
          <Suspense fallback={<PageSkeleton />}>
            <PostureTrendsPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
