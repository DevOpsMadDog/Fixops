/**
 * BehaviorAnalyticsHub — User & Entity Behavior unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone behavior-analytics dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.3 (S3 SOC Operations — Behavior sub-cluster).
 *
 *   tab          | source page                    | endpoint
 *   -------------|--------------------------------|----------------------------------------------
 *   uba          | UBADashboard                   | /api/v1/uba/{stats,users,events,alerts}
 *   behavioral   | BehavioralAnalyticsDashboard   | /api/v1/behavioral-analytics/{anomalies,stats}
 *   insider      | InsiderThreatMonitor           | /api/v1/insider-threat/{alerts,stats}
 *
 * Route: /mission-control/behavior
 * Persona target: SOC T2 (#6), Threat Hunter (#8), Sec Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.3
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Users, Activity, UserX } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Panels — lazy-loaded, wired to real backends
const UBAPanel = lazy(() => import("@/components/behavior/UBAPanel"));
const BehavioralAnalyticsPanel = lazy(() => import("@/components/behavior/BehavioralAnalyticsPanel"));
const InsiderThreatPanel = lazy(() => import("@/components/behavior/InsiderThreatPanel"));

type TabKey = "uba" | "behavioral" | "insider";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "uba",
    label: "UBA",
    icon: Users,
    description:
      "User Behavior Analytics — risk-scored users, anomalous events, open alerts (Folded from UBADashboard).",
  },
  {
    key: "behavioral",
    label: "Behavioral Analytics",
    icon: Activity,
    description:
      "Entity-level behavioral anomalies and baseline deviation stats (Folded from BehavioralAnalyticsDashboard).",
  },
  {
    key: "insider",
    label: "Insider Threat",
    icon: UserX,
    description:
      "Insider-threat alerts and rollup statistics across detection signals (Folded from InsiderThreatMonitor).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function BehaviorAnalyticsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "uba";
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
        title="Behavior Analytics"
        description="Unified user & entity behavior hero — UBA risk scoring, anomaly detection, and insider-threat monitoring."
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

        <TabsContent value="uba">
          <Suspense fallback={<PageSkeleton />}>
            <UBAPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="behavioral">
          <Suspense fallback={<PageSkeleton />}>
            <BehavioralAnalyticsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="insider">
          <Suspense fallback={<PageSkeleton />}>
            <InsiderThreatPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
