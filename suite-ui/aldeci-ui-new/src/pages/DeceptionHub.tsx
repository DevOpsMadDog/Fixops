/**
 * DeceptionHub — Deception / Honeypot / Decoy unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone deception pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.17 (S17 FAIL Chaos —
 * Deception sub-cluster).
 *
 *   tab          | source page                   | endpoint
 *   -------------|-------------------------------|-------------------------------------------
 *   engine       | DeceptionEngine               | /api/v1/deception/{stats,canaries,alerts}
 *   analytics    | DeceptionAnalyticsDashboard   | /api/v1/deception-analytics/{stats,assets,interactions}
 *   decoys       | ThreatDeceptionDashboard      | /api/v1/threat-deception/{decoys,stats}
 *
 * Route: /brain/fail/deception
 * Persona target: SOC T2 (#6), Threat Hunter (#8), Sec Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.17
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Eye, BarChart3, Bot } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { FAILStatsPanel } from "@/components/deception/FAILStatsPanel";
import { DeceptionAnalyticsPanel } from "@/components/deception/DeceptionAnalyticsPanel";
import { DecoysPanel } from "@/components/deception/DecoysPanel";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.


type TabKey = "engine" | "analytics" | "decoys";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "engine",
    label: "Engine",
    icon: Eye,
    description:
      "Honeypot and canary-token engine — live deception assets, recent alerts, and trigger metrics (Folded from DeceptionEngine).",
  },
  {
    key: "analytics",
    label: "Analytics",
    icon: BarChart3,
    description:
      "Deception analytics — interaction history, attacker IP breakdown, and asset effectiveness (Folded from DeceptionAnalyticsDashboard).",
  },
  {
    key: "decoys",
    label: "Decoys",
    icon: Bot,
    description:
      "Decoy registry — names, types, ports, interaction counts, and campaign status (Folded from ThreatDeceptionDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function DeceptionHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "engine";
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
        title="Deception"
        description="Unified deception workspace — honeypot/canary engine, attacker analytics, and decoy registry."
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

        <TabsContent value="engine">
          <Suspense fallback={<PageSkeleton />}>
            <FAILStatsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="analytics">
          <Suspense fallback={<PageSkeleton />}>
            <DeceptionAnalyticsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="decoys">
          <Suspense fallback={<PageSkeleton />}>
            <DecoysPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
