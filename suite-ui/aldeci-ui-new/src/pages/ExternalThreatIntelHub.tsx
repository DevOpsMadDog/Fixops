/**
 * ExternalThreatIntelHub — External Threat Intelligence unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone external-threat-intel pages into a single tabbed hero
 * per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14 (S14 Threat Intel —
 * External / Zero-Day / Dark Web sub-cluster).
 *
 *   tab     | source page                   | endpoint
 *   --------|-------------------------------|--------------------------------------------------------
 *   zeroday | ZeroDayIntelligenceDashboard  | /api/v1/zero-day/{stats,vulns,threat-actors}
 *   darkweb | DarkWebMonitoringDashboard    | /api/v1/dark-web/{stats,mentions,credential-exposures}
 *   scores  | ThreatScoreDashboard          | /api/v1/threat-scores/{stats,top-threats,scores}
 *
 * Route: /attack/intel/external
 * Persona target: Threat Hunter (#8), SOC T2 (#6), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Bug, Eye, BarChart3 } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported panel components — each wired to real backend endpoints.
const ZeroDayPanel = lazy(() => import("@/components/threat-intel/ZeroDayPanel"));
const DarkWebPanel = lazy(() => import("@/components/threat-intel/DarkWebPanel"));
const ThreatScoresPanel = lazy(() => import("@/components/threat-intel/ThreatScoresPanel"));

type TabKey = "zeroday" | "darkweb" | "scores";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "zeroday",
    label: "Zero-Day",
    icon: Bug,
    description:
      "Zero-day and N-day vulnerabilities, exploitation status, and threat actors (Folded from ZeroDayIntelligenceDashboard).",
  },
  {
    key: "darkweb",
    label: "Dark Web",
    icon: Eye,
    description:
      "Dark web mentions, credential exposures, and keyword alerts (Folded from DarkWebMonitoringDashboard).",
  },
  {
    key: "scores",
    label: "Threat Scores",
    icon: BarChart3,
    description:
      "Composite threat scoring across all assets — top threats and score distribution (Folded from ThreatScoreDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ExternalThreatIntelHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "zeroday";
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
        title="External Threat Intelligence"
        description="Unified external-threat workspace — zero-day exploitation, dark web exposure, and composite threat scoring."
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

        <TabsContent value="zeroday">
          <Suspense fallback={<PageSkeleton />}>
            <ZeroDayPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="darkweb">
          <Suspense fallback={<PageSkeleton />}>
            <DarkWebPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="scores">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatScoresPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
