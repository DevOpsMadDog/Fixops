/**
 * ThreatActorsHub — Threat Intel Actors / Indicators unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 5 standalone threat-actor / IOC pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14 (S14 Threat Intel —
 * Actors + Indicators sub-cluster).
 *
 *   tab          | source page                    | endpoint
 *   -------------|--------------------------------|----------------------------------------------
 *   actors       | ThreatActorDashboard           | /api/v1/threat-actors/{stats,actors,watchlist,iocs}
 *   tracking     | ActorTrackingDashboard         | /api/v1/actor-tracking/{actors,stats}
 *   attribution  | ThreatAttributionDashboard     | /api/v1/threat-attribution/{attributions,stats}
 *   indicators   | ThreatIndicatorDashboard       | /api/v1/threat-indicators/indicators
 *   ioc-hunter   | IOCHunter                      | /api/v1/ioc-enrichment/{stats,iocs}
 *
 * Route: /attack/intel/actors
 * Persona target: SOC T2 (#6), Threat Hunter (#8), GRC Analyst (#12)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { UserCog, Crosshair, Fingerprint, AlertTriangle, Search } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

import { ThreatActorsPanel } from "@/components/threat-actors/ThreatActorsPanel";
import { ActorTrackingPanel } from "@/components/threat-actors/ActorTrackingPanel";
import { AttributionPanel } from "@/components/threat-actors/AttributionPanel";
import { IndicatorsPanel } from "@/components/threat-actors/IndicatorsPanel";
import { IOCHunterPanel } from "@/components/threat-actors/IOCHunterPanel";

type TabKey = "actors" | "tracking" | "attribution" | "indicators" | "ioc-hunter";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "actors",
    label: "Actors",
    icon: UserCog,
    description:
      "Threat actor dossiers, watchlist, and known IOCs (Folded from ThreatActorDashboard).",
  },
  {
    key: "tracking",
    label: "Actor Tracking",
    icon: Crosshair,
    description:
      "Live actor activity tracking with engagement statistics (Folded from ActorTrackingDashboard).",
  },
  {
    key: "attribution",
    label: "Attribution",
    icon: Fingerprint,
    description:
      "Attribution analysis tying observed activity to actor groups (Folded from ThreatAttributionDashboard).",
  },
  {
    key: "indicators",
    label: "Indicators",
    icon: AlertTriangle,
    description:
      "Live IOC feed across observed indicators (Folded from ThreatIndicatorDashboard).",
  },
  {
    key: "ioc-hunter",
    label: "IOC Hunter",
    icon: Search,
    description:
      "Interactive IOC search and enrichment console (Folded from IOCHunter).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ThreatActorsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "actors";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps are primitive strings — no new object references each render.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        // URL changed externally (deep-link / back button) → update state
        setTab(urlTab);
      } else {
        // State changed (user clicked tab) → push to URL once
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
        title="Threat Actors & Indicators"
        description="Unified threat-intel workspace — actor dossiers, live tracking, attribution analysis, and IOC hunting."
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

        <TabsContent value="actors">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatActorsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="tracking">
          {/* WIRED: ActorTrackingDashboard — /api/v1/actor-tracking summary + actors + active + ttp-summary */}
          <Suspense fallback={<PageSkeleton />}>
            <ActorTrackingPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="attribution">
          <Suspense fallback={<PageSkeleton />}>
            <AttributionPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="indicators">
          <Suspense fallback={<PageSkeleton />}>
            <IndicatorsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="ioc-hunter">
          <Suspense fallback={<PageSkeleton />}>
            <IOCHunterPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
