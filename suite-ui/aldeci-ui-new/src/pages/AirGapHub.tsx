/**
 * AirGapHub — Air-Gap Operational Triad unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone air-gap operational pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.28 (S28 MCP Gateway —
 * Air-Gap operational sub-cluster).
 *
 *   tab           | source page             | endpoint
 *   --------------|-------------------------|----------------------------------------------
 *   feed-status   | AirGapBundleConsole     | GET /api/v1/airgap/status
 *   feeds         | OfflineFeedRegistry     | GET /api/v1/air-gap/bundle/list + stats
 *   update-status | OfflineUpdateStatus     | GET /api/v1/airgap/updates/history
 *
 * Route: /connect/mcp/air-gap
 * Persona target: DevOps Engineer (#18), SRE (#19), Automation Engineer (#25)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.28
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, Database, Download } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

import { AirGapFeedStatusPanel } from "@/components/airgap/AirGapFeedStatusPanel";
import { AirGapFeedsPanel } from "@/components/airgap/AirGapFeedsPanel";
import { AirGapUpdateStatusPanel } from "@/components/airgap/AirGapUpdateStatusPanel";

type TabKey = "feed-status" | "feeds" | "update-status";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "feed-status",
    label: "Feed Status",
    icon: Activity,
    description:
      "Live status of air-gap mode, FIPS compliance, local LLM, and network isolation (Folded from AirGapBundleConsole).",
  },
  {
    key: "feeds",
    label: "Feed Registry",
    icon: Database,
    description:
      "Registry of offline intel feed bundles available for air-gap deployment, with manifest, version, and status (Folded from OfflineFeedRegistry).",
  },
  {
    key: "update-status",
    label: "Update Status",
    icon: Download,
    description:
      "History of applied offline update packages — vuln DB, signatures, compliance rules, LLM models (Folded from OfflineUpdateStatus).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AirGapHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "feed-status";
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
        title="Air-Gap Operations"
        description="Unified air-gap workspace — feed status, feed registry, and update propagation for disconnected deployments."
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

        <TabsContent value="feed-status">
          <Suspense fallback={<PageSkeleton />}>
            <AirGapFeedStatusPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="feeds">
          <Suspense fallback={<PageSkeleton />}>
            <AirGapFeedsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="update-status">
          <Suspense fallback={<PageSkeleton />}>
            <AirGapUpdateStatusPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
