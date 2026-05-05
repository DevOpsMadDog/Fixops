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
 *   feed-status   | AirGapBundleConsole     | GET /api/v1/air-gap/feed-status
 *   feeds         | OfflineFeedRegistry     | GET /api/v1/air-gap/feeds
 *   update-status | OfflineUpdateStatus     | GET /api/v1/air-gap/update-status
 *
 * Route: /connect/mcp/air-gap
 * Persona target: DevOps Engineer (#18), SRE (#19), Automation Engineer (#25)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.28
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, Database, Download } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

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
      "Live status of air-gap intel feed bundles — staleness, last sync, operator-loaded snapshot health (Folded from AirGapBundleConsole).",
  },
  {
    key: "feeds",
    label: "Feed Registry",
    icon: Database,
    description:
      "Registry of offline intel feeds available for air-gap deployment, with manifest, version, and signature metadata (Folded from OfflineFeedRegistry).",
  },
  {
    key: "update-status",
    label: "Update Status",
    icon: Download,
    description:
      "Air-gap update progress: bundles received, applied, pending, and rollback availability (Folded from OfflineUpdateStatus).",
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

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /air-gap/feeds → /connect/mcp/air-gap?tab=feeds) work.
  useEffect(() => {
    if (params.get("tab") !== tab) {
      const next = new URLSearchParams(params);
      next.set("tab", tab);
      setParams(next, { replace: true });
    }
  }, [tab, params, setParams]);

  // React when query string changes (e.g. user clicks an old link in another tab).
  useEffect(() => {
    const incoming = params.get("tab");
    if (isTabKey(incoming) && incoming !== tab) setTab(incoming);
  }, [params, tab]);

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
          </Suspense>
        </TabsContent>
        <TabsContent value="feeds">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="update-status">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
