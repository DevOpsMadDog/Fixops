/**
 * AssetInventoryHub — Asset Inventory metadata unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone asset-metadata pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.9 (S9 Inventory —
 * Asset metadata sub-cluster: groups + tags + criticality).
 *
 *   tab          | source page                  | endpoint
 *   -------------|------------------------------|----------------------------------------------
 *   groups       | AssetGroupsDashboard         | /api/v1/asset-groups/groups
 *   tags         | AssetTagsDashboard           | /api/v1/asset-tags/{tags,stats}
 *   criticality  | AssetCriticalityDashboard    | /api/v1/asset-criticality/*
 *
 * Route: /discover/assets/inventory
 * Persona target: Asset Owner (#15), GRC Analyst (#12), Platform Eng (#16)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.9
 *
 * Sibling note: the asset-listing hero (`AssetInventory.tsx` at `/assets`) is
 * preserved as-is — this hub focuses on the metadata management surfaces that
 * sit above the inventory table (grouping, tagging, criticality scoring).
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Layers, Tag, AlertTriangle } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const AssetGroupsDashboard = lazy(() => import("@/pages/AssetGroupsDashboard"));
const AssetTagsDashboard = lazy(() => import("@/pages/AssetTagsDashboard"));
const AssetCriticalityDashboard = lazy(() => import("@/pages/AssetCriticalityDashboard"));

type TabKey = "groups" | "tags" | "criticality";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "groups",
    label: "Groups",
    icon: Layers,
    description:
      "Asset groups with member and policy tracking — bulk membership and per-group stats (Folded from AssetGroupsDashboard).",
  },
  {
    key: "tags",
    label: "Tags",
    icon: Tag,
    description:
      "Asset tag inventory and assignment statistics across the fleet (Folded from AssetTagsDashboard).",
  },
  {
    key: "criticality",
    label: "Criticality",
    icon: AlertTriangle,
    description:
      "Tier distribution, criticality factors, critical-path BFS, and top-10 critical assets (Folded from AssetCriticalityDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function AssetInventoryHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "groups";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /asset-groups → /discover/assets/inventory?tab=groups) work.
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
        title="Asset Inventory Metadata"
        description="Unified asset-management workspace — groups, tags, and criticality scoring across the fleet."
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

        <TabsContent value="groups">
          <Suspense fallback={<PageSkeleton />}>
            <AssetGroupsDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="tags">
          <Suspense fallback={<PageSkeleton />}>
            <AssetTagsDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="criticality">
          <Suspense fallback={<PageSkeleton />}>
            <AssetCriticalityDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
