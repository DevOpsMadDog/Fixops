/**
 * AssetInventoryHub — Asset Inventory unified hero (8 tabs)
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Original 3-tab fold (groups + tags + criticality) per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.9.
 *
 * 2026-05-02 expansion (this commit) absorbs the 5 inventory pages flagged
 * by docs/legacy_dashboard_sweep_2026-05-02.md §3 Cluster C —
 * "AssetInventoryHub consolidation target":
 *
 *   tab           | source page                       | endpoint(s)
 *   --------------|-----------------------------------|------------------------------------------
 *   groups        | AssetGroupsDashboard              | /api/v1/asset-groups/groups
 *   tags          | AssetTagsDashboard                | /api/v1/asset-tags/{tags,stats}
 *   criticality   | AssetCriticalityDashboard         | /api/v1/asset-criticality/*
 *   cmdb          | CMDBDashboard                     | /api/v1/cmdb/{cis,changes}
 *   risk          | AssetRiskDashboard                | /api/v1/asset-risk/{scores,heatmap}
 *   cloud-res     | CloudResourceInventoryDashboard   | /api/v1/cloud-inventory/resources
 *   snapshot      | AgentlessSnapshotDashboard        | /api/v1/agentless-snapshot/*
 *   cloud-accts   | CloudAccountsDashboard            | /api/v1/cloud-accounts/accounts
 *
 * Route: /discover/assets/inventory
 * Persona target: Asset Owner (#15), GRC Analyst (#12), Platform Eng (#16),
 *                 Cloud Security Eng (#17), CMDB Owner (#23)
 *
 * Sibling note: the asset-listing hero (`AssetInventory.tsx` at `/assets`) is
 * preserved as-is — this hub focuses on the metadata + risk + cloud-resource
 * surfaces that sit above the inventory table.
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Layers,
  Tag,
  AlertTriangle,
  Database,
  ShieldAlert,
  Cloud,
  Camera,
  Server,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { AssetGroupsPanel } from "@/components/assets/AssetGroupsPanel";
import { AssetTagsPanel } from "@/components/assets/AssetTagsPanel";
import { AssetCriticalityPanel } from "@/components/assets/AssetCriticalityPanel";
import { CMDBPanel } from "@/components/assets/CMDBPanel";
import { AssetRiskPanel } from "@/components/assets/AssetRiskPanel";
import { CloudResourcesPanel } from "@/components/assets/CloudResourcesPanel";
import { AgentlessSnapshotPanel } from "@/components/assets/AgentlessSnapshotPanel";
import { CloudAccountsPanel } from "@/components/assets/CloudAccountsPanel";

type TabKey =
  | "groups"
  | "tags"
  | "criticality"
  | "cmdb"
  | "risk"
  | "cloud-res"
  | "snapshot"
  | "cloud-accts";

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
  {
    key: "cmdb",
    label: "CMDB",
    icon: Database,
    description:
      "Configuration Items inventory, type breakdowns, environment distribution, and recent changes (Folded from CMDBDashboard).",
  },
  {
    key: "risk",
    label: "Risk",
    icon: ShieldAlert,
    description:
      "Asset risk scoring, heatmap by type × criticality, top-15 highest-risk assets, and risk-factor breakdown (Folded from AssetRiskDashboard).",
  },
  {
    key: "cloud-res",
    label: "Cloud Resources",
    icon: Cloud,
    description:
      "Live cloud resource inventory across providers — instance, storage, identity, and network resources (Folded from CloudResourceInventoryDashboard).",
  },
  {
    key: "snapshot",
    label: "Snapshots",
    icon: Camera,
    description:
      "Agentless workload snapshots — scans running VMs/containers without installing agents (Folded from AgentlessSnapshotDashboard).",
  },
  {
    key: "cloud-accts",
    label: "Cloud Accounts",
    icon: Server,
    description:
      "Connected AWS/Azure/GCP accounts with sync status, regions, and resource counts (Folded from CloudAccountsDashboard).",
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
        title="Asset Inventory"
        description="Unified asset workspace — groups, tags, criticality, CMDB, risk scoring, cloud resources, snapshots, and accounts."
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
            <AssetGroupsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="tags">
          <Suspense fallback={<PageSkeleton />}>
            <AssetTagsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="criticality">
          <Suspense fallback={<PageSkeleton />}>
            <AssetCriticalityPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="cmdb">
          <Suspense fallback={<PageSkeleton />}>
            <CMDBPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="risk">
          <Suspense fallback={<PageSkeleton />}>
            <AssetRiskPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="cloud-res">
          <Suspense fallback={<PageSkeleton />}>
            <CloudResourcesPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="snapshot">
          <Suspense fallback={<PageSkeleton />}>
            <AgentlessSnapshotPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="cloud-accts">
          <Suspense fallback={<PageSkeleton />}>
            <CloudAccountsPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
