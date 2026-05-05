/**
 * NetworkSegmentationHub — Network Segmentation & Firewall unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone network-segmentation / firewall pages into a single tabbed
 * hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * Network Segmentation / Firewall sub-cluster).
 *
 *   tab        | source page                       | endpoint
 *   -----------|-----------------------------------|----------------------------------------------
 *   microseg   | MicrosegmentationPolicyDashboard  | /api/v1/microsegmentation/{segments,stats}
 *   firewall   | FirewallAnalyzer                  | /api/v1/firewall-policy/{rules,stats}
 *   policy     | FirewallPolicyDashboard           | /api/v1/firewall-policy/{firewalls,stats}
 *
 * Route: /discover/network-segmentation
 * Persona target: Platform Engineer (#20), Security Architect (#11), SRE (#19)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (Network Posture tab)
 *
 * Route in App.tsx); this fold restores its reachability via the new hub.
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Network, ShieldCheck, FileCog } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { MicrosegmentationPanel } from "@/components/network/MicrosegmentationPanel";
import { FirewallPanel } from "@/components/network/FirewallPanel";
import { ZeroTrustPolicyPanel } from "@/components/network/ZeroTrustPolicyPanel";

type TabKey = "microseg" | "firewall" | "policy";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "microseg",
    label: "Microsegmentation",
    icon: Network,
    description:
      "Network microsegmentation enforcement with policy tracking and violation monitoring (Folded from MicrosegmentationPolicyDashboard).",
  },
  {
    key: "firewall",
    label: "Firewall Analyzer",
    icon: ShieldCheck,
    description:
      "Firewall rule analysis, hit-rate stats, and shadow-rule detection (Folded from FirewallAnalyzer).",
  },
  {
    key: "policy",
    label: "Policy",
    icon: FileCog,
    description:
      "Firewall policy posture across managed devices with rule-set drift (Folded from FirewallPolicyDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function NetworkSegmentationHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "microseg";
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
        title="Network Segmentation & Firewalls"
        description="Unified network-posture workspace — microsegmentation enforcement, firewall rule analysis, and policy posture across managed devices."
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

        <TabsContent value="microseg">
          <Suspense fallback={<PageSkeleton />}>
            <MicrosegmentationPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="firewall">
          <Suspense fallback={<PageSkeleton />}>
            <FirewallPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="policy">
          <Suspense fallback={<PageSkeleton />}>
            <ZeroTrustPolicyPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
