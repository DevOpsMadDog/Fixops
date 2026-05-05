/**
 * ThreatIntelOpsHub — Threat Intelligence Operations unified hero
 * (Phase 3 UX consolidation, 2026-05-02 — combined 4-page pair)
 *
 * Folds 4 standalone threat-intel operations dashboards into a single tabbed
 * hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14 (Threat Intel Ops
 * combined sub-cluster — backlog 51 / item 52 follow-up: pair-merge of two
 * adjacent 2-page candidates into one 4-page hero).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|----------------------------------------------
 *   watchlist  | WatchlistManager             | /api/v1/ioc-enrichment/{stats,iocs}, /threat-actors
 *   feeds      | FeedSubscriptionsDashboard   | /api/v1/feed-subscriptions/subscriptions
 *   briefs     | ThreatBriefDashboard         | /api/v1/threat-briefs
 *   response   | ThreatResponseDashboard      | /api/v1/threat-response/{incidents/active,playbooks}
 *
 * Route: /attack/intel/ops
 * Persona target: Threat Intel Analyst (#9), SOC Analyst (#7), IR Lead (#10), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Eye, Rss, FileText, Siren } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { WatchlistPanel } from "@/components/threat-intel/WatchlistPanel";
import { FeedSubscriptionsPanel } from "@/components/threat-intel/FeedSubscriptionsPanel";
import { ThreatBriefsPanel } from "@/components/threat-intel/ThreatBriefsPanel";
import { ThreatResponsePanel } from "@/components/threat-intel/ThreatResponsePanel";

type TabKey = "watchlist" | "feeds" | "briefs" | "response";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "watchlist",
    label: "Watchlist",
    icon: Eye,
    description:
      "Threat actor and IOC watchlist — active indicators, daily matches, auto-block actions (Folded from WatchlistManager).",
  },
  {
    key: "feeds",
    label: "Feed Subscriptions",
    icon: Rss,
    description:
      "Threat-intel feed subscriptions, ingestion logs, delivery configs and refresh-interval health (Folded from FeedSubscriptionsDashboard).",
  },
  {
    key: "briefs",
    label: "Threat Briefs",
    icon: FileText,
    description:
      "Distributed threat briefs with TLP classification, recipient tracking and brief-type rollups (Folded from ThreatBriefDashboard).",
  },
  {
    key: "response",
    label: "Response",
    icon: Siren,
    description:
      "Active threat-response incidents and the playbooks driving containment / eradication (Folded from ThreatResponseDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ThreatIntelOpsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "watchlist";
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
        title="Threat Intel Operations"
        description="Unified threat-intel operations hero — watchlists, feed subscriptions, distributed briefs, and active incident response."
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

        <TabsContent value="watchlist">
          <Suspense fallback={<PageSkeleton />}>
            <WatchlistPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="feeds">
          <Suspense fallback={<PageSkeleton />}>
            <FeedSubscriptionsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="briefs">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatBriefsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="response">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatResponsePanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
