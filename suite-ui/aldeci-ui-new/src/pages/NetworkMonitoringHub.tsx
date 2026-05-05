/**
 * NetworkMonitoringHub — Network monitoring/anomaly/threat unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone network-observability dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (S11 Cloud Posture — Network Observability
 * sub-cluster).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|---------------------------------------------
 *   monitoring | NetworkMonitoringDashboard   | /api/v1/network-monitoring/{interfaces,alert-rules,...}
 *   anomaly    | NetworkAnomalyDashboard      | /api/v1/network-anomaly/{summary,baselines,traffic-trend}
 *   threats    | NetworkThreatsDashboard      | /api/v1/network-threats/{threats/active,rules,baselines}
 *
 * Route: /discover/network
 * Persona target: SOC T2 (#6), Network Engineer (#15), Incident Responder (#7)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, ShieldAlert, Waves } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "monitoring" | "anomaly" | "threats";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "monitoring",
    label: "Monitoring — Interfaces",
    icon: Activity,
    description:
      "Live network interfaces, alert rules, and observability inventory (Folded from NetworkMonitoringDashboard).",
  },
  {
    key: "anomaly",
    label: "Anomaly — Baselines",
    icon: Waves,
    description:
      "Traffic baselines, anomaly summary, and per-segment trend analysis (Folded from NetworkAnomalyDashboard).",
  },
  {
    key: "threats",
    label: "Threats — Active",
    icon: ShieldAlert,
    description:
      "Active network threats, detection rules, and threat baselines (Folded from NetworkThreatsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function NetworkMonitoringHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "monitoring";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /network-monitoring → /discover/network?tab=monitoring) work.
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
        title="Network Monitoring"
        description="Unified network observability workspace — live interfaces, anomaly baselines, and active threat detection."
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

        <TabsContent value="monitoring">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="anomaly">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="threats">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
