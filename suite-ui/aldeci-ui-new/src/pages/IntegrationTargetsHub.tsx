/**
 * IntegrationTargetsHub — Outbound integration targets unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone outbound-target dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27 (S27 Integrations Hub —
 * Targets sub-cluster).
 *
 *   tab          | source page            | endpoint
 *   -------------|------------------------|----------------------------------------------
 *   prowler      | ProwlerDashboard       | /api/v1/prowler/{findings,compliance,scan}
 *   servicenow   | ServiceNowDashboard    | /api/v1/servicenow/{connections,incidents,cmdb,mappings}
 *   siem         | SIEMOutputDashboard    | /api/v1/siem-output/{targets,events,stats}
 *
 * Route: /connect/targets
 * Persona target: DevOps Engineer (#18), SRE (#19), GRC Analyst (#12), SOC T2 (#6)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Cloud, Workflow, Send } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

const ProwlerPanel    = lazy(() => import("./integration-targets/ProwlerPanel"));
const ServiceNowPanel = lazy(() => import("./integration-targets/ServiceNowPanel"));
const SIEMPanel       = lazy(() => import("./integration-targets/SIEMPanel"));

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "prowler" | "servicenow" | "siem";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "prowler",
    label: "Prowler (CSPM)",
    icon: Cloud,
    description:
      "Cloud security posture via Prowler — scan triggers, findings table, and CIS compliance scorecard (Folded from ProwlerDashboard).",
  },
  {
    key: "servicenow",
    label: "ServiceNow",
    icon: Workflow,
    description:
      "ServiceNow ITSM bridge — connection health, synced incidents, CMDB lookups, and field mappings (Folded from ServiceNowDashboard).",
  },
  {
    key: "siem",
    label: "SIEM Output",
    icon: Send,
    description:
      "Outbound SIEM forwarders (Splunk, Sentinel, QRadar) — target health, recent events, and forwarding stats (Folded from SIEMOutputDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IntegrationTargetsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "prowler";
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
        title="Integration Targets"
        description="Outbound integration targets — push posture findings to Prowler, sync incidents to ServiceNow, and forward events to your SIEM."
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

        <TabsContent value="prowler">
          <Suspense fallback={<PageSkeleton />}>
            <ProwlerPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="servicenow">
          <Suspense fallback={<PageSkeleton />}>
            <ServiceNowPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="siem">
          <Suspense fallback={<PageSkeleton />}>
            <SIEMPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
