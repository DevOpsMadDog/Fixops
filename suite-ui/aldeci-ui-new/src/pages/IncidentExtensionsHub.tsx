/**
 * IncidentExtensionsHub — Incident Response extensions unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone IR-extension dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22 (S22 Incident Response —
 * Extensions sub-cluster). Sits alongside the main S22 IR Console and
 * complements ForensicsHub (already folded at /remediate/forensics).
 *
 *   tab          | source page              | endpoint
 *   -------------|--------------------------|----------------------------------------------
 *   cloud        | CloudIRDashboard         | /api/v1/cloud-ir/*
 *   breach       | BreachResponse           | /api/v1/breach-response/{stats,cases}
 *   comms        | IncidentCommsDashboard   | /api/v1/incident-comms/{communications,stats}
 *
 * Route: /remediate/incidents/extensions
 * Persona target: IR Lead (#7), SOC T2 (#6), Crisis Comms (#13)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Cloud, ShieldAlert, MessageCircle } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "cloud" | "breach" | "comms";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "cloud",
    label: "Cloud IR",
    icon: Cloud,
    description:
      "Cloud-native incident response — multi-cloud incident triage, runbook execution and snapshot evidence (Folded from CloudIRDashboard).",
  },
  {
    key: "breach",
    label: "Breach Response",
    icon: ShieldAlert,
    description:
      "Active breach cases, response timeline, regulator notifications and disclosure status (Folded from BreachResponse).",
  },
  {
    key: "comms",
    label: "Comms",
    icon: MessageCircle,
    description:
      "Incident communications log — stakeholder updates, internal channels and external disclosures (Folded from IncidentCommsDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IncidentExtensionsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "cloud";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /cloud-ir → /remediate/incidents/extensions?tab=cloud) work.
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
        title="Incident Extensions"
        description="Cloud IR, breach response and stakeholder comms — unified IR extensions complementing the core IR Console."
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

        <TabsContent value="cloud">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="breach">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="comms">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
