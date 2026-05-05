/**
 * ThreatModelingHub — Attack Paths Threat-Modeling unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone threat-modeling pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.12 (S12 Attack Paths —
 * Modeling tab cluster).
 *
 *   tab       | source page                          | endpoint
 *   ----------|--------------------------------------|--------------------------------------------
 *   models    | ThreatModelDashboard                 | /api/v1/threat-modeling/{models,threats}
 *   cyber     | CyberThreatModelingDashboard         | /api/v1/cyber-threat-models/{models,stats}
 *   pipeline  | ThreatModelingPipelineDashboard      | /api/v1/threat-modeling-pipeline/{models,stride,unmitigated}
 *
 * Route: /attack/threat-modeling
 * Persona target: Sec Architect (#11), AppSec Engineer (#10), Threat Hunter (#8)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.12
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Layers, Network, ShieldOff } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.


type TabKey = "models" | "cyber" | "pipeline";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "models",
    label: "STRIDE Models",
    icon: Layers,
    description:
      "STRIDE auto-generation, model catalog, threat lists, and mitigation tracking (Folded from ThreatModelDashboard).",
  },
  {
    key: "cyber",
    label: "Cyber Models",
    icon: Network,
    description:
      "Cyber-threat model catalog with attack-graph linkage and live API stats (Folded from CyberThreatModelingDashboard).",
  },
  {
    key: "pipeline",
    label: "Modeling Pipeline",
    icon: ShieldOff,
    description:
      "Continuous threat-modeling pipeline — STRIDE coverage and unmitigated threat queue (Folded from ThreatModelingPipelineDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ThreatModelingHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "models";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /threat-models → /attack/threat-modeling?tab=models) work.
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
        title="Threat Modeling"
        description="Unified threat-modeling workspace — STRIDE models, cyber-threat catalog, and continuous modeling pipeline."
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

        <TabsContent value="models">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="cyber">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="pipeline">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
