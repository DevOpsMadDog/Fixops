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
 *   models    | ThreatModelDashboard                 | /api/v1/threat-modeling/{models,stride-categories}
 *   cyber     | CyberThreatModelingDashboard         | /api/v1/cyber-threat-models/{summary,unmitigated}
 *   pipeline  | ThreatModelingPipelineDashboard      | /api/v1/threat-modeling-pipeline/{models,unmitigated}
 *
 * Route: /attack/threat-modeling
 * Persona target: Sec Architect (#11), AppSec Engineer (#10), Threat Hunter (#8)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.12
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Layers, Network, ShieldOff } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { StrideModelsPanel } from "@/components/threat-modeling/StrideModelsPanel";
import { CyberModelsPanel } from "@/components/threat-modeling/CyberModelsPanel";
import { ModelingPipelinePanel } from "@/components/threat-modeling/ModelingPipelinePanel";

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
      "STRIDE auto-generation, model catalog, threat lists, and mitigation tracking (/api/v1/threat-modeling/models).",
  },
  {
    key: "cyber",
    label: "Cyber Models",
    icon: Network,
    description:
      "Cyber-threat model catalog with attack-graph linkage and live API stats (/api/v1/cyber-threat-models/summary).",
  },
  {
    key: "pipeline",
    label: "Modeling Pipeline",
    icon: ShieldOff,
    description:
      "Continuous threat-modeling pipeline — STRIDE coverage and unmitigated threat queue (/api/v1/threat-modeling-pipeline/models).",
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
            <StrideModelsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="cyber">
          <Suspense fallback={<PageSkeleton />}>
            <CyberModelsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="pipeline">
          <Suspense fallback={<PageSkeleton />}>
            <ModelingPipelinePanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
