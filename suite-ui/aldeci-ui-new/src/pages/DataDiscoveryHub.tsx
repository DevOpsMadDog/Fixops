/**
 * DataDiscoveryHub — Data Security Posture Management (DSPM) unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone DSPM / data-security pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (Data Discovery / DSPM cluster).
 *
 *   tab            | source page                  | endpoint
 *   ---------------|------------------------------|----------------------------------------------
 *   discovery      | DataDiscoveryDashboard       | /api/v1/data-discovery/datastores
 *   classification | DataClassificationDashboard  | /api/v1/data-classification/{stats,items,violations}
 *   exfiltration   | DataExfiltrationDashboard    | /api/v1/data-exfiltration/{stats,incidents}
 *
 * Route: /discover/dspm
 * Persona target: GRC Analyst (#12), Compliance Manager (#13), DPO, Security Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md (Data Discovery / DSPM sub-cluster)
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Database, Tags, AlertOctagon } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const DataDiscoveryDashboard = lazy(() => import("@/pages/DataDiscoveryDashboard"));
const DataClassificationDashboard = lazy(() => import("@/pages/DataClassificationDashboard"));
const DataExfiltrationDashboard = lazy(() => import("@/pages/DataExfiltrationDashboard"));

type TabKey = "discovery" | "classification" | "exfiltration";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "discovery",
    label: "Discovery",
    icon: Database,
    description:
      "Discovered datastores across cloud + on-prem with sensitivity context (Folded from DataDiscoveryDashboard).",
  },
  {
    key: "classification",
    label: "Classification",
    icon: Tags,
    description:
      "Sensitivity classification, PII detection, and policy violation tracking (Folded from DataClassificationDashboard).",
  },
  {
    key: "exfiltration",
    label: "Exfiltration",
    icon: AlertOctagon,
    description:
      "Exfiltration incidents and DLP detections across all egress vectors (Folded from DataExfiltrationDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function DataDiscoveryHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "discovery";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /data-discovery → /discover/dspm?tab=discovery) work.
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
        title="Data Security Posture (DSPM)"
        description="Unified data security workspace — datastore discovery, sensitivity classification, and exfiltration monitoring."
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

        <TabsContent value="discovery">
          <Suspense fallback={<PageSkeleton />}>
            <DataDiscoveryDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="classification">
          <Suspense fallback={<PageSkeleton />}>
            <DataClassificationDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="exfiltration">
          <Suspense fallback={<PageSkeleton />}>
            <DataExfiltrationDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
