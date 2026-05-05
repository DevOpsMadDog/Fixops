/**
 * SecretsHub — Secrets management & detection unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone secrets pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10 (S10 Code Intelligence —
 * Secrets sub-cluster).
 *
 *   tab        | source page              | endpoint
 *   -----------|--------------------------|----------------------------------------------
 *   detection  | SecretsDetection         | /api/v1/secrets-management/{secrets,...}
 *   scanner    | SecretScannerDashboard   | /api/v1/secret-scanner/{scan-jobs,findings,stats}
 *   rotation   | SecretsRotation          | /api/v1/secrets-management/{secrets,expiring,stats}
 *
 * Route: /discover/secrets-hub
 * Persona target: AppSec Engineer (#10), DevOps (#18), SecOps (#5/#6)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10
 *
 * Note: SecretScannerDashboard was previously orphan-imported in App.tsx
 * (no Route) — this fold restores reachability.
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Key, ScanSearch, RotateCw } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { SecretsDetectionPanel } from "@/components/secrets/SecretsDetectionPanel";
import { SecretScannerPanel } from "@/components/secrets/SecretScannerPanel";
import { SecretsRotationPanel } from "@/components/secrets/SecretsRotationPanel";

type TabKey = "detection" | "scanner" | "rotation";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "detection",
    label: "Detection",
    icon: Key,
    description:
      "Live secrets inventory with status filtering, history, and rotate/revoke actions (Folded from SecretsDetection).",
  },
  {
    key: "scanner",
    label: "Scanner",
    icon: ScanSearch,
    description:
      "Repository / filesystem scan jobs and findings (Folded from SecretScannerDashboard — restored from orphan import).",
  },
  {
    key: "rotation",
    label: "Rotation",
    icon: RotateCw,
    description:
      "Expiring credentials and on-demand rotation operations (Folded from SecretsRotation).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function SecretsHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "detection";
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
        title="Secrets"
        description="Unified secrets workspace — detection inventory, code-base scanner, and rotation lifecycle."
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

        <TabsContent value="detection">
          <Suspense fallback={<PageSkeleton />}>
            <SecretsDetectionPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="scanner">
          <Suspense fallback={<PageSkeleton />}>
            <SecretScannerPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="rotation">
          <Suspense fallback={<PageSkeleton />}>
            <SecretsRotationPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
