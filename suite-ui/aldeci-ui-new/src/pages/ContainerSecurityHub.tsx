/**
 * ContainerSecurityHub — Container Security unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone container-security pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * Container Security sub-cluster).
 *
 *   tab      | source page                      | endpoint
 *   ---------|----------------------------------|---------------------------------------------------
 *   image    | ContainerSecurityDashboard       | /api/v1/containers/{policies}, /api/v1/kubernetes-security/stats
 *   runtime  | ContainerRuntimeSecurityDashboard| /api/v1/container-runtime/{stats,containers,violations}
 *   posture  | ContainerPostureDashboard        | /api/v1/container-posture/{clusters,stats}
 *
 * Route: /discover/container-security
 * Persona target: Container Engineer (#15), DevSecOps (#14), Cloud Security Architect (#19)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Box, ShieldAlert, Activity } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ContainerImagePanel } from "@/components/container/ContainerImagePanel";
import { ContainerRuntimePanel } from "@/components/container/ContainerRuntimePanel";
import { ContainerPosturePanel } from "@/components/container/ContainerPosturePanel";

type TabKey = "image" | "runtime" | "posture";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "image",
    label: "Image & Build",
    icon: Box,
    description:
      "Image analysis, policies, drift, and CIS benchmarks for container builds (Folded from ContainerSecurityDashboard).",
  },
  {
    key: "runtime",
    label: "Runtime",
    icon: Activity,
    description:
      "Live container runtime monitoring, behavioral baselines, and policy violations (Folded from ContainerRuntimeSecurityDashboard).",
  },
  {
    key: "posture",
    label: "Cluster Posture",
    icon: ShieldAlert,
    description:
      "Kubernetes cluster posture across managed environments (Folded from ContainerPostureDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ContainerSecurityHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "image";
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
        title="Container Security"
        description="Unified container security workspace — image scans, runtime monitoring, and Kubernetes cluster posture."
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

        <TabsContent value="image">
          <Suspense fallback={<PageSkeleton />}>
            <ContainerImagePanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="runtime">
          <Suspense fallback={<PageSkeleton />}>
            <ContainerRuntimePanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="posture">
          <Suspense fallback={<PageSkeleton />}>
            <ContainerPosturePanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
