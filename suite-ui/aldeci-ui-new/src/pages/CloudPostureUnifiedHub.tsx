/**
 * CloudPostureUnifiedHub — Cloud-Native Application Protection unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds the four core CNAPP-pillar pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture —
 * CNAPP Unified sub-cluster). Replaces fragmented /cloud-security, /cwp,
 * /cwpp, /cnapp routes with one Wiz/Apiiro-style cohesive console.
 *
 *   tab       | source page                      | endpoint
 *   ----------|----------------------------------|---------------------------------------------------
 *   posture   | CloudSecurityDashboard            | /api/v1/cloud/{accounts,benchmarks,findings},
 *             |                                   | /api/v1/cloud-security-engine/{accounts,findings,stats}
 *   workloads | CloudWorkloadProtectionDashboard  | /api/v1/cwp/{stats,workloads,threats}
 *   platform  | CWPPDashboard                     | /api/v1/cnapp/{workloads,threats,stats}
 *   unified   | CNAPPDashboard                    | /api/v1/cnapp/{workloads,findings,stats}
 *
 * Route: /discover/cloud-posture
 * Persona target: Cloud Security Architect (#19), DevSecOps (#14), Platform Engineer (#15)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Cloud, ShieldCheck, Layers, Workflow } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const CloudSecurityDashboard = lazy(() => import("@/pages/CloudSecurityDashboard"));
const CloudWorkloadProtectionDashboard = lazy(
  () => import("@/pages/CloudWorkloadProtectionDashboard"),
);
const CWPPDashboard = lazy(() => import("@/pages/CWPPDashboard"));
const CNAPPDashboard = lazy(() => import("@/pages/CNAPPDashboard"));

type TabKey = "posture" | "workloads" | "platform" | "unified";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "posture",
    label: "Cloud Posture (CSPM)",
    icon: Cloud,
    description:
      "Multi-cloud misconfiguration, account inventory, benchmarks, and findings (Folded from CloudSecurityDashboard).",
  },
  {
    key: "workloads",
    label: "Workload Protection (CWP)",
    icon: ShieldCheck,
    description:
      "Cloud workload runtime protection, threat detection, and per-workload health (Folded from CloudWorkloadProtectionDashboard).",
  },
  {
    key: "platform",
    label: "CWPP",
    icon: Layers,
    description:
      "Cloud Workload Protection Platform — workloads, threats, and platform-wide stats (Folded from CWPPDashboard).",
  },
  {
    key: "unified",
    label: "Unified CNAPP",
    icon: Workflow,
    description:
      "Single-pane CNAPP view across CSPM + CWPP + CIEM with unified findings, workloads, and posture trio (Folded from CNAPPDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function CloudPostureUnifiedHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "posture";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /cloud-security → /discover/cloud-posture?tab=posture) work.
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
        title="Cloud Posture & CNAPP"
        description="Unified cloud-native application protection workspace — posture (CSPM), workload protection (CWP/CWPP), and the cross-pillar CNAPP view."
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

        <TabsContent value="posture">
          <Suspense fallback={<PageSkeleton />}>
            <CloudSecurityDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="workloads">
          <Suspense fallback={<PageSkeleton />}>
            <CloudWorkloadProtectionDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="platform">
          <Suspense fallback={<PageSkeleton />}>
            <CWPPDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="unified">
          <Suspense fallback={<PageSkeleton />}>
            <CNAPPDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
