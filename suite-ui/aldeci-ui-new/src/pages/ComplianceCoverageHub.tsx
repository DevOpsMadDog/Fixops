/**
 * ComplianceCoverageHub — Compliance Coverage / Gap unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone compliance-coverage pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23 (S23 Compliance Dashboard —
 * Coverage / Gap sub-cluster).
 *
 *   tab        | source page                   | endpoint
 *   -----------|-------------------------------|--------------------------------------------------
 *   gaps       | ComplianceGapDashboard        | /api/v1/compliance-gaps/{stats,assessments,gaps}
 *   cloud      | CloudComplianceDashboard      | /api/v1/cloud-compliance/{controls,stats}
 *   endpoint   | EndpointComplianceDashboard   | /api/v1/endpoint-compliance/{stats,endpoints,checks,department-compliance}
 *
 * Route: /comply/coverage
 * Persona target: GRC Analyst (#12), Compliance Manager (#13), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldAlert, Cloud, MonitorCheck } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported panel components — each wired to a real backend endpoint.
const ComplianceGapPanel = lazy(() => import("@/components/compliance/ComplianceGapPanel"));
const CloudCompliancePanel = lazy(() => import("@/components/compliance/CloudCompliancePanel"));
const EndpointCompliancePanel = lazy(() => import("@/components/compliance/EndpointCompliancePanel"));

type TabKey = "gaps" | "cloud" | "endpoint";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "gaps",
    label: "Gap Analysis",
    icon: ShieldAlert,
    description:
      "Compliance gap assessments and remediation tracking (Folded from ComplianceGapDashboard).",
  },
  {
    key: "cloud",
    label: "Cloud Coverage",
    icon: Cloud,
    description:
      "Cloud-control coverage across CIS, NIST, ISO, PCI baselines (Folded from CloudComplianceDashboard).",
  },
  {
    key: "endpoint",
    label: "Endpoint Coverage",
    icon: MonitorCheck,
    description:
      "Endpoint compliance check status by department and control family (Folded from EndpointComplianceDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function ComplianceCoverageHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "gaps";
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
        title="Compliance Coverage"
        description="Unified compliance-coverage workspace — gap analysis, cloud-control coverage, and endpoint compliance posture."
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

        <TabsContent value="gaps">
          <Suspense fallback={<PageSkeleton />}>
            <ComplianceGapPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="cloud">
          <Suspense fallback={<PageSkeleton />}>
            <CloudCompliancePanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="endpoint">
          <Suspense fallback={<PageSkeleton />}>
            <EndpointCompliancePanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
