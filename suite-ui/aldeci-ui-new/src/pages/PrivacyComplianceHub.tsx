/**
 * PrivacyComplianceHub — Privacy & Control Testing unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone privacy/control dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23 (S23 Compliance — Privacy/Controls sub-cluster).
 *
 *   tab        | source page                       | endpoint
 *   -----------|-----------------------------------|----------------------------------------------
 *   gdpr       | PrivacyGDPRDashboard              | /api/v1/privacy/{stats,dsrs,consents,incidents,processing-activities}
 *   impact     | PrivacyImpactDashboard            | /api/v1/privacy-impact/assessments
 *   controls   | ControlTestingDashboard           | /api/v1/control-testing/controls
 *
 * Route: /comply/privacy
 * Persona target: GRC Analyst (#12), Compliance Mgr (#13), CISO (#1)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.23
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldAlert, FileSearch, ClipboardCheck } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported panel components — each wired to a real backend endpoint.
const PrivacyGDPRPanel = lazy(() => import("@/components/privacy/PrivacyGDPRPanel"));
const PrivacyImpactPanel = lazy(() => import("@/components/privacy/PrivacyImpactPanel"));
const ControlTestingPanel = lazy(() => import("@/components/privacy/ControlTestingPanel"));

type TabKey = "gdpr" | "impact" | "controls";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "gdpr",
    label: "Privacy & GDPR",
    icon: ShieldAlert,
    description:
      "Data subject requests, consents, privacy incidents, and processing activities (Folded from PrivacyGDPRDashboard).",
  },
  {
    key: "impact",
    label: "Privacy Impact",
    icon: FileSearch,
    description:
      "Privacy impact assessments (PIAs) for regulatory and DPIA-driven workflows (Folded from PrivacyImpactDashboard).",
  },
  {
    key: "controls",
    label: "Control Testing",
    icon: ClipboardCheck,
    description:
      "Security control testing lifecycle — failing controls, due tests, effectiveness scores (Folded from ControlTestingDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PrivacyComplianceHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "gdpr";
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
        title="Privacy & Controls"
        description="Unified privacy compliance hero — GDPR/DSR workflows, privacy impact assessments, and control testing lifecycle."
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

        <TabsContent value="gdpr">
          <Suspense fallback={<PageSkeleton />}>
            <PrivacyGDPRPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="impact">
          <Suspense fallback={<PageSkeleton />}>
            <PrivacyImpactPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="controls">
          <Suspense fallback={<PageSkeleton />}>
            <ControlTestingPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
