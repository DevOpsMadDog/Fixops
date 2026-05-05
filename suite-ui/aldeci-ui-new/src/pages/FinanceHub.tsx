/**
 * FinanceHub — Executive Brief / Finance unified hero (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 5 standalone finance/executive cost-tracking pages into a single
 * tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.2 (S2 Executive
 * Brief — Investment + ROI sub-cluster).
 *
 *   tab            | source page                        | endpoint
 *   ---------------|------------------------------------|---------------------------------------------
 *   bu-heatmap     | BUDollarRiskHeatmap                | /api/v1/risk/heatmap, /api/v1/risk/brs/bu
 *   investment     | SecurityInvestmentDashboard        | /api/v1/security-investment/{investments,budget,outcomes}
 *   budget         | SecurityBudgetDashboard            | /api/v1/security-budget/{stats,allocations,transactions}
 *   incident-costs | IncidentCostsDashboard             | /api/v1/incident-costs/{costs,stats}
 *   cyber-insur    | CyberInsuranceDashboard            | /api/v1/cyber-insurance/{policies,claims,assessments,stats}
 *
 * Route: /mission-control/finance
 * Persona target: CISO (#1), CFO (#4)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.2
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  DollarSign,
  TrendingUp,
  Wallet,
  AlertTriangle,
  Shield,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { BUHeatmapPanel } from "@/components/finance/BUHeatmapPanel";
import { InvestmentPanel } from "@/components/finance/InvestmentPanel";
import { BudgetPanel } from "@/components/finance/BudgetPanel";
import { IncidentCostsPanel } from "@/components/finance/IncidentCostsPanel";
import { CyberInsurancePanel } from "@/components/finance/CyberInsurancePanel";

type TabKey =
  | "bu-heatmap"
  | "investment"
  | "budget"
  | "incident-costs"
  | "cyber-insur";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "bu-heatmap",
    label: "BU Dollar Risk",
    icon: DollarSign,
    description:
      "Dollar-weighted risk heatmap across business units (Folded from BUDollarRiskHeatmap).",
  },
  {
    key: "investment",
    label: "Investment & ROI",
    icon: TrendingUp,
    description:
      "Security investments, allocations, and measurable risk-reduction outcomes (Folded from SecurityInvestmentDashboard).",
  },
  {
    key: "budget",
    label: "Budget",
    icon: Wallet,
    description:
      "Annual security budget tracking — allocations vs spend with transaction trail (Folded from SecurityBudgetDashboard).",
  },
  {
    key: "incident-costs",
    label: "Incident Costs",
    icon: AlertTriangle,
    description:
      "Per-incident cost ledger with breach, downtime, and recovery breakdown (Folded from IncidentCostsDashboard).",
  },
  {
    key: "cyber-insur",
    label: "Cyber Insurance",
    icon: Shield,
    description:
      "Policy coverage, claims, and underwriter assessments (Folded from CyberInsuranceDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function FinanceHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "bu-heatmap";
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
        title="Finance & Investment"
        description="Executive view of dollar risk, security investment ROI, budgets, incident costs, and cyber insurance."
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

        <TabsContent value="bu-heatmap">
          <Suspense fallback={<PageSkeleton />}>
            <BUHeatmapPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="investment">
          {/* WIRED: SecurityInvestmentDashboard — /api/v1/security-investment portfolio + investments */}
          <Suspense fallback={<PageSkeleton />}>
            <InvestmentPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="budget">
          <Suspense fallback={<PageSkeleton />}>
            <BudgetPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="incident-costs">
          <Suspense fallback={<PageSkeleton />}>
            <IncidentCostsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="cyber-insur">
          <Suspense fallback={<PageSkeleton />}>
            <CyberInsurancePanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
