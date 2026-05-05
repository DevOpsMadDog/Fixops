/**
 * SupplyChainHub — Supply Chain Risk & Intelligence unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone supply-chain dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.4 (S4 SLA & Risk Register —
 * Supply Chain by-domain sub-cluster) cross-listed with §2.10 (S10 Code
 * Intelligence — Supply Chain tab).
 *
 *   tab          | source page                  | endpoint
 *   -------------|------------------------------|---------------------------------------------------------
 *   security     | SupplyChainSecurity          | /api/v1/supply-chain/{risk-summary,dependencies}
 *   risk         | SupplyChainDashboard         | /api/v1/supply-chain/{vendors,stats,components}
 *   intel        | SupplyChainIntelDashboard    | /api/v1/supply-chain-intel/{stats,packages,sbom,malicious,vulns,check}
 *
 * Route: /discover/supply-chain
 * Persona target: Vulnerability Manager (#9), AppSec Engineer (#10), Sec Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.4 / §2.10
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, Network, Radar } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

import { SupplyChainSecurityPanel } from "@/pages/supply-chain/SupplyChainSecurityPanel";
import { SupplyChainRiskPanel } from "@/pages/supply-chain/SupplyChainRiskPanel";
import { SupplyChainIntelPanel } from "@/pages/supply-chain/SupplyChainIntelPanel";

type TabKey = "security" | "risk" | "intel";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "security",
    label: "Security",
    icon: ShieldCheck,
    description:
      "SBOM analysis, dependency risk, license compliance, transitive dependencies (Folded from SupplyChainSecurity).",
  },
  {
    key: "risk",
    label: "Vendor Risk",
    icon: Network,
    description:
      "Third-party vendor and component risk — supplier tiering, EOL components, risk breakdown (Folded from SupplyChainDashboard).",
  },
  {
    key: "intel",
    label: "Intelligence",
    icon: Radar,
    description:
      "Package vulnerability tracking, malicious package detection and SBOM intelligence (Folded from SupplyChainIntelDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function SupplyChainHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "security";
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
        title="Supply Chain"
        description="Unified supply-chain hero — SBOM & dependency security, third-party vendor risk, and package intelligence."
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

        <TabsContent value="security">
          <Suspense fallback={<PageSkeleton />}>
            <SupplyChainSecurityPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="risk">
          <Suspense fallback={<PageSkeleton />}>
            <SupplyChainRiskPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="intel">
          <Suspense fallback={<PageSkeleton />}>
            <SupplyChainIntelPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
