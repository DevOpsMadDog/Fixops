/**
 * IdentityGovernanceHub — Identity Governance & Analytics unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone identity governance / analytics pages into a single
 * tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 * (S11 Cloud Posture — IAM Deep / Identity Governance sub-cluster).
 *
 *   tab        | source page                  | endpoint
 *   -----------|------------------------------|----------------------------------------------
 *   governance | IdentityGovernance           | /api/v1/identity-governance/{reviews,entitlements,stats}
 *   analytics  | IdentityAnalyticsDashboard   | /api/v1/identity-analytics/{stats,risks,profiles}
 *   digital    | DigitalIdentityDashboard     | /api/v1/digital-identity/{identities,stats}
 *
 * Route: /discover/identity-governance
 * Persona target: GRC Analyst (#12), Security Architect (#11), IAM Admin
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (IAM Deep)
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, BarChart3, Fingerprint, Grid3x3 } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { AccessMatrixPanel } from "@/components/access-matrix/AccessMatrixPanel";
import { GovernanceReviewsPanel } from "@/components/identity/GovernanceReviewsPanel";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "governance" | "analytics" | "digital" | "access-matrix";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "governance",
    label: "Governance",
    icon: ShieldCheck,
    description:
      "Access reviews, entitlements, and orphaned-account governance (Folded from IdentityGovernance).",
  },
  {
    key: "analytics",
    label: "Analytics",
    icon: BarChart3,
    description:
      "Identity risk analytics, behavioral profiles, and risk scoring (Folded from IdentityAnalyticsDashboard).",
  },
  {
    key: "digital",
    label: "Digital Identity",
    icon: Fingerprint,
    description:
      "Digital identity inventory and lifecycle stats (Folded from DigitalIdentityDashboard).",
  },
  {
    key: "access-matrix",
    label: "Access Matrix",
    icon: Grid3x3,
    description:
      "Roles × resource-types permission grid — effective access levels per ALDECI RBAC role. Live from /api/v1/access-matrix/.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function IdentityGovernanceHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "governance";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /identity-governance → /discover/identity-governance?tab=governance) work.
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
        title="Identity Governance & Analytics"
        description="Unified IAM workspace — access governance, risk analytics, and digital identity inventory."
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

        <TabsContent value="governance">
          <Suspense fallback={<PageSkeleton />}>
            <GovernanceReviewsPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="analytics">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="digital">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="access-matrix">
          <Suspense fallback={<PageSkeleton />}>
            <AccessMatrixPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
