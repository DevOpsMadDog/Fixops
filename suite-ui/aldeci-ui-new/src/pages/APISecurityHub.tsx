/**
 * APISecurityHub — Unified API Security hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone API security dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10 (API Security cluster).
 *
 *   tab        | source page                | endpoint
 *   -----------|----------------------------|----------------------------------------------
 *   inventory  | APISecurityDashboard       | /api/v1/api-security/{inventory,vulns,anomalies}
 *   management | APISecurityMgmtDashboard   | /api/v1/api-security-engine/{stats,endpoints,abuse-events,scans}
 *   discovery  | APIDiscoveryDashboard      | /api/v1/api-discovery/{stats,endpoints}
 *
 * Route: /discover/api-security
 * Persona target: AppSec Engineer (#10), API Owner (#16), Sec Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldAlert, ListChecks, Search } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "inventory" | "management" | "discovery";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "inventory",
    label: "Inventory & OWASP",
    icon: ShieldAlert,
    description:
      "API inventory with OWASP API Top 10 vulnerability breakdown, schema validation stats, and traffic anomaly feed (Folded from APISecurityDashboard).",
  },
  {
    key: "management",
    label: "Management",
    icon: ListChecks,
    description:
      "API security engine — registered endpoints, API key inventory, abuse events, and scan results with risk scoring (Folded from APISecurityMgmtDashboard).",
  },
  {
    key: "discovery",
    label: "Discovery",
    icon: Search,
    description:
      "Automated discovery of undocumented and shadow APIs with risk scoring and authentication coverage (Folded from APIDiscoveryDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function APISecurityHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "inventory";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /api-discovery → /discover/api-security?tab=discovery) work.
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
        title="API Security"
        description="Unified API security hero — inventory + OWASP API Top 10, runtime management with abuse detection, and continuous discovery of undocumented endpoints."
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

        <TabsContent value="inventory">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="management">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
        <TabsContent value="discovery">
          <Suspense fallback={<PageSkeleton />}>
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
