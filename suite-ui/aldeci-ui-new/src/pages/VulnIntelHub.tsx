/**
 * VulnIntelHub — Vulnerability Intelligence unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 4 standalone vulnerability-intelligence / external-threat-context pages
 * into a single tabbed hero per docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.7
 * (S7 Findings Explorer — Vulnerability Intelligence sub-cluster).
 *
 *   tab          | source page                  | endpoint
 *   -------------|------------------------------|----------------------------------------------
 *   vuln-intel   | VulnIntelligenceDashboard    | /api/v1/vuln-intel/{stats,cves,advisories,subscriptions}
 *   cve-search   | CVESearch                    | /api/v1/cve/{vulnerabilities,stats}
 *   ip-rep       | IPReputationDashboard        | /api/v1/ip-reputation/{blocklist,stats}
 *   geolocation  | ThreatGeolocationDashboard   | /api/v1/threat-geolocation/{stats,heatmap}
 *
 * VulnIntelFusionDashboard was already folded into /issues#vuln-intel-fusion
 * earlier (P3 fold 2026-04-27) — not duplicated here.
 *
 * Route: /discover/vuln-intel
 * Persona target: Vulnerability Manager (#9), SOC T2 (#6), Threat Hunter (#8)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.7
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldAlert, Search, Globe, Map } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.
const VulnIntelligenceDashboard = lazy(() => import("@/pages/VulnIntelligenceDashboard"));
const CVESearch = lazy(() => import("@/pages/CVESearch"));
const IPReputationDashboard = lazy(() => import("@/pages/IPReputationDashboard"));
const ThreatGeolocationDashboard = lazy(() => import("@/pages/ThreatGeolocationDashboard"));

type TabKey = "vuln-intel" | "cve-search" | "ip-rep" | "geolocation";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "vuln-intel",
    label: "Vuln Intelligence",
    icon: ShieldAlert,
    description:
      "Aggregated CVE feed, vendor advisories, and active subscriptions (Folded from VulnIntelligenceDashboard).",
  },
  {
    key: "cve-search",
    label: "CVE Search",
    icon: Search,
    description:
      "Direct CVE lookup with severity / CVSS filtering against the local CVE database (Folded from CVESearch).",
  },
  {
    key: "ip-rep",
    label: "IP Reputation",
    icon: Globe,
    description:
      "Live IP blocklist enrichment with threat-source attribution (Folded from IPReputationDashboard).",
  },
  {
    key: "geolocation",
    label: "Geolocation",
    icon: Map,
    description:
      "Geographic heatmap of observed threat origins and country-level statistics (Folded from ThreatGeolocationDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function VulnIntelHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "vuln-intel";
  const [tab, setTab] = useState<TabKey>(initial);

  // Keep ?tab= in sync with the active tab so deep-links and old-route
  // redirects (e.g. /cve-search → /discover/vuln-intel?tab=cve-search) work.
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
        title="Vulnerability Intelligence"
        description="Unified vuln-intel workspace — CVE feed, direct lookup, IP reputation, and threat geolocation."
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

        <TabsContent value="vuln-intel">
          <Suspense fallback={<PageSkeleton />}>
            <VulnIntelligenceDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="cve-search">
          <Suspense fallback={<PageSkeleton />}>
            <CVESearch />
          </Suspense>
        </TabsContent>
        <TabsContent value="ip-rep">
          <Suspense fallback={<PageSkeleton />}>
            <IPReputationDashboard />
          </Suspense>
        </TabsContent>
        <TabsContent value="geolocation">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatGeolocationDashboard />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
