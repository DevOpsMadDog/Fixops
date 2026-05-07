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
import type { ComponentType } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldAlert, Search, Globe, Map, AlertCircle, Download } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { vulnIntelApi, epssApi, ipReputationApi, threatGeolocationApi } from "@/lib/api";

// Lazy-imported existing pages — preserved as-is so all behavior, API calls,
// loading/error/empty states, and form interactions continue to work.

type TabKey = "vuln-intel" | "cve-search" | "ip-rep" | "geolocation";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: ComponentType<{ className?: string }>;
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

// ── Severity badge colour map ──────────────────────────────────────────────
const SEVERITY_VARIANT: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-black",
  low: "bg-blue-500 text-white",
};

interface CveItem {
  cve_id?: string;
  id?: string;
  severity?: string;
  source?: string;
  published?: string;
  published_at?: string;
  title?: string;
  description?: string;
  [key: string]: unknown;
}

interface VulnIntelResponse {
  items?: CveItem[];
  count?: number;
  router?: string;
}

function VulnIntelOverview() {
  const { data, isLoading, isError, error } = useQuery<VulnIntelResponse>({
    queryKey: ["vuln-intel", "index"],
    queryFn: async () => {
      const res = await vulnIntelApi.index("default");
      return res.data as VulnIntelResponse;
    },
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">CVE Feed</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">
            Failed to load vulnerability intelligence:{" "}
            {error instanceof Error ? error.message : "Unknown error"}
          </p>
        </CardContent>
      </Card>
    );
  }

  const items = data?.items ?? [];
  const count = data?.count ?? items.length;

  if (count === 0 || items.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No CVEs ingested yet"
        description="Connect a vulnerability feed or run a scan to populate the CVE intelligence feed."
      />
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center justify-between">
          <span>CVE Feed</span>
          <Badge variant="secondary">{count} CVEs</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                <th className="px-4 py-2 font-medium">CVE ID</th>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Published</th>
                <th className="px-4 py-2 font-medium">Title</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {items.map((item, idx) => {
                const cveId = item.cve_id ?? item.id ?? `cve-${idx}`;
                const severity = (item.severity ?? "unknown").toLowerCase();
                const source = item.source ?? "—";
                const published = item.published ?? item.published_at ?? "—";
                const pubDisplay = published !== "—"
                  ? new Date(published).toLocaleDateString()
                  : "—";
                const title = item.title ?? item.description ?? "—";
                const trimmedTitle = title.length > 80 ? `${title.slice(0, 80)}…` : title;

                return (
                  <tr key={cveId} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-2 font-mono text-xs text-indigo-400 whitespace-nowrap">
                      {cveId}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${
                          SEVERITY_VARIANT[severity] ?? "bg-muted text-muted-foreground"
                        }`}
                      >
                        {severity}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">{source}</td>
                    <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">{pubDisplay}</td>
                    <td className="px-4 py-2 text-muted-foreground max-w-xs truncate">{trimmedTitle}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

interface EpssScore {
  cve_id?: string;
  epss?: number;
  percentile?: number;
  date?: string;
  [key: string]: unknown;
}

interface EpssResponse {
  scores?: EpssScore[];
  total?: number;
  page?: number;
  page_size?: number;
}

function EpssScoresPanel() {
  const { data, isLoading, isError, error } = useQuery<EpssResponse>({
    queryKey: ["epss", "scores"],
    queryFn: async () => {
      const res = await epssApi.scores({ page: 1, page_size: 50 });
      return res.data as EpssResponse;
    },
    staleTime: 120_000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">EPSS Scores</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-full" />
          ))}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">
            Failed to load EPSS scores:{" "}
            {error instanceof Error ? error.message : "Unknown error"}
          </p>
        </CardContent>
      </Card>
    );
  }

  const scores = data?.scores ?? [];
  const total = data?.total ?? scores.length;

  if (scores.length === 0) {
    return (
      <EmptyState
        icon={Search}
        title="No EPSS scores ingested"
        description="Trigger an EPSS import to download the FIRST.org daily feed and populate exploit-prediction scores."
      />
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center justify-between">
          <span>EPSS Scores — Exploit Prediction</span>
          <Badge variant="secondary">{total} CVEs</Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                <th className="px-4 py-2 font-medium">CVE ID</th>
                <th className="px-4 py-2 font-medium">EPSS Score</th>
                <th className="px-4 py-2 font-medium">Percentile</th>
                <th className="px-4 py-2 font-medium">Date</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {scores.map((row, idx) => {
                const cveId = row.cve_id ?? `epss-${idx}`;
                const epss = typeof row.epss === "number" ? row.epss : 0;
                const pct = typeof row.percentile === "number" ? row.percentile : 0;
                const epssDisplay = (epss * 100).toFixed(2) + "%";
                const pctDisplay = (pct * 100).toFixed(1) + "th";
                const riskClass =
                  epss >= 0.7
                    ? "bg-red-600 text-white"
                    : epss >= 0.4
                    ? "bg-amber-500 text-black"
                    : "bg-blue-500 text-white";
                const dateDisplay = row.date
                  ? new Date(row.date).toLocaleDateString()
                  : "—";

                return (
                  <tr key={cveId} className="hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-2 font-mono text-xs text-indigo-400 whitespace-nowrap">
                      {cveId}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${riskClass}`}
                      >
                        {epssDisplay}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-muted-foreground">{pctDisplay}</td>
                    <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">{dateDisplay}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ── IP Reputation Panel ──────────────────────────────────────────────────────

interface BlocklistEntry {
  ip?: string;
  threat_type?: string;
  source?: string;
  added_at?: string;
  confidence?: number;
  [key: string]: unknown;
}

interface BlocklistResponse {
  entries?: BlocklistEntry[];
  items?: BlocklistEntry[];
  total?: number;
  count?: number;
}

interface IpRepStats {
  total_blocked?: number;
  high_confidence?: number;
  sources?: number;
  [key: string]: unknown;
}

function IPReputationPanel() {
  const { data: statsData } = useQuery<IpRepStats>({
    queryKey: ["ip-reputation", "stats"],
    queryFn: async () => {
      const res = await ipReputationApi.stats("default");
      return res.data as IpRepStats;
    },
    staleTime: 60_000,
  });

  const { data, isLoading, isError, error } = useQuery<BlocklistResponse>({
    queryKey: ["ip-reputation", "blocklist"],
    queryFn: async () => {
      const res = await ipReputationApi.blocklist("default", 100, 0);
      return res.data as BlocklistResponse;
    },
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-sm">IP Blocklist</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">Failed to load IP reputation: {error instanceof Error ? error.message : "Unknown error"}</p>
        </CardContent>
      </Card>
    );
  }

  const entries = data?.entries ?? data?.items ?? [];
  const total = data?.total ?? data?.count ?? entries.length;

  return (
    <div className="space-y-4">
      {statsData && (
        <div className="grid grid-cols-3 gap-3">
          {([
            { label: "Total Blocked", value: statsData.total_blocked ?? 0, cls: "text-red-500" },
            { label: "High Confidence", value: statsData.high_confidence ?? 0, cls: "text-amber-500" },
            { label: "Sources", value: statsData.sources ?? 0, cls: "text-muted-foreground" },
          ] as const).map(({ label, value, cls }) => (
            <Card key={label} className="py-3 px-4">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-xl font-bold ${cls}`}>{value}</p>
            </Card>
          ))}
        </div>
      )}
      {entries.length === 0 ? (
        <EmptyState
          icon={Globe}
          title="No blocked IPs"
          description="Submit IP reputation data or connect a threat-intel feed to populate the blocklist."
        />
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center justify-between">
              <span>IP Blocklist</span>
              <Badge variant="secondary">{total} entries</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                    <th className="px-4 py-2 font-medium">IP Address</th>
                    <th className="px-4 py-2 font-medium">Threat Type</th>
                    <th className="px-4 py-2 font-medium">Source</th>
                    <th className="px-4 py-2 font-medium">Confidence</th>
                    <th className="px-4 py-2 font-medium">Added</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {entries.map((e, idx) => {
                    const ip = e.ip ?? `ip-${idx}`;
                    const conf = typeof e.confidence === "number" ? e.confidence : null;
                    const confClass = conf === null ? "bg-muted text-muted-foreground"
                      : conf >= 0.8 ? "bg-red-600 text-white"
                      : conf >= 0.5 ? "bg-amber-500 text-black"
                      : "bg-blue-500 text-white";
                    const added = e.added_at ? new Date(e.added_at).toLocaleDateString() : "—";
                    return (
                      <tr key={ip + idx} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-2 font-mono text-xs text-indigo-400 whitespace-nowrap">{ip}</td>
                        <td className="px-4 py-2 text-muted-foreground">{e.threat_type ?? "—"}</td>
                        <td className="px-4 py-2 text-muted-foreground">{e.source ?? "—"}</td>
                        <td className="px-4 py-2">
                          {conf !== null ? (
                            <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-semibold ${confClass}`}>{(conf * 100).toFixed(0)}%</span>
                          ) : "—"}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground whitespace-nowrap">{added}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ── Threat Geolocation Panel ─────────────────────────────────────────────────

interface GeoHeatmapEntry {
  country?: string;
  country_code?: string;
  count?: number;
  threat_count?: number;
  [key: string]: unknown;
}

interface GeoHeatmapResponse {
  countries?: GeoHeatmapEntry[];
  heatmap?: GeoHeatmapEntry[];
  total_events?: number;
  [key: string]: unknown;
}

interface GeoStats {
  total_events?: number;
  countries_observed?: number;
  blocked_countries?: number;
  [key: string]: unknown;
}

function ThreatGeolocationPanel() {
  const { data: statsData } = useQuery<GeoStats>({
    queryKey: ["threat-geolocation", "stats"],
    queryFn: async () => {
      const res = await threatGeolocationApi.stats("default");
      return res.data as GeoStats;
    },
    staleTime: 60_000,
  });

  const { data, isLoading, isError, error } = useQuery<GeoHeatmapResponse>({
    queryKey: ["threat-geolocation", "heatmap"],
    queryFn: async () => {
      const res = await threatGeolocationApi.heatmap("default");
      return res.data as GeoHeatmapResponse;
    },
    staleTime: 60_000,
  });

  if (isLoading) {
    return (
      <Card>
        <CardHeader><CardTitle className="text-sm">Threat Geolocation</CardTitle></CardHeader>
        <CardContent className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}
        </CardContent>
      </Card>
    );
  }

  if (isError) {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 py-10 text-destructive">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">Failed to load geolocation data: {error instanceof Error ? error.message : "Unknown error"}</p>
        </CardContent>
      </Card>
    );
  }

  const countries = data?.countries ?? data?.heatmap ?? [];

  return (
    <div className="space-y-4">
      {statsData && (
        <div className="grid grid-cols-3 gap-3">
          {([
            { label: "Total Events", value: statsData.total_events ?? 0, cls: "text-muted-foreground" },
            { label: "Countries Observed", value: statsData.countries_observed ?? 0, cls: "text-indigo-400" },
            { label: "Blocked Countries", value: statsData.blocked_countries ?? 0, cls: "text-red-500" },
          ] as const).map(({ label, value, cls }) => (
            <Card key={label} className="py-3 px-4">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-xl font-bold ${cls}`}>{value}</p>
            </Card>
          ))}
        </div>
      )}
      {countries.length === 0 ? (
        <EmptyState
          icon={Map}
          title="No geolocation data yet"
          description="Record geo events to build a threat-origin heatmap. Connect an IP-enrichment feed for automatic attribution."
        />
      ) : (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center justify-between">
              <span>Country Threat Heatmap</span>
              <Badge variant="secondary">{countries.length} countries</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground uppercase tracking-wide">
                    <th className="px-4 py-2 font-medium">Country</th>
                    <th className="px-4 py-2 font-medium">Code</th>
                    <th className="px-4 py-2 font-medium">Threat Events</th>
                    <th className="px-4 py-2 font-medium">Heat Bar</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {countries.map((c, idx) => {
                    const count = c.count ?? c.threat_count ?? 0;
                    const maxCount = Math.max(...countries.map(x => x.count ?? x.threat_count ?? 0), 1);
                    const pct = Math.round((count / maxCount) * 100);
                    return (
                      <tr key={(c.country_code ?? c.country ?? idx)} className="hover:bg-muted/30 transition-colors">
                        <td className="px-4 py-2 text-muted-foreground">{c.country ?? "Unknown"}</td>
                        <td className="px-4 py-2 font-mono text-xs text-indigo-400">{c.country_code ?? "—"}</td>
                        <td className="px-4 py-2 text-muted-foreground">{count}</td>
                        <td className="px-4 py-2 w-40">
                          <div className="h-2 rounded-full bg-muted overflow-hidden">
                            <div
                              className="h-full rounded-full bg-red-500 transition-all"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function VulnIntelHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "vuln-intel";
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

  const handleExportCsv = () => {
    const orgId = localStorage.getItem("org_id") || "default";
    window.location.href = `/api/v1/security-findings/export?format=csv&org_id=${orgId}`;
  };

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
        actions={
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-2 px-3 py-1.5 text-sm font-medium rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          >
            <Download className="h-4 w-4" />
            Export CSV
          </button>
        }
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
            <VulnIntelOverview />
          </Suspense>
        </TabsContent>
        <TabsContent value="cve-search">
          <Suspense fallback={<PageSkeleton />}>
            <EpssScoresPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="ip-rep">
          <Suspense fallback={<PageSkeleton />}>
            <IPReputationPanel />
          </Suspense>
        </TabsContent>
        <TabsContent value="geolocation">
          <Suspense fallback={<PageSkeleton />}>
            <ThreatGeolocationPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
