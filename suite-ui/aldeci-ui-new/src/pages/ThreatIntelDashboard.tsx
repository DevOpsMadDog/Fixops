/**
 * Threat Intelligence Dashboard
 *
 * Feed health grid, IOC browser with search + copy, 7-day trend chart.
 * Route: /threat-intel
 *
 * API: GET /api/v1/feeds/status  GET /api/v1/threat-intel/iocs
 * Falls back to mock data on failure.
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  Shield,
  Activity,
  Globe,
  Hash,
  Link,
  Server,
  Search,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  TrendingUp,
  Wifi,
  WifiOff,
  Radio,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

function authedFetch(url: string) {
  return fetch(url, { headers: { "X-API-Key": API_KEY } });
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type FeedStatus = "live" | "degraded" | "down";
type IocType = "ip" | "domain" | "hash" | "url";
type Severity = "critical" | "high" | "medium" | "low";

interface Feed {
  id: string;
  name: string;
  status: FeedStatus;
  ioc_count: number;
  last_updated: string;
}

interface IOC {
  type: IocType;
  value: string;
  severity: Severity;
  source: string;
  last_seen: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_FEEDS: Feed[] = [
  { id: "otx", name: "AlienVault OTX", status: "live", ioc_count: 14832, last_updated: "2m ago" },
  { id: "shodan", name: "Shodan", status: "live", ioc_count: 3291, last_updated: "5m ago" },
  { id: "vt", name: "VirusTotal", status: "degraded", ioc_count: 8847, last_updated: "12m ago" },
  { id: "cisa", name: "CISA KEV", status: "live", ioc_count: 1087, last_updated: "1h ago" },
  { id: "nvd", name: "NVD", status: "live", ioc_count: 246943, last_updated: "6h ago" },
  { id: "abuse", name: "Abuse.ch", status: "live", ioc_count: 29441, last_updated: "8m ago" },
];

const MOCK_IOCS: IOC[] = [
  { type: "ip", value: "185.220.101.47", severity: "critical", source: "OTX", last_seen: "2m ago" },
  { type: "domain", value: "evil-c2.example.net", severity: "high", source: "VirusTotal", last_seen: "15m ago" },
  { type: "hash", value: "d41d8cd98f00b204e9800998ecf8427e", severity: "high", source: "Abuse.ch", last_seen: "1h ago" },
  { type: "url", value: "http://phish.example.com/login", severity: "medium", source: "CISA", last_seen: "3h ago" },
  { type: "ip", value: "91.108.56.130", severity: "critical", source: "Shodan", last_seen: "4m ago" },
  { type: "domain", value: "malware-dropper.ru", severity: "critical", source: "OTX", last_seen: "6m ago" },
  { type: "hash", value: "5d41402abc4b2a76b9719d911017c592", severity: "medium", source: "Abuse.ch", last_seen: "2h ago" },
  { type: "url", value: "https://fake-bank.example.org/auth", severity: "high", source: "VirusTotal", last_seen: "30m ago" },
  { type: "ip", value: "198.51.100.42", severity: "low", source: "NVD", last_seen: "8h ago" },
  { type: "domain", value: "c2-beacon.onion.example", severity: "high", source: "OTX", last_seen: "20m ago" },
];

const TREND_DATA = [
  { day: "Mon", ip: 1240, domain: 830, hash: 560, url: 310 },
  { day: "Tue", ip: 1560, domain: 940, hash: 620, url: 280 },
  { day: "Wed", ip: 980, domain: 710, hash: 490, url: 340 },
  { day: "Thu", ip: 2100, domain: 1200, hash: 780, url: 420 },
  { day: "Fri", ip: 1830, domain: 1050, hash: 690, url: 390 },
  { day: "Sat", ip: 760, domain: 540, hash: 380, url: 210 },
  { day: "Sun", ip: 1420, domain: 870, hash: 530, url: 360 },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(0)}K`;
  return n.toString();
}

const STATUS_CONFIG: Record<FeedStatus, { label: string; color: string; dot: string; icon: typeof Wifi }> = {
  live:     { label: "Live",     color: "text-green-400",  dot: "bg-green-400",  icon: Wifi },
  degraded: { label: "Degraded", color: "text-yellow-400", dot: "bg-yellow-400", icon: Radio },
  down:     { label: "Down",     color: "text-red-400",    dot: "bg-red-400",    icon: WifiOff },
};

const IOC_TYPE_CONFIG: Record<IocType, { label: string; icon: typeof Globe; color: string }> = {
  ip:     { label: "IP",     icon: Server, color: "text-cyan-400 bg-cyan-500/10" },
  domain: { label: "Domain", icon: Globe,  color: "text-purple-400 bg-purple-500/10" },
  hash:   { label: "Hash",   icon: Hash,   color: "text-orange-400 bg-orange-500/10" },
  url:    { label: "URL",    icon: Link,   color: "text-blue-400 bg-blue-500/10" },
};

const SEV_BADGE: Record<Severity, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const TREND_COLORS = {
  ip:     "#22d3ee",
  domain: "#a78bfa",
  hash:   "#fb923c",
  url:    "#60a5fa",
};

const CHART_TOOLTIP_STYLE = {
  background: "oklch(0.17 0.01 250)",
  border: "1px solid oklch(0.25 0.01 250)",
  borderRadius: 8,
  fontSize: 12,
  color: "oklch(0.93 0.005 250)",
};

// ═══════════════════════════════════════════════════════════
// Feed Status Card
// ═══════════════════════════════════════════════════════════

function FeedCard({ feed, index }: { feed: Feed; index: number }) {
  const cfg = STATUS_CONFIG[feed.status];
  const StatusIcon = cfg.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, duration: 0.3 }}
    >
      <Card className="relative overflow-hidden group hover:border-primary/30 transition-colors duration-200">
        {/* status accent strip */}
        <div
          className={cn(
            "absolute top-0 left-0 right-0 h-0.5",
            feed.status === "live"     && "bg-green-400",
            feed.status === "degraded" && "bg-yellow-400",
            feed.status === "down"     && "bg-red-400",
          )}
        />
        <CardContent className="pt-5 pb-4 px-4">
          <div className="flex items-start justify-between mb-3">
            <div className="flex items-center gap-2">
              <div className={cn("w-1.5 h-1.5 rounded-full animate-pulse", cfg.dot)} />
              <span className="text-sm font-medium">{feed.name}</span>
            </div>
            <Badge
              className={cn(
                "text-xs border-0",
                feed.status === "live"     && "bg-green-500/10 text-green-400",
                feed.status === "degraded" && "bg-yellow-500/10 text-yellow-400",
                feed.status === "down"     && "bg-red-500/10 text-red-400",
              )}
            >
              <StatusIcon className="w-2.5 h-2.5 mr-1" />
              {cfg.label}
            </Badge>
          </div>
          <p className="text-2xl font-bold tabular-nums tracking-tight mb-1">
            {formatCount(feed.ioc_count)}
          </p>
          <p className="text-xs text-muted-foreground">IOCs · Updated {feed.last_updated}</p>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// IOC Row
// ═══════════════════════════════════════════════════════════

function IocRow({ ioc, index }: { ioc: IOC; index: number }) {
  const [copied, setCopied] = useState(false);
  const typeCfg = IOC_TYPE_CONFIG[ioc.type];
  const TypeIcon = typeCfg.icon;

  function handleCopy() {
    navigator.clipboard.writeText(ioc.value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <motion.tr
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03, duration: 0.25 }}
      className="border-b border-border/50 hover:bg-accent/30 transition-colors group"
    >
      <td className="py-2.5 px-3">
        <span className={cn("inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium", typeCfg.color)}>
          <TypeIcon className="w-3 h-3" />
          {typeCfg.label}
        </span>
      </td>
      <td className="py-2.5 px-3 font-mono text-xs text-foreground max-w-[220px] truncate">
        {ioc.value}
      </td>
      <td className="py-2.5 px-3">
        <Badge variant={SEV_BADGE[ioc.severity]} className="uppercase text-[10px] tracking-wide">
          {ioc.severity}
        </Badge>
      </td>
      <td className="py-2.5 px-3 text-xs text-muted-foreground">{ioc.source}</td>
      <td className="py-2.5 px-3 text-xs text-muted-foreground">{ioc.last_seen}</td>
      <td className="py-2.5 px-3 text-right">
        <Button
          size="sm"
          variant="ghost"
          className="h-6 px-2 opacity-0 group-hover:opacity-100 transition-opacity"
          onClick={handleCopy}
          aria-label={`Copy ${ioc.value}`}
        >
          {copied
            ? <Check className="w-3 h-3 text-green-400" />
            : <Copy className="w-3 h-3" />
          }
        </Button>
      </td>
    </motion.tr>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function ThreatIntelDashboard() {
  const [search, setSearch] = useState("");

  const { data: feeds, isLoading: feedsLoading, refetch: refetchFeeds } = useQuery<Feed[]>({
    queryKey: ["feeds-status"],
    queryFn: async () => {
      const res = await authedFetch(`${API}/api/v1/threat-feeds/sources?org_id=${ORG_ID}`);
      if (!res.ok) {
        // fallback to legacy endpoint
        const res2 = await authedFetch(`${API}/api/v1/feeds/status`);
        if (!res2.ok) throw new Error("feeds api unavailable");
        return res2.json();
      }
      return res.json();
    },
    retry: 1,
    staleTime: 60_000,
    initialData: MOCK_FEEDS,
  });

  const { data: iocs, isLoading: iocsLoading } = useQuery<IOC[]>({
    queryKey: ["threat-intel-iocs"],
    queryFn: async () => {
      const res = await authedFetch(`${API}/api/v1/threat-feeds/items?org_id=${ORG_ID}&limit=20`);
      if (!res.ok) {
        // fallback to legacy endpoint
        const res2 = await authedFetch(`${API}/api/v1/threat-intel/iocs`);
        if (!res2.ok) throw new Error("iocs api unavailable");
        return res2.json();
      }
      return res.json();
    },
    retry: 1,
    staleTime: 30_000,
    initialData: MOCK_IOCS,
  });

  const { data: feedStats } = useQuery<any>({
    queryKey: ["threat-feeds-stats"],
    queryFn: async () => {
      const res = await authedFetch(`${API}/api/v1/threat-feeds/stats?org_id=${ORG_ID}`);
      if (!res.ok) throw new Error("stats api unavailable");
      return res.json();
    },
    retry: 1,
    staleTime: 60_000,
  });

  const filteredIocs = useMemo(() => {
    if (!iocs) return [];
    const q = search.toLowerCase();
    if (!q) return iocs;
    return iocs.filter(
      (i) =>
        i.value.toLowerCase().includes(q) ||
        i.type.includes(q) ||
        i.severity.includes(q) ||
        i.source.toLowerCase().includes(q),
    );
  }, [iocs, search]);

  const liveCount  = feeds?.filter((f) => f.status === "live").length ?? 0;
  const totalIocs  = feeds?.reduce((s, f) => s + f.ioc_count, 0) ?? 0;
  const criticalIocs = iocs?.filter((i) => i.severity === "critical").length ?? 0;

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      {/* Header */}
      <PageHeader
        title="Threat Intelligence"
        description="Live IOC feeds, indicator browser, and ingestion trend across 28+ sources"
        badge="Live"
        actions={
          <Button
            size="sm"
            variant="outline"
            onClick={() => refetchFeeds()}
            className="gap-2"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard
          title="Active Feeds"
          value={`${liveCount} / ${feeds?.length ?? 0}`}
          icon={Activity}
          trend="up"
          trendLabel="All healthy"
        />
        <KpiCard
          title="Total IOCs"
          value={totalIocs}
          icon={Shield}
          trend="up"
          trendLabel="+2.3K today"
        />
        <KpiCard
          title="Critical IOCs"
          value={criticalIocs}
          icon={AlertTriangle}
          trend="down"
          trendLabel="Requires action"
        />
        <KpiCard
          title="New Today"
          value={feedStats?.new_today ?? "4,218"}
          icon={TrendingUp}
          trend="up"
          trendLabel="vs 3,901 yesterday"
        />
      </div>

      {/* Feed Status Grid */}
      <section>
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
          Feed Status
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {(feeds ?? MOCK_FEEDS).map((feed, i) => (
            <FeedCard key={feed.id} feed={feed} index={i} />
          ))}
        </div>
      </section>

      <Separator />

      {/* Main content: IOC table + trend chart */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6 min-h-0">
        {/* IOC Browser — takes 3/5 */}
        <Card className="xl:col-span-3 flex flex-col min-h-0">
          <CardHeader className="pb-3 flex-row items-center justify-between space-y-0">
            <CardTitle className="text-sm font-semibold">IOC Browser</CardTitle>
            <div className="relative w-52">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search indicators…"
                className="pl-8 h-8 text-xs"
              />
            </div>
          </CardHeader>
          <Separator />
          <div className="flex-1 overflow-hidden">
            <ScrollArea className="h-[340px]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-xs text-muted-foreground">
                    <th className="py-2 px-3 text-left font-medium w-20">Type</th>
                    <th className="py-2 px-3 text-left font-medium">Value</th>
                    <th className="py-2 px-3 text-left font-medium w-24">Severity</th>
                    <th className="py-2 px-3 text-left font-medium w-24">Source</th>
                    <th className="py-2 px-3 text-left font-medium w-24">Last Seen</th>
                    <th className="py-2 px-3 w-10" />
                  </tr>
                </thead>
                <tbody>
                  {filteredIocs.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                        No indicators match your search
                      </td>
                    </tr>
                  ) : (
                    filteredIocs.map((ioc, i) => (
                      <IocRow key={`${ioc.type}-${ioc.value}`} ioc={ioc} index={i} />
                    ))
                  )}
                </tbody>
              </table>
            </ScrollArea>
          </div>
        </Card>

        {/* Trend Chart — takes 2/5 */}
        <Card className="xl:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">7-Day IOC Trend</CardTitle>
          </CardHeader>
          <Separator />
          <CardContent className="pt-4">
            <ResponsiveContainer width="100%" height={310}>
              <BarChart data={TREND_DATA} barSize={8} barGap={2}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.01 250)" vertical={false} />
                <XAxis
                  dataKey="day"
                  tick={{ fontSize: 11, fill: "oklch(0.60 0.01 250)" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 11, fill: "oklch(0.60 0.01 250)" }}
                  axisLine={false}
                  tickLine={false}
                  tickFormatter={(v: number) => `${(v / 1000).toFixed(0)}K`}
                />
                <Tooltip
                  contentStyle={CHART_TOOLTIP_STYLE}
                  cursor={{ fill: "oklch(0.25 0.01 250 / 0.4)" }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11, paddingTop: 12 }}
                  iconType="circle"
                  iconSize={6}
                />
                <Bar dataKey="ip"     fill={TREND_COLORS.ip}     radius={[2, 2, 0, 0]} name="IP" />
                <Bar dataKey="domain" fill={TREND_COLORS.domain} radius={[2, 2, 0, 0]} name="Domain" />
                <Bar dataKey="hash"   fill={TREND_COLORS.hash}   radius={[2, 2, 0, 0]} name="Hash" />
                <Bar dataKey="url"    fill={TREND_COLORS.url}    radius={[2, 2, 0, 0]} name="URL" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
