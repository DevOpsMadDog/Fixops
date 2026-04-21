/**
 * Metrics Aggregator Dashboard
 *
 * Cross-domain security metric sources, aggregations, and alert triggers.
 *   1. KPIs: Total Metrics, Sources Active, Aggregations/hr, Alerts Triggered
 *   2. Metric sources table (name, type, last_collected, metric_count, status)
 *
 * Route: /metrics-aggregator
 * API: GET /api/v1/metrics-aggregator/sources
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BarChart3, RefreshCw, Database, Bell, Activity } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SOURCES = [
  { id: "SRC-001", name: "SIEM Event Stream",       type: "siem",       last_collected: "30 sec ago",  metric_count: 14823, status: "active" },
  { id: "SRC-002", name: "EDR Telemetry Feed",       type: "edr",        last_collected: "1 min ago",   metric_count: 9341,  status: "active" },
  { id: "SRC-003", name: "Cloud CloudTrail Logs",    type: "cloud",      last_collected: "2 min ago",   metric_count: 6720,  status: "active" },
  { id: "SRC-004", name: "Vulnerability Scanner",    type: "vuln",       last_collected: "10 min ago",  metric_count: 3218,  status: "active" },
  { id: "SRC-005", name: "Network Flow Collector",   type: "network",    last_collected: "45 sec ago",  metric_count: 22401, status: "active" },
  { id: "SRC-006", name: "IAM Access Logs",          type: "identity",   last_collected: "5 min ago",   metric_count: 4872,  status: "active" },
  { id: "SRC-007", name: "Container Runtime Metrics",type: "container",  last_collected: "3 min ago",   metric_count: 1934,  status: "degraded" },
  { id: "SRC-008", name: "DLP Policy Engine",        type: "dlp",        last_collected: "20 min ago",  metric_count: 871,   status: "active" },
];

const MOCK_STATS = { total_metrics: 64182, sources_active: 7, aggregations_hr: 2840, alerts_triggered: 23 };

// ── Badge helpers ──────────────────────────────────────────────

function SourceTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    siem:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    edr:       "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    cloud:     "border-sky-500/30 text-sky-400 bg-sky-500/10",
    vuln:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    network:   "border-teal-500/30 text-teal-400 bg-teal-500/10",
    identity:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    container: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    dlp:       "border-rose-500/30 text-rose-400 bg-rose-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>{type}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    degraded: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    offline:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function MetricsAggregatorDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveSources, setLiveSources] = useState<any[] | null>(null);
  const [liveStats, setLiveStats]     = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/metrics-aggregator/sources?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/metrics-aggregator/stats?org_id=${ORG_ID}`),
    ]).then(([sourcesRes, statsRes]) => {
      if (sourcesRes.status === "fulfilled") setLiveSources(sourcesRes.value?.sources ?? sourcesRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const sources = liveSources ?? MOCK_SOURCES;
  const stats   = liveStats   ?? MOCK_STATS;


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Metrics Aggregator"
        description="Cross-domain security metric collection, aggregation, and alert correlation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Metrics"      value={stats.total_metrics.toLocaleString()}    icon={BarChart3}  trend="up" />
        <KpiCard title="Sources Active"     value={stats.sources_active}                    icon={Database}   trend="flat" className="border-cyan-500/20" />
        <KpiCard title="Aggregations / hr"  value={stats.aggregations_hr.toLocaleString()}  icon={Activity}   trend="up"      className="border-blue-500/20" />
        <KpiCard title="Alerts Triggered"   value={stats.alerts_triggered}                  icon={Bell}       trend="up"      className="border-amber-500/20" />
      </div>

      {/* Sources Table */}
      <Card className="border-cyan-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-cyan-400">
            <Database className="h-4 w-4" />
            Metric Sources
          </CardTitle>
          <CardDescription className="text-xs">
            Active telemetry sources feeding the aggregation pipeline
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Source Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Last Collected</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Metrics</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sources.map((src: any, i: number) => (
                  <TableRow key={src.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{src.id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium">{src.name}</TableCell>
                    <TableCell className="py-2"><SourceTypeBadge type={src.type ?? src.source_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{src.last_collected ?? src.last_seen ?? "—"}</TableCell>
                    <TableCell className="py-2 text-right font-mono text-xs tabular-nums">
                      {(src.metric_count ?? src.metrics ?? 0).toLocaleString()}
                    </TableCell>
                    <TableCell className="py-2 text-right"><StatusBadge status={src.status ?? "active"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
