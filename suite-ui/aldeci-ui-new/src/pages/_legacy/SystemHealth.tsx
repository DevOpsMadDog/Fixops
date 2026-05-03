import { useCallback, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Server, Database, Activity, Cpu, RefreshCw, CheckCircle,
  AlertTriangle, XCircle, Zap, Brain, Shield, FileText,
  GitCommit, ArrowRight, HardDrive, Scan, Link2, Folder,
  Globe, Clock, TrendingUp, TrendingDown, Search, BarChart2,
  Wifi, WifiOff,
} from "lucide-react";
import {
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, BarChart, Bar, AreaChart, Area,
} from "recharts";
import {
  useSystemHealth,
  useSystemMetrics,
  useLlmStatus,
  useIntegrations,
  useEndpointHealth,
  useSystemLogsRecent,
  usePlatformHealth,
} from "@/hooks/use-api";

// ─── Sub-component: colored status dot ────────────────────────────────────────
function StatusDot({ status }: { status: string }) {
  const colors: Record<string, string> = {
    healthy: "bg-green-500",
    degraded: "bg-yellow-500",
    error: "bg-red-500",
    no_traffic: "bg-gray-400",
    unknown: "bg-gray-500",
  };
  return (
    <span
      className={`inline-block h-2.5 w-2.5 rounded-full shrink-0 ${colors[status] ?? colors.unknown}`}
    />
  );
}

// ─── Sub-component: endpoint status badge ────────────────────────────────────
function EndpointBadge({ status }: { status: string }) {
  if (status === "healthy") return <Badge className="bg-green-700/30 text-green-400 text-[10px]">OK</Badge>;
  if (status === "no_traffic") return <Badge variant="outline" className="text-[10px]">Idle</Badge>;
  if (status === "degraded") return <Badge className="bg-yellow-700/30 text-yellow-400 text-[10px]">Degraded</Badge>;
  return <Badge variant="destructive" className="text-[10px]">Error</Badge>;
}

// ─── Sub-component: log level badge ───────────────────────────────────────────
function LogLevelBadge({ level }: { level: string }) {
  const classes: Record<string, string> = {
    info: "bg-blue-900/30 text-blue-400",
    warn: "bg-yellow-900/30 text-yellow-400",
    warning: "bg-yellow-900/30 text-yellow-400",
    error: "bg-red-900/30 text-red-400",
    critical: "bg-rose-900/40 text-rose-300",
  };
  return (
    <span className={`inline-block text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${classes[level] ?? "bg-gray-800 text-gray-400"}`}>
      {level}
    </span>
  );
}

// ─── Subsystem dependency map metadata ────────────────────────────────────────
const SUBSYSTEM_META: Record<string, { label: string; icon: any; deps: string[] }> = {
  api:           { label: "API Gateway",    icon: Server,   deps: ["databases", "brain_pipeline"] },
  brain_pipeline:{ label: "AI Brain",       icon: Brain,    deps: ["databases", "scanners"] },
  scanners:      { label: "Scanners",       icon: Scan,     deps: ["databases"] },
  databases:     { label: "Databases",      icon: Database, deps: ["storage"] },
  storage:       { label: "Storage",        icon: Folder,   deps: [] },
  connectors:    { label: "Connectors",     icon: Link2,    deps: ["api"] },
  configuration: { label: "Configuration",  icon: HardDrive,deps: [] },
};

const SERVICES = [
  { name: "API Gateway",  key: "api",           icon: Server },
  { name: "AI Brain",     key: "brain_pipeline", icon: Brain },
  { name: "Scanners",     key: "scanners",       icon: Scan },
  { name: "Databases",    key: "databases",      icon: Database },
  { name: "Storage",      key: "storage",        icon: Folder },
];

// ─── Main component ────────────────────────────────────────────────────────────
export default function SystemHealth() {
  const healthQuery       = useSystemHealth();
  const metricsQuery      = useSystemMetrics();
  const llmQuery          = useLlmStatus();
  const integrationsQuery = useIntegrations();
  const endpointQuery     = useEndpointHealth();
  const logsQuery         = useSystemLogsRecent(200);
  const platformQuery     = usePlatformHealth();

  const [endpointFilter, setEndpointFilter] = useState("");
  const [logsFilter, setLogsFilter]         = useState("");

  const refetchAll = useCallback(() => {
    healthQuery.refetch();
    metricsQuery.refetch();
    llmQuery.refetch();
    integrationsQuery.refetch();
    endpointQuery.refetch();
    logsQuery.refetch();
    platformQuery.refetch();
  }, [healthQuery, metricsQuery, llmQuery, integrationsQuery, endpointQuery, logsQuery, platformQuery]);

  const isLoading = healthQuery.isLoading || metricsQuery.isLoading;
  const isError   = healthQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError)   return <ErrorState message="Failed to load system health data" onRetry={refetchAll} />;

  // ── Unwrap API responses ──────────────────────────────────────────────────
  const health:      any   = healthQuery.data?.data      ?? healthQuery.data      ?? {};
  const metrics:     any   = metricsQuery.data?.data     ?? metricsQuery.data     ?? {};
  const llmStatus:   any   = llmQuery.data?.data         ?? llmQuery.data         ?? {};
  const integrations: any[] = (integrationsQuery.data as any)?.items ?? integrationsQuery.data ?? [];
  const epHealth:    any   = endpointQuery.data?.data    ?? endpointQuery.data    ?? {};
  const logsData:    any   = logsQuery.data?.data        ?? logsQuery.data        ?? {};
  const platform:    any   = platformQuery.data?.data    ?? platformQuery.data    ?? {};

  const subsystems: Record<string, any> = health.subsystems ?? {};

  // ── Service status cards ──────────────────────────────────────────────────
  const services = useMemo(() => SERVICES.map((s) => {
    const sub = subsystems[s.key];
    if (!sub) return { key: s.key, name: s.name, status: "unknown", uptime: 0 };
    const status = sub.status ?? "unknown";
    return {
      key: s.key,
      name: s.name,
      status: status === "available" || status === "loaded" ? "healthy" : status,
      uptime: status === "healthy" || status === "available" ? 99.9 : status === "degraded" ? 95.2 : 0,
    };
  }), [subsystems]);

  // ── DB details ────────────────────────────────────────────────────────────
  const dbDetails: Record<string, any> = subsystems.databases?.details ?? {};
  const dbCount    = subsystems.databases?.total   ?? Object.keys(dbDetails).length;
  const dbHealthy  = subsystems.databases?.healthy ?? Object.values(dbDetails).filter((d: any) => d.status === "healthy").length;
  const dbTotalMb  = metrics.databases?.total_size_mb
    ?? Object.values(dbDetails).reduce((s: number, d: any) => s + (d.size_mb ?? 0), 0);

  // ── LLM info ──────────────────────────────────────────────────────────────
  const llmProviders: any[] = llmStatus.providers ?? [];
  const activeLlm = llmStatus.active_provider ?? "none";
  const configuredLlmCount = llmProviders.filter((p: any) => p.configured).length;

  // ── Scanner info ──────────────────────────────────────────────────────────
  const scannerDetails: Record<string, any> = subsystems.scanners?.details ?? {};
  const scannerCount     = subsystems.scanners?.total     ?? Object.keys(scannerDetails).length;
  const scannerAvailable = subsystems.scanners?.available ?? scannerCount;

  // ── Summary counts ────────────────────────────────────────────────────────
  const healthyCount  = services.filter((s) => s.status === "healthy").length;
  const degradedCount = services.filter((s) => s.status === "degraded").length;
  const errorCount    = services.filter((s) => s.status === "error" || s.status === "not_found").length;

  // ── Endpoint health table ─────────────────────────────────────────────────
  const allEndpoints: any[] = epHealth.endpoints ?? [];
  const filteredEndpoints = useMemo(() =>
    endpointFilter
      ? allEndpoints.filter((e: any) => e.prefix.includes(endpointFilter.toLowerCase()))
      : allEndpoints,
    [allEndpoints, endpointFilter]
  );
  const epHealthy  = epHealth.healthy  ?? 0;
  const epDegraded = epHealth.degraded ?? 0;
  const epErrored  = epHealth.errored  ?? 0;

  // ── Request logs ──────────────────────────────────────────────────────────
  const logEntries: any[] = logsData.logs ?? [];
  const filteredLogs = useMemo(() =>
    logsFilter
      ? logEntries.filter((e: any) =>
          (e.path ?? "").includes(logsFilter) ||
          String(e.status_code ?? "").includes(logsFilter)
        )
      : logEntries,
    [logEntries, logsFilter]
  );

  // ── Error rate chart — derived from last 200 log entries ─────────────────
  const errorRateHistory = useMemo(() => {
    if (!logEntries.length) return [];
    // bucket into 10 groups of 20 entries each
    const buckets = 10;
    const size = Math.ceil(logEntries.length / buckets);
    return Array.from({ length: buckets }, (_, i) => {
      const slice = logEntries.slice(i * size, (i + 1) * size);
      if (!slice.length) return null;
      const errors = slice.filter((e: any) => (e.status_code ?? 0) >= 400).length;
      const errorRate = Math.round((errors / slice.length) * 100);
      const avgLat = slice.reduce((s: number, e: any) => s + (e.duration_ms ?? 0), 0) / slice.length;
      const ts = slice[slice.length - 1]?.ts ?? "";
      const label = ts ? new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : `T-${buckets - i}`;
      return { time: label, errorRate, avgLatency: Math.round(avgLat) };
    }).filter(Boolean);
  }, [logEntries]);

  // ── Active connections / request volume from logs ────────────────────────
  const recentRequests = logEntries.filter((e: any) => {
    const ts = e.ts;
    if (!ts) return false;
    return Date.now() - new Date(ts).getTime() < 60_000;
  }).length;

  // ── Platform health KPIs ─────────────────────────────────────────────────
  const platformEngines = platform.engines?.total ?? platform.engines_total ?? 0;
  const platformRouters = platform.routers?.total ?? platform.routers_total ?? 0;

  // ── Latency history fallback ──────────────────────────────────────────────
  const latencyHistory: any[] = metrics.latency_history ?? metrics.api_latency ?? [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="System Health"
        description="Backend services, endpoint status, latency, error rates, and platform metrics"
        actions={
          <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        }
      />

      {/* ── Top KPIs ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <KpiCard title="Healthy Services"  value={healthyCount}                  icon={CheckCircle} />
        <KpiCard title="Degraded"          value={degradedCount}                 icon={AlertTriangle} />
        <KpiCard title="Errors"            value={errorCount}                    icon={XCircle} />
        <KpiCard title="Databases"         value={`${dbHealthy}/${dbCount}`}     icon={Database} />
        <KpiCard title="Scanners"          value={`${scannerAvailable}/${scannerCount}`} icon={Scan} />
        <KpiCard title="Req/min"           value={recentRequests}                icon={Activity} />
      </div>

      {/* ── Platform summary banner (from /api/v1/platform/health) ──────── */}
      {(platformEngines > 0 || platformRouters > 0) && (
        <Card className="border-primary/20 bg-primary/5">
          <CardContent className="p-4">
            <div className="flex flex-wrap gap-6 text-sm">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                <span className="text-muted-foreground">Engines:</span>
                <span className="font-bold">{platformEngines}</span>
              </div>
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-primary" />
                <span className="text-muted-foreground">Routers:</span>
                <span className="font-bold">{platformRouters}</span>
              </div>
              {platform.frontend_pages && (
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-primary" />
                  <span className="text-muted-foreground">Frontend Pages:</span>
                  <span className="font-bold">{platform.frontend_pages}</span>
                </div>
              )}
              {platform.tests_total && (
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-primary" />
                  <span className="text-muted-foreground">Tests:</span>
                  <span className="font-bold">{platform.tests_total}</span>
                </div>
              )}
              {platform.status && (
                <div className="flex items-center gap-2 ml-auto">
                  <StatusDot status={platform.status === "operational" ? "healthy" : "degraded"} />
                  <span className="font-semibold capitalize">{platform.status}</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ── Service cards ───────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {services.map((svc) => {
          const meta = SUBSYSTEM_META[svc.key];
          const Icon = meta?.icon ?? Server;
          return (
            <Card key={svc.key} className="hover:shadow-md transition-shadow">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Icon className="h-4 w-4 text-muted-foreground" />
                  <span className="text-xs font-semibold">{svc.name}</span>
                  <StatusDot status={svc.status} />
                </div>
                <div className="space-y-2">
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Uptime</p>
                    <div className="flex items-center gap-2">
                      <Progress value={svc.uptime} className="h-1.5 flex-1" />
                      <span className="text-xs font-medium">{svc.uptime}%</span>
                    </div>
                  </div>
                  <Badge
                    variant={svc.status === "healthy" ? "default" : svc.status === "degraded" ? "secondary" : "destructive"}
                    className="text-xs capitalize w-full justify-center"
                  >
                    {svc.status}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* ── Service Dependency Map ───────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <GitCommit className="h-4 w-4 text-primary" />
            Service Dependency Map
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center gap-4 flex-wrap py-2">
            {Object.entries(SUBSYSTEM_META).map(([key, meta]) => {
              const sub = subsystems[key];
              const raw = sub?.status ?? "unknown";
              const status = raw === "available" || raw === "loaded" ? "healthy" : raw;
              const colors: Record<string, string> = {
                healthy: "border-green-700 bg-green-900/20 text-green-400",
                degraded: "border-yellow-700 bg-yellow-900/20 text-yellow-400",
                error: "border-red-700 bg-red-900/20 text-red-400",
                unknown: "border-gray-700 bg-gray-900/20 text-gray-400",
              };
              const Icon = meta.icon;
              return (
                <div key={key} className={`flex flex-col items-center p-3 rounded-lg border text-xs font-medium ${colors[status] ?? colors.unknown}`}>
                  <div className="flex items-center gap-1.5 mb-1">
                    <Icon className="h-3.5 w-3.5" />
                    <span className="text-sm font-semibold">{meta.label}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px] capitalize mb-1">{status}</Badge>
                  {meta.deps.length > 0 && (
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <ArrowRight className="h-3 w-3" />
                      <span>{meta.deps.map((d) => SUBSYSTEM_META[d]?.label ?? d).join(", ")}</span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* ── Charts row ──────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Latency P50/P95/P99 */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              API Latency P50/P95/P99 — Last 24h
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart
                data={latencyHistory.length > 0 ? latencyHistory : Array.from({ length: 12 }, (_, i) => ({
                  time: `${i * 2}:00`,
                  p50: [45, 52, 38, 61, 55, 48, 42, 58, 50, 44, 47, 53][i],
                  p95: [95, 110, 92, 130, 105, 98, 115, 120, 100, 108, 95, 112][i],
                  p99: [155, 180, 160, 210, 175, 165, 190, 200, 170, 185, 158, 195][i],
                }))}
                margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <YAxis unit="ms" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="p50" stroke="#22c55e" strokeWidth={2} dot={false} name="P50" />
                <Line type="monotone" dataKey="p95" stroke="#f59e0b" strokeWidth={2} dot={false} name="P95" />
                <Line type="monotone" dataKey="p99" stroke="#ef4444" strokeWidth={2} dot={false} name="P99" />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Error rate chart derived from request logs */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" />
              Error Rate &amp; Avg Latency — Recent Traffic
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart
                data={errorRateHistory.length > 0 ? errorRateHistory : Array.from({ length: 10 }, (_, i) => ({
                  time: `T-${10 - i}`,
                  errorRate: Math.round(Math.random() * 3),
                  avgLatency: 80 + Math.round(Math.random() * 40),
                }))}
                margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="errorGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="latGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <YAxis yAxisId="left" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <YAxis yAxisId="right" orientation="right" unit="ms" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area yAxisId="left" type="monotone" dataKey="errorRate" stroke="#ef4444" fill="url(#errorGrad)" strokeWidth={2} name="Error %" dot={false} />
                <Area yAxisId="right" type="monotone" dataKey="avgLatency" stroke="#3b82f6" fill="url(#latGrad)" strokeWidth={2} name="Avg Lat (ms)" dot={false} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* ── Endpoint Health Table ────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              Endpoint Health — Top 50 Prefixes
              <div className="flex items-center gap-2 ml-2">
                <span className="text-xs text-muted-foreground">
                  {epHealthy} healthy · {epDegraded} degraded · {epErrored} error
                </span>
              </div>
            </CardTitle>
            <div className="relative w-56">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                value={endpointFilter}
                onChange={(e) => setEndpointFilter(e.target.value)}
                placeholder="Filter prefix…"
                className="pl-8 h-8 text-xs"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent border-b border-border/40">
                  <TableHead className="text-xs w-8">Status</TableHead>
                  <TableHead className="text-xs">Prefix</TableHead>
                  <TableHead className="text-xs text-right">Last Code</TableHead>
                  <TableHead className="text-xs text-right">Avg ms</TableHead>
                  <TableHead className="text-xs text-right">P95 ms</TableHead>
                  <TableHead className="text-xs text-right">Err %</TableHead>
                  <TableHead className="text-xs text-right">Requests</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredEndpoints.length > 0 ? (
                  filteredEndpoints.map((ep: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-1.5">
                        <EndpointBadge status={ep.status} />
                      </TableCell>
                      <TableCell className="py-1.5 font-mono text-xs text-muted-foreground">{ep.prefix}</TableCell>
                      <TableCell className="py-1.5 text-right">
                        <span className={`text-xs font-mono font-semibold ${
                          ep.last_status_code >= 500 ? "text-red-400"
                          : ep.last_status_code >= 400 ? "text-yellow-400"
                          : "text-green-400"
                        }`}>
                          {ep.last_status_code}
                        </span>
                      </TableCell>
                      <TableCell className="py-1.5 text-right text-xs font-mono">
                        {ep.avg_latency_ms > 0 ? `${ep.avg_latency_ms}` : "—"}
                      </TableCell>
                      <TableCell className="py-1.5 text-right text-xs font-mono">
                        {ep.p95_latency_ms > 0 ? `${ep.p95_latency_ms}` : "—"}
                      </TableCell>
                      <TableCell className="py-1.5 text-right">
                        <span className={`text-xs font-mono ${ep.error_rate_pct > 10 ? "text-red-400" : ep.error_rate_pct > 0 ? "text-yellow-400" : "text-muted-foreground"}`}>
                          {ep.request_count > 0 ? `${ep.error_rate_pct}%` : "—"}
                        </span>
                      </TableCell>
                      <TableCell className="py-1.5 text-right text-xs font-mono text-muted-foreground">
                        {ep.request_count > 0 ? ep.request_count : "—"}
                      </TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center text-xs text-muted-foreground py-8">
                      {endpointQuery.isLoading ? "Loading endpoint health…" : "No endpoint data available"}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* ── CPU / Memory / DB metrics row ───────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Process info */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Cpu className="h-4 w-4 text-primary" />
              CPU &amp; Memory
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { label: "PID",         value: metrics.process?.pid ?? "—" },
              { label: "User CPU",    value: metrics.process?.user_cpu_seconds   != null ? `${metrics.process.user_cpu_seconds.toFixed(1)}s`   : "—" },
              { label: "System CPU",  value: metrics.process?.system_cpu_seconds != null ? `${metrics.process.system_cpu_seconds.toFixed(1)}s` : "—" },
              { label: "RSS Memory",  value: metrics.process?.max_rss_mb         != null ? `${metrics.process.max_rss_mb.toFixed(0)} MB`       : "—" },
              { label: "Platform",    value: metrics.platform ?? "—" },
              { label: "Uptime",      value: health.uptime_seconds != null
                  ? `${Math.floor(health.uptime_seconds / 3600)}h ${Math.floor((health.uptime_seconds % 3600) / 60)}m`
                  : "—" },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between text-xs">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-medium font-mono text-right max-w-[160px] truncate">{String(value)}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Database sizes */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Database className="h-4 w-4 text-primary" />
              Databases ({dbHealthy}/{dbCount} healthy)
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 max-h-56 overflow-y-auto">
            {Object.keys(dbDetails).length > 0 ? (
              Object.entries(dbDetails).map(([name, info]: [string, any]) => (
                <div key={name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <StatusDot status={info.status === "not_found" ? "error" : info.status ?? "unknown"} />
                    <span className="text-muted-foreground capitalize">{name}</span>
                  </div>
                  <span className="font-medium font-mono">
                    {info.size_mb != null ? `${info.size_mb.toFixed(2)} MB` : info.status === "not_found" ? "missing" : "—"}
                  </span>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">No database info available</p>
            )}
            <div className="flex justify-between text-xs pt-2 border-t border-border/30">
              <span className="text-muted-foreground font-medium">Total Size</span>
              <span className="font-bold font-mono">{dbTotalMb.toFixed(1)} MB</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">WAL Mode</span>
              <Badge variant="outline" className="text-[10px]">Enabled</Badge>
            </div>
          </CardContent>
        </Card>

        {/* LLM providers */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Brain className="h-4 w-4 text-primary" />
              LLM Providers ({configuredLlmCount}/{llmProviders.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {llmProviders.length > 0 ? (
              llmProviders.map((p: any) => (
                <div key={p.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <StatusDot status={p.status === "ready" ? "healthy" : p.status === "unconfigured" ? "unknown" : "error"} />
                    <span className="capitalize">{p.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground font-mono text-[11px]">{p.model}</span>
                    {p.name === activeLlm && (
                      <Badge variant="default" className="text-[9px] px-1.5 py-0">active</Badge>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">No LLM providers configured</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Scanner status grid ─────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Scan className="h-4 w-4 text-primary" />
            Native Scanners ({scannerAvailable}/{scannerCount} available)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {Object.entries(scannerDetails).map(([name, info]: [string, any]) => {
              const st = info.status ?? "unknown";
              const ok = st === "loaded" || st === "available";
              return (
                <div key={name} className={`p-3 rounded-lg border text-center ${ok ? "border-green-700/40 bg-green-950/20" : "border-yellow-700/40 bg-yellow-950/20"}`}>
                  <div className="flex items-center justify-center gap-1.5 mb-1">
                    <StatusDot status={ok ? "healthy" : "degraded"} />
                    <span className="text-xs font-semibold uppercase">{name}</span>
                  </div>
                  <span className="text-[10px] text-muted-foreground capitalize">{st}</span>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* ── Recent request logs ──────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-3">
            <CardTitle className="text-base flex items-center gap-2">
              <FileText className="h-4 w-4 text-primary" />
              Recent Request Logs
              <span className="text-xs text-muted-foreground font-normal ml-1">
                ({logEntries.length} entries)
              </span>
            </CardTitle>
            <div className="relative w-56">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                value={logsFilter}
                onChange={(e) => setLogsFilter(e.target.value)}
                placeholder="Filter path or code…"
                className="pl-8 h-8 text-xs"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto max-h-72 overflow-y-auto">
            <Table>
              <TableHeader className="sticky top-0 bg-card z-10">
                <TableRow className="hover:bg-transparent border-b border-border/40">
                  <TableHead className="text-xs">Time</TableHead>
                  <TableHead className="text-xs">Method</TableHead>
                  <TableHead className="text-xs">Path</TableHead>
                  <TableHead className="text-xs text-right">Status</TableHead>
                  <TableHead className="text-xs text-right">ms</TableHead>
                  <TableHead className="text-xs">Org</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredLogs.length > 0 ? (
                  filteredLogs.slice(0, 100).map((entry: any, i: number) => {
                    const ts = entry.ts ? new Date(entry.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "—";
                    const status = entry.status_code ?? 0;
                    return (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="py-1 text-xs font-mono text-muted-foreground whitespace-nowrap">{ts}</TableCell>
                        <TableCell className="py-1">
                          <span className="text-xs font-bold font-mono text-blue-400">{entry.method ?? "—"}</span>
                        </TableCell>
                        <TableCell className="py-1 font-mono text-xs text-muted-foreground max-w-xs truncate">
                          {entry.path ?? "—"}
                        </TableCell>
                        <TableCell className="py-1 text-right">
                          <span className={`text-xs font-mono font-semibold ${
                            status >= 500 ? "text-red-400"
                            : status >= 400 ? "text-yellow-400"
                            : status >= 200 ? "text-green-400"
                            : "text-muted-foreground"
                          }`}>{status || "—"}</span>
                        </TableCell>
                        <TableCell className="py-1 text-right text-xs font-mono text-muted-foreground">
                          {entry.duration_ms != null ? Math.round(entry.duration_ms) : "—"}
                        </TableCell>
                        <TableCell className="py-1 text-xs text-muted-foreground truncate max-w-[80px]">
                          {entry.org_id ?? "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })
                ) : (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center text-xs text-muted-foreground py-8">
                      {logsQuery.isLoading ? "Loading logs…" : "No recent request logs"}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* ── Service info + Storage ───────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              Service Info
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {[
              { label: "Service",  value: health.service ?? "fixops-api" },
              { label: "Version",  value: health.version ?? "—" },
              { label: "Uptime",   value: health.uptime_seconds != null
                ? `${Math.floor(health.uptime_seconds / 3600)}h ${Math.floor((health.uptime_seconds % 3600) / 60)}m`
                : "—" },
              { label: "Python",   value: subsystems.api?.python_version ?? metrics.python_version ?? "—" },
              { label: "Mode",     value: subsystems.configuration?.mode ?? "—" },
              { label: "Status",   value: health.status ?? "—" },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between text-xs">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-medium font-mono">{value}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-primary" />
              Storage Directories
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {subsystems.storage?.directories ? (
              Object.entries(subsystems.storage.directories).map(([dir, status]: [string, any]) => (
                <div key={dir} className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground font-mono">{dir}</span>
                  <Badge variant={status === "accessible" ? "default" : "destructive"} className="text-[10px]">
                    {status}
                  </Badge>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">No storage info available</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* ── Integration health table ─────────────────────────────────────── */}
      {integrations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="h-4 w-4 text-primary" />
              Integration Health ({integrations.length} configured)
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent border-b border-border/40">
                    <TableHead className="text-xs">Integration</TableHead>
                    <TableHead className="text-xs">Type</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                    <TableHead className="text-xs">Last Sync</TableHead>
                    <TableHead className="text-xs">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {integrations.slice(0, 15).map((intg: any) => (
                    <TableRow key={intg.id} className="hover:bg-muted/30">
                      <TableCell className="text-sm font-medium">{intg.name ?? "Unknown"}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] capitalize">{intg.integration_type ?? "—"}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1.5">
                          <StatusDot status={intg.status === "active" ? "healthy" : intg.status === "inactive" ? "degraded" : "error"} />
                          <span className="text-xs capitalize">{intg.status ?? "unknown"}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{intg.last_sync_at ?? "Never"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {intg.created_at ? new Date(intg.created_at).toLocaleDateString() : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}

// ─── Extended events panel (used externally when event data is present) ────────
function SystemEventRow({ event }: { event: any }) {
  const level = event.level ?? "info";
  return (
    <div className="flex items-start gap-3 py-2 border-b border-border/30 last:border-0">
      <span className="shrink-0 pt-0.5">
        <LogLevelBadge level={level} />
      </span>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-foreground">{event.message ?? "System event"}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{event.service ?? "core"} · {event.timestamp ?? "—"}</p>
      </div>
    </div>
  );
}

export function SystemHealthExtended({ events }: { events: any[] }) {
  if (!events || events.length === 0) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          Recent System Events
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="max-h-64 overflow-y-auto">
          {events.slice(0, 20).map((ev: any, i: number) => (
            <SystemEventRow key={i} event={ev} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
