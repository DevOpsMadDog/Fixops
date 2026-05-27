/**
 * Security Metrics Live Dashboard
 *
 * KPI tracking, threshold alerts, and trend aggregation.
 *   1. KPIs: Tracked Metrics, Active Alerts, Critical Breaches, Metrics at Target
 *   2. Metric dashboard grid (from /security-metrics/metrics)
 *   3. Readings sparkline for selected metric
 *   4. Alert list (from /security-metrics/alerts)
 *   5. Aggregate table (from /security-metrics/metrics stats)
 *
 * Route: /security-metrics-live
 * API:
 *   GET /api/v1/security-metrics/metrics
 *   GET /api/v1/security-metrics/alerts
 *   GET /api/v1/security-metrics/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  BarChart3, AlertTriangle, Target, Activity, RefreshCw,
  TrendingUp, TrendingDown, Minus, Bell, CheckCircle,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";

async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

type MetricStatus = "normal" | "warning" | "critical";
type MetricTrend  = "up" | "down" | "flat";

interface Metric {
  id: string;
  name: string;
  category: string;
  current: number;
  target: number;
  unit: string;
  status: MetricStatus;
  trend: MetricTrend;
  updated: string;
  readings?: number[];
}

interface AlertItem {
  id: string;
  severity: string;
  metric?: string;
  name?: string;
  msg?: string;
  message?: string;
  created?: string;
  created_at?: string;
}

// ── Helpers ────────────────────────────────────────────────────

const STATUS_STYLES: Record<MetricStatus, string> = {
  normal:   "border-green-500/30 text-green-400 bg-green-500/10",
  warning:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500",
  warning:  "bg-amber-500",
  high:     "bg-orange-500",
  info:     "bg-blue-500",
};

function TrendIcon({ trend }: { trend: MetricTrend }) {
  if (trend === "up")   return <TrendingUp   className="h-3.5 w-3.5 text-green-400" />;
  if (trend === "down") return <TrendingDown className="h-3.5 w-3.5 text-red-400" />;
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
}

function normaliseMetric(m: Record<string, unknown>, idx: number): Metric {
  const rawStatus = String(m.status ?? "normal").toLowerCase();
  const status: MetricStatus = (["normal", "warning", "critical"] as MetricStatus[]).includes(rawStatus as MetricStatus)
    ? (rawStatus as MetricStatus) : "normal";
  const rawTrend = String(m.trend ?? "flat").toLowerCase();
  const trend: MetricTrend = (["up", "down", "flat"] as MetricTrend[]).includes(rawTrend as MetricTrend)
    ? (rawTrend as MetricTrend) : "flat";
  return {
    id:       String(m.id ?? m.metric_id ?? idx),
    name:     String(m.name ?? m.metric_name ?? m.title ?? `Metric ${idx + 1}`),
    category: String(m.category ?? ""),
    current:  Number(m.current ?? m.value ?? m.current_value ?? 0),
    target:   Number(m.target  ?? m.target_value ?? 0),
    unit:     String(m.unit ?? ""),
    status,
    trend,
    updated:  String(m.updated ?? m.updated_at ?? ""),
    readings: Array.isArray(m.readings) ? (m.readings as number[]) : undefined,
  };
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityMetricsDashboard2() {
  const [selectedIdx, setSelectedIdx] = useState<number>(0);
  const [refreshing, setRefreshing]   = useState(false);
  const [acked, setAcked]             = useState<Set<string>>(new Set());
  const [loading, setLoading]         = useState(true);

  const [metrics, setMetrics] = useState<Metric[]>([]);
  const [alerts, setAlerts]   = useState<AlertItem[]>([]);
  const [stats, setStats]     = useState<Record<string, unknown> | null>(null);

  const fetchAll = () => {
    setLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/security-metrics/metrics?org_id=default"),
      apiFetch("/api/v1/security-metrics/alerts?org_id=default"),
      apiFetch("/api/v1/security-metrics/stats?org_id=default"),
    ]).then(([mRes, aRes, sRes]) => {
      if (mRes.status === "fulfilled") {
        const d = mRes.value as Record<string, unknown>;
        const arr: unknown[] = Array.isArray(d) ? d as unknown[] : ((d.metrics ?? d.items ?? []) as unknown[]);
        setMetrics((arr as Record<string, unknown>[]).map((m, i) => normaliseMetric(m, i)));
      }
      if (aRes.status === "fulfilled") {
        const d = aRes.value as Record<string, unknown>;
        const arr: unknown[] = Array.isArray(d) ? d as unknown[] : ((d.alerts ?? d.items ?? []) as unknown[]);
        setAlerts(arr as AlertItem[]);
      }
      if (sRes.status === "fulfilled") setStats(sRes.value as Record<string, unknown>);
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchAll(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAll();
    setTimeout(() => setRefreshing(false), 800);
  };

  const selMetric  = metrics[selectedIdx];
  const readings   = selMetric?.readings ?? [];
  const maxReading = readings.length > 0 ? Math.max(...readings) : 1;

  const totalTracked   = stats?.total          ?? metrics.length;
  const activeAlerts   = stats?.active_alerts  ?? alerts.filter((a) => !acked.has(a.id)).length;
  const critBreaches   = stats?.critical_count ?? metrics.filter((m) => m.status === "critical").length;
  const atTarget       = stats?.at_target      ?? metrics.filter((m) => m.current <= m.target).length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Metrics Live"
        description="KPI tracking, threshold alerts, and trend aggregation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Tracked Metrics"   value={Number(totalTracked)}  icon={BarChart3}    trend="up"  />
        <KpiCard title="Active Alerts"     value={Number(activeAlerts)}  icon={AlertTriangle} trend="up"  className="border-amber-500/20" />
        <KpiCard title="Critical Breaches" value={Number(critBreaches)}  icon={AlertTriangle} trend="up"  className="border-red-500/20" />
        <KpiCard title="Metrics at Target" value={Number(atTarget)}      icon={Target}        trend="up"  className="border-green-500/20" />
      </div>

      {/* Metric grid */}
      {loading ? (
        <div className="flex items-center justify-center h-40">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
        </div>
      ) : metrics.length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-14 text-muted-foreground gap-2">
            <BarChart3 className="h-8 w-8 opacity-30" />
            <p className="text-sm">No metrics data available</p>
            <p className="text-xs">Metrics will appear once the engine collects data</p>
          </CardContent>
        </Card>
      ) : (
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground mb-3 uppercase tracking-wider">Metric Dashboard</h3>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {metrics.map((m, i) => (
              <Card
                key={m.id}
                onClick={() => setSelectedIdx(i)}
                className={cn(
                  "cursor-pointer transition-all hover:border-primary/40",
                  selectedIdx === i && "border-primary/60 bg-primary/5",
                  m.status === "critical" && "border-red-500/30",
                  m.status === "warning"  && "border-amber-500/30"
                )}
              >
                <CardContent className="p-3">
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-[11px] font-medium leading-tight text-foreground">{m.name}</span>
                    <TrendIcon trend={m.trend} />
                  </div>
                  <div className="flex items-baseline gap-1 mb-2">
                    <span className="text-xl font-bold tabular-nums">{m.current}</span>
                    {m.unit && <span className="text-xs text-muted-foreground">{m.unit}</span>}
                  </div>
                  <div className="flex items-center justify-between">
                    <Badge className={cn("text-[10px] border capitalize", STATUS_STYLES[m.status])}>{m.status}</Badge>
                    <span className="text-[10px] text-muted-foreground">target: {m.target}{m.unit}</span>
                  </div>
                  {m.updated && <div className="mt-1 text-[10px] text-muted-foreground truncate">{m.updated}</div>}
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}

      {/* Sparkline + Alerts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Sparkline */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Readings — {selMetric?.name ?? "Select a metric above"}
            </CardTitle>
            <CardDescription className="text-xs">Last readings for selected metric</CardDescription>
          </CardHeader>
          <CardContent>
            {readings.length === 0 ? (
              <div className="flex items-center justify-center h-28 text-muted-foreground text-xs">
                No reading history available
              </div>
            ) : (
              <>
                <div className="flex items-end gap-1 h-28 mb-2">
                  {readings.map((v, i) => {
                    const pct = maxReading > 0 ? (v / maxReading) * 100 : 0;
                    const isLast = i === readings.length - 1;
                    return (
                      <div key={i} className="flex-1 flex flex-col items-center gap-0.5 h-full justify-end" title={`${v}${selMetric?.unit ?? ""}`}>
                        <div
                          className={cn("w-full rounded-t transition-all", isLast ? "bg-primary" : "bg-muted-foreground/30")}
                          style={{ height: `${pct}%` }}
                        />
                      </div>
                    );
                  })}
                </div>
                <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                  <span>{readings.length} readings ago</span>
                  <span>Now: {readings[readings.length - 1]}{selMetric?.unit}</span>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Alert list */}
        <Card className="border-amber-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                <Bell className="h-4 w-4" />
                Threshold Alerts
              </CardTitle>
              <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
                {alerts.filter((a) => !acked.has(a.id)).length} unacknowledged
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {alerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-2">
                <CheckCircle className="h-6 w-6 opacity-30" />
                <p className="text-xs">No active alerts</p>
              </div>
            ) : (
              <div className="max-h-64 overflow-y-auto divide-y divide-border/40">
                {alerts.map((a) => (
                  <div
                    key={a.id}
                    className={cn("flex items-start gap-2 px-4 py-2.5", acked.has(a.id) && "opacity-40")}
                  >
                    <span className={cn("w-2 h-2 rounded-full mt-1 shrink-0", SEV_DOT[a.severity] ?? "bg-slate-500")} />
                    <div className="flex-1 min-w-0">
                      <div className="text-[11px] font-medium truncate">{a.metric ?? a.name ?? "Alert"}</div>
                      <div className="text-[10px] text-muted-foreground">{a.msg ?? a.message ?? ""}</div>
                      <div className="text-[10px] text-muted-foreground/60 mt-0.5">
                        {a.created ?? (a.created_at ? String(a.created_at).slice(0, 16).replace("T", " ") : "")}
                      </div>
                    </div>
                    {!acked.has(a.id) ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-[10px] shrink-0"
                        onClick={() => setAcked((prev) => new Set([...prev, a.id]))}
                      >
                        Ack
                      </Button>
                    ) : (
                      <CheckCircle className="h-3.5 w-3.5 text-green-500 shrink-0 mt-0.5" />
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Aggregate table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-purple-400" />
            Metric Summary
          </CardTitle>
          <CardDescription className="text-xs">Current values, targets, and status for all tracked metrics</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {metrics.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-2">
              <BarChart3 className="h-6 w-6 opacity-30" />
              <p className="text-xs">No metrics to aggregate</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Metric</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Current</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Target</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Trend</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {metrics.map((m) => (
                    <TableRow key={m.id} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2.5">{m.name}</TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{m.category}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">{m.current}{m.unit}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{m.target}{m.unit}</TableCell>
                      <TableCell className="py-2.5">
                        <Badge className={cn("text-[10px] border capitalize", STATUS_STYLES[m.status])}>{m.status}</Badge>
                      </TableCell>
                      <TableCell className="py-2.5"><TrendIcon trend={m.trend} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
