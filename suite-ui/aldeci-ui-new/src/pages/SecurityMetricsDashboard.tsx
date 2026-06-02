/**
 * Security Metrics Dashboard
 *
 * Trend analysis and KPI tracking across all security domains.
 *   1. KPIs: MTTD, MTTR, Security Score, SLA Compliance  (from /security-metrics/stats)
 *   2. Top metrics table  (from /security-metrics/metrics)
 *   3. Category breakdown — score bars
 *   4. Alert thresholds panel  (from /security-metrics/alerts)
 *
 * API:
 *   GET /api/v1/security-metrics/metrics
 *   GET /api/v1/security-metrics/stats
 *   GET /api/v1/security-metrics/alerts
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import {
  Clock,
  TrendingDown,
  TrendingUp,
  Shield,
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Target,
  Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";

// ── API helpers ────────────────────────────────────────────────

const apiKey = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || (getStoredAuthToken() ?? "");
const apiFetch = (path: string) =>
  fetch(`/api/v1${path}`, { headers: { "X-API-Key": apiKey } }).then((r) => {
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  });

// ── Types ──────────────────────────────────────────────────────

interface MetricRow {
  name: string;
  current: string;
  target: string;
  variance: string;
  meeting: boolean;
  trend: string;
}

interface AlertThreshold {
  name: string;
  condition?: string;
  status: string;
  detail?: string;
  message?: string;
  severity?: string;
  metric?: string;
}

// ── Helpers ────────────────────────────────────────────────────

function TrendArrow({ trend, meeting }: { trend: string; meeting: boolean }) {
  if (trend === "up") {
    return meeting
      ? <TrendingUp className="h-3.5 w-3.5 text-green-400" />
      : <TrendingUp className="h-3.5 w-3.5 text-red-400" />;
  }
  return meeting
    ? <TrendingDown className="h-3.5 w-3.5 text-green-400" />
    : <TrendingDown className="h-3.5 w-3.5 text-red-400" />;
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityMetricsDashboard() {
  usePageTitle("Security Metrics");
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);

  const [statsData, setStatsData]     = useState<Record<string, unknown> | null>(null);
  const [metricsData, setMetricsData] = useState<MetricRow[]>([]);
  const [alertsData, setAlertsData]   = useState<AlertThreshold[]>([]);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch("/security-metrics/metrics?org_id=default"),
      apiFetch("/security-metrics/stats?org_id=default"),
      apiFetch("/security-metrics/alerts?org_id=default"),
    ]).then(([metricsResult, statsResult, alertsResult]) => {
      if (statsResult.status === "fulfilled") {
        setStatsData(statsResult.value as Record<string, unknown>);
      }
      if (metricsResult.status === "fulfilled") {
        const d = metricsResult.value as Record<string, unknown>;
        const arr: unknown[] = Array.isArray(d) ? d as unknown[] : ((d.metrics ?? d.items ?? []) as unknown[]);
        setMetricsData(
          (arr as Record<string, unknown>[]).map((m) => ({
            name:     String(m.name    ?? m.metric_name ?? m.title ?? ""),
            current:  String(m.current ?? m.value ?? m.current_value ?? "—"),
            target:   String(m.target  ?? m.target_value ?? "—"),
            variance: String(m.variance ?? "—"),
            meeting:  Boolean(m.meeting ?? m.on_target ?? false),
            trend:    String(m.trend   ?? "up"),
          }))
        );
      }
      if (alertsResult.status === "fulfilled") {
        const d = alertsResult.value as Record<string, unknown>;
        const arr: unknown[] = Array.isArray(d) ? d as unknown[] : ((d.alerts ?? d.items ?? []) as unknown[]);
        setAlertsData(arr as AlertThreshold[]);
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const s = statsData as Record<string, unknown> | null;
  const liveMttd  = String(s?.mttd           ?? s?.mean_time_to_detect   ?? "—");
  const liveMttr  = String(s?.mttr           ?? s?.mean_time_to_respond  ?? "—");
  const liveScore = String(s?.security_score ?? s?.score                 ?? "—");
  const liveSla   = String(s?.sla_compliance ?? s?.sla                   ?? "—");

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Metrics Dashboard"
        description="Trend analysis and KPI tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="MTTD"           value={liveMttd}  icon={Clock}        trend="down" className="border-blue-500/20" />
        <KpiCard title="MTTR"           value={liveMttr}  icon={Activity}     trend="down" className="border-green-500/20" />
        <KpiCard title="Security Score" value={liveScore} icon={Shield}       trend="up"   className="border-purple-500/20" />
        <KpiCard title="SLA Compliance" value={liveSla}   icon={CheckCircle2} trend="up"   className="border-amber-500/20" />
      </div>

      {/* Top metrics table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Target className="h-4 w-4 text-indigo-400" />
            Security Metrics
          </CardTitle>
          <CardDescription className="text-xs">Current vs. target with variance and trend direction</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {metricsData.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 text-muted-foreground gap-2">
              <BarChart3 className="h-8 w-8 opacity-30" />
              <p className="text-sm">No metrics data available</p>
              <p className="text-xs">Metrics will appear once the engine collects data</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Metric</TableHead>
                    <TableHead className="text-[11px] h-8">Current</TableHead>
                    <TableHead className="text-[11px] h-8">Target</TableHead>
                    <TableHead className="text-[11px] h-8">Variance</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Trend</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {metricsData.map((row) => (
                    <TableRow key={row.name} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2.5">{row.name}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 font-bold">{row.current}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{row.target}</TableCell>
                      <TableCell className={cn("text-xs tabular-nums py-2.5 font-semibold", row.meeting ? "text-green-400" : "text-red-400")}>
                        {row.variance}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {row.meeting
                          ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">On Target</Badge>
                          : <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Off Target</Badge>
                        }
                      </TableCell>
                      <TableCell className="py-2.5">
                        <TrendArrow trend={row.trend} meeting={row.meeting} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Alert thresholds */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            Alert Thresholds
          </CardTitle>
          <CardDescription className="text-xs">Automated escalation rules and current status</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {alertsData.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-2">
              <Shield className="h-8 w-8 opacity-30" />
              <p className="text-sm">No active alerts</p>
              <p className="text-xs">All thresholds are within acceptable ranges</p>
            </div>
          ) : (
            alertsData.map((t, i) => {
              const isTriggered = t.status === "triggered" || t.severity === "critical" || t.severity === "high";
              return (
                <div
                  key={t.name ?? i}
                  className={cn(
                    "flex items-start gap-3 rounded-lg border p-3",
                    isTriggered ? "border-red-500/30 bg-red-500/5" : "border-border bg-muted/10"
                  )}
                >
                  <div className={cn(
                    "mt-0.5 h-2 w-2 rounded-full flex-shrink-0",
                    isTriggered ? "bg-red-500 animate-pulse" : "bg-green-500"
                  )} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold">{t.name ?? t.metric ?? "Alert"}</span>
                      <Badge className={cn(
                        "text-[10px] border flex-shrink-0",
                        isTriggered
                          ? "border-red-500/30 text-red-400 bg-red-500/10"
                          : "border-green-500/30 text-green-400 bg-green-500/10"
                      )}>
                        {t.status ?? t.severity ?? "active"}
                      </Badge>
                    </div>
                    {(t.condition ?? t.message) && (
                      <p className="text-[10px] text-muted-foreground mt-0.5 font-mono">{t.condition ?? t.message}</p>
                    )}
                    {t.detail && <p className="text-[10px] text-muted-foreground mt-0.5">{t.detail}</p>}
                  </div>
                </div>
              );
            })
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
