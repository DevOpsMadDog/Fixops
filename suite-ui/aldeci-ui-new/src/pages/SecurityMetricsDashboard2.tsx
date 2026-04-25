/**
 * Security Metrics Live Dashboard
 *
 * KPI tracking, threshold alerts, and trend aggregation.
 *   1. KPIs: Tracked Metrics, Active Alerts, Critical Breaches, Metrics at Target
 *   2. Metric dashboard grid (8 metric cards)
 *   3. Readings sparkline (CSS bars for selected metric)
 *   4. Alert list (10 unacknowledged alerts)
 *   5. Aggregate table (8 metrics with daily/weekly/monthly stats)
 *
 * Route: /security-metrics-live (avoids conflict with /security-metrics)
 * API stubs: GET /api/v1/security-metrics, /api/v1/security-metrics/alerts
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  BarChart3, AlertTriangle, Target, Activity, RefreshCw,
  TrendingUp, TrendingDown, Minus, Bell, CheckCircle,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
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

// ── Mock data ──────────────────────────────────────────────────

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
}

const METRICS: Metric[] = [
  { id: "m1", name: "Mean Time to Detect",    category: "IR",          current: 2.1,  target: 2.0,  unit: "hrs",    status: "warning",  trend: "down",  updated: "2 min ago" },
  { id: "m2", name: "Mean Time to Respond",   category: "IR",          current: 4.2,  target: 8.0,  unit: "hrs",    status: "normal",   trend: "down",  updated: "2 min ago" },
  { id: "m3", name: "Patch Compliance Rate",  category: "Vuln",        current: 78,   target: 90,   unit: "%",      status: "warning",  trend: "up",    updated: "5 min ago" },
  { id: "m4", name: "Open Critical Vulns",    category: "Vuln",        current: 14,   target: 5,    unit: "",       status: "critical", trend: "up",    updated: "5 min ago" },
  { id: "m5", name: "SLA Compliance",         category: "SLA",         current: 78,   target: 95,   unit: "%",      status: "warning",  trend: "down",  updated: "10 min ago" },
  { id: "m6", name: "Phishing Click Rate",    category: "Awareness",   current: 3.2,  target: 2.0,  unit: "%",      status: "warning",  trend: "down",  updated: "1 hr ago" },
  { id: "m7", name: "MFA Adoption",           category: "IAM",         current: 94,   target: 100,  unit: "%",      status: "normal",   trend: "up",    updated: "15 min ago" },
  { id: "m8", name: "Endpoint Detection %",   category: "EDR",         current: 99.1, target: 99.0, unit: "%",      status: "normal",   trend: "flat",  updated: "1 min ago" },
];

const READINGS: Record<string, number[]> = {
  m1: [3.1, 2.8, 2.6, 2.4, 2.5, 2.3, 2.2, 2.1, 2.3, 2.0, 2.2, 2.1],
  m2: [6.5, 5.9, 5.2, 4.8, 4.5, 4.3, 4.6, 4.2, 4.0, 4.4, 4.1, 4.2],
  m3: [68, 70, 72, 74, 75, 76, 75, 77, 76, 78, 77, 78],
  m4: [22, 20, 19, 17, 16, 15, 17, 16, 15, 14, 15, 14],
  m5: [82, 80, 79, 78, 77, 79, 78, 77, 79, 78, 77, 78],
  m6: [5.1, 4.8, 4.5, 4.2, 4.0, 3.8, 3.6, 3.5, 3.4, 3.3, 3.2, 3.2],
  m7: [88, 89, 90, 91, 91, 92, 93, 93, 94, 94, 94, 94],
  m8: [98.5, 98.7, 98.9, 99.0, 98.9, 99.0, 99.1, 99.0, 99.1, 99.1, 99.0, 99.1],
};

const ALERTS = [
  { id: "a1",  severity: "critical", metric: "Open Critical Vulns",   msg: "Threshold exceeded: 14 > target 5",         created: "2026-04-16 08:00" },
  { id: "a2",  severity: "warning",  metric: "SLA Compliance",        msg: "Below target: 78% vs 95% target",            created: "2026-04-16 08:15" },
  { id: "a3",  severity: "warning",  metric: "Patch Compliance Rate", msg: "Below target: 78% vs 90% target",            created: "2026-04-16 08:20" },
  { id: "a4",  severity: "critical", metric: "Mean Time to Detect",   msg: "Breached SLO: 2.1 hrs vs 2.0 hr target",    created: "2026-04-16 08:30" },
  { id: "a5",  severity: "warning",  metric: "Phishing Click Rate",   msg: "Above target: 3.2% vs 2.0% target",         created: "2026-04-16 09:00" },
  { id: "a6",  severity: "warning",  metric: "SLA Compliance",        msg: "Trending down for 4 consecutive readings",   created: "2026-04-16 09:10" },
  { id: "a7",  severity: "warning",  metric: "Open Critical Vulns",   msg: "3 new critical findings in last 24 hrs",     created: "2026-04-16 09:20" },
  { id: "a8",  severity: "info",     metric: "MFA Adoption",          msg: "6% below full coverage target",              created: "2026-04-16 09:30" },
  { id: "a9",  severity: "info",     metric: "Endpoint Detection %",  msg: "0.1% margin above target — monitor closely", created: "2026-04-16 09:45" },
  { id: "a10", severity: "warning",  metric: "Patch Compliance Rate", msg: "48 endpoints missing Q1 patches",            created: "2026-04-16 10:00" },
];

const AGGREGATES = [
  { name: "MTTD (hrs)",           daily_avg: 2.1,  daily_min: 1.8, daily_max: 3.4, weekly_avg: 2.4,  monthly_avg: 2.8  },
  { name: "MTTR (hrs)",           daily_avg: 4.2,  daily_min: 3.1, daily_max: 6.8, weekly_avg: 4.6,  monthly_avg: 5.2  },
  { name: "Patch Compliance (%)", daily_avg: 78,   daily_min: 76,  daily_max: 79,  weekly_avg: 77,   monthly_avg: 74   },
  { name: "Open Critical Vulns",  daily_avg: 14,   daily_min: 13,  daily_max: 17,  weekly_avg: 15.4, monthly_avg: 18.2 },
  { name: "SLA Compliance (%)",   daily_avg: 78,   daily_min: 77,  daily_max: 80,  weekly_avg: 78.2, monthly_avg: 79.1 },
  { name: "Phishing Click (%)",   daily_avg: 3.2,  daily_min: 2.8, daily_max: 3.9, weekly_avg: 3.5,  monthly_avg: 4.0  },
  { name: "MFA Adoption (%)",     daily_avg: 94,   daily_min: 93,  daily_max: 94,  weekly_avg: 93.4, monthly_avg: 91.8 },
  { name: "EDR Coverage (%)",     daily_avg: 99.1, daily_min: 99.0,daily_max: 99.2,weekly_avg: 99.0, monthly_avg: 98.9 },
];

// ── Helpers ────────────────────────────────────────────────────

const STATUS_STYLES: Record<MetricStatus, string> = {
  normal:   "border-green-500/30 text-green-400 bg-green-500/10",
  warning:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  critical: "border-red-500/30 text-red-400 bg-red-500/10",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-red-500",
  warning:  "bg-amber-500",
  info:     "bg-blue-500",
};

function TrendIcon({ trend }: { trend: MetricTrend }) {
  if (trend === "up")   return <TrendingUp   className="h-3.5 w-3.5 text-green-400" />;
  if (trend === "down") return <TrendingDown className="h-3.5 w-3.5 text-red-400" />;
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityMetricsDashboard2() {
  const [selectedMetric, setSelectedMetric] = useState<string>("m1");
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [acked, setAcked] = useState<Set<string>>(new Set());

  useEffect(() => {
    apiFetch(`/api/v1/security-metrics/metrics?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); });
  }, []);

  const readings = READINGS[selectedMetric] ?? [];
  const maxReading = Math.max(...readings);
  const selMetric = METRICS.find((m) => m.id === selectedMetric);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
    {error && (
      <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
        <p className="text-red-400 text-sm">{error}</p>
        <button
          onClick={() => { setError(null); window.location.reload(); }}
          className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
        >
          Retry
        </button>
      </div>
    )}
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
        <KpiCard title="Tracked Metrics"   value={34} icon={BarChart3}    trend="up"   />
        <KpiCard title="Active Alerts"     value={7}  icon={AlertTriangle} trend="up"  className="border-amber-500/20" />
        <KpiCard title="Critical Breaches" value={2}  icon={AlertTriangle} trend="up"  className="border-red-500/20" />
        <KpiCard title="Metrics at Target" value={18} icon={Target}        trend="up"  className="border-green-500/20" />
      </div>

      {/* Metric grid */}
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground mb-3 uppercase tracking-wider">Metric Dashboard</h3>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {METRICS.map((m) => (
            <Card
              key={m.id}
              onClick={() => setSelectedMetric(m.id)}
              className={cn(
                "cursor-pointer transition-all hover:border-primary/40",
                selectedMetric === m.id && "border-primary/60 bg-primary/5",
                m.status === "critical" && "border-red-500/30",
                m.status === "warning" && "border-amber-500/30"
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
                <div className="mt-1 text-[10px] text-muted-foreground">{m.updated}</div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Sparkline + Alerts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Sparkline */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Readings — {selMetric?.name}
            </CardTitle>
            <CardDescription className="text-xs">Last 12 readings for selected metric</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1 h-28 mb-2">
              {readings.map((v, i) => {
                const pct = maxReading > 0 ? (v / maxReading) * 100 : 0;
                const isLast = i === readings.length - 1;
                return (
                  <div key={i} className="flex-1 flex flex-col items-center gap-0.5 h-full justify-end" title={`${v}${selMetric?.unit ?? ""}`}>
                    <div
                      className={cn(
                        "w-full rounded-t transition-all",
                        isLast ? "bg-primary" : "bg-muted-foreground/30"
                      )}
                      style={{ height: `${pct}%` }}
                    />
                  </div>
                );
              })}
            </div>
            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
              <span>12 readings ago</span>
              <span>Now: {readings[readings.length - 1]}{selMetric?.unit}</span>
            </div>
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
                {ALERTS.filter((a) => !acked.has(a.id)).length} unacknowledged
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-64 overflow-y-auto divide-y divide-border/40">
              {ALERTS.map((a) => (
                <div
                  key={a.id}
                  className={cn(
                    "flex items-start gap-2 px-4 py-2.5",
                    acked.has(a.id) && "opacity-40"
                  )}
                >
                  <span className={cn("w-2 h-2 rounded-full mt-1 shrink-0", SEV_DOT[a.severity])} />
                  <div className="flex-1 min-w-0">
                    <div className="text-[11px] font-medium truncate">{a.metric}</div>
                    <div className="text-[10px] text-muted-foreground">{a.msg}</div>
                    <div className="text-[10px] text-muted-foreground/60 mt-0.5">{a.created}</div>
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
          </CardContent>
        </Card>
      </div>

      {/* Aggregate table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-purple-400" />
            Metric Aggregates
          </CardTitle>
          <CardDescription className="text-xs">Daily, weekly, and monthly averages with min/max</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Metric</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Day Avg</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Day Min</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Day Max</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Week Avg</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Month Avg</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {AGGREGATES.map((row) => (
                  <TableRow key={row.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{row.name}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{row.daily_avg}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-green-400">{row.daily_min}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-red-400">{row.daily_max}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{row.weekly_avg}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{row.monthly_avg}</TableCell>
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
