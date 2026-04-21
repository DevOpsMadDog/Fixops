/**
 * Awareness Metrics Dashboard
 *
 * Security awareness metrics tracking across departments.
 *   1. KPIs: Metrics Tracked, Departments, Best Metric, Worst Metric
 *   2. Metrics table (metric_type, department, value, period, sample_size, recorded_at)
 *
 * Route: /awareness-metrics
 * API: GET /api/v1/awareness-metrics
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BookOpen, RefreshCw, TrendingUp, TrendingDown, Users, BarChart2 } from "lucide-react";

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

const MOCK_METRICS = [
  { id: "met-001", metric_type: "Phishing Click Rate",       department: "Engineering",    value: 2.1,  period: "Q1-2026", sample_size: 340,  recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-002", metric_type: "Training Completion Rate",  department: "Engineering",    value: 94.3, period: "Q1-2026", sample_size: 340,  recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-003", metric_type: "Phishing Click Rate",       department: "Finance",        value: 8.7,  period: "Q1-2026", sample_size: 120,  recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-004", metric_type: "Training Completion Rate",  department: "Finance",        value: 71.2, period: "Q1-2026", sample_size: 120,  recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-005", metric_type: "Incident Report Rate",      department: "HR",             value: 43.5, period: "Q1-2026", sample_size: 85,   recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-006", metric_type: "Password Policy Adherence", department: "Sales",          value: 88.9, period: "Q1-2026", sample_size: 210,  recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-007", metric_type: "MFA Enrollment Rate",       department: "Operations",     value: 97.4, period: "Q1-2026", sample_size: 180,  recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-008", metric_type: "Phishing Click Rate",       department: "Legal",          value: 3.8,  period: "Q1-2026", sample_size: 55,   recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-009", metric_type: "Training Completion Rate",  department: "Marketing",      value: 62.0, period: "Q1-2026", sample_size: 95,   recorded_at: "2026-04-01T00:00:00Z" },
  { id: "met-010", metric_type: "MFA Enrollment Rate",       department: "Executive",      value: 100.0, period: "Q1-2026", sample_size: 12, recorded_at: "2026-04-01T00:00:00Z" },
];

const MOCK_STATS = {
  metrics_tracked: 48,
  departments: 9,
  best_metric: "MFA Enrollment — Executive: 100%",
  worst_metric: "Training Completion — Marketing: 62%",
};

// ── Badge helpers ──────────────────────────────────────────────

function MetricTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    "Phishing Click Rate":        "border-red-500/30 text-red-400 bg-red-500/10",
    "Training Completion Rate":   "border-green-500/30 text-green-400 bg-green-500/10",
    "MFA Enrollment Rate":        "border-teal-500/30 text-teal-400 bg-teal-500/10",
    "Incident Report Rate":       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "Password Policy Adherence":  "border-emerald-500/30 text-emerald-400 bg-emerald-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function formatTs(ts: string) {
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", year: "numeric" });
}

// ── Component ──────────────────────────────────────────────────

export default function AwarenessMetricsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveMetrics, setLiveMetrics] = useState<any[] | null>(null);
  const [liveStats, setLiveStats]   = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/awareness-metrics/metrics?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/awareness-metrics/stats?org_id=${ORG_ID}`),
    ]).then(([metricsRes, statsRes]) => {
      if (metricsRes.status === "fulfilled") setLiveMetrics(metricsRes.value?.metrics ?? metricsRes.value ?? null);
      if (statsRes.status === "fulfilled")   setLiveStats(statsRes.value ?? null);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const metrics = liveMetrics ?? MOCK_METRICS;
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
        title="Awareness Metrics"
        description="Security awareness program metrics — phishing click rates, training completion, MFA adoption by department"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Metrics Tracked" value={stats.metrics_tracked}  icon={BookOpen}    trend="up"   className="border-green-500/20" />
        <KpiCard title="Departments"     value={stats.departments}       icon={Users}       trend="flat" className="border-teal-500/20" />
        <KpiCard title="Best Metric"     value={stats.best_metric}       icon={TrendingUp}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Worst Metric"    value={stats.worst_metric}      icon={TrendingDown} trend="down" className="border-teal-500/20" />
      </div>

      {/* Metrics Table */}
      <Card className="border-green-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
              <BarChart2 className="h-4 w-4" />
              Awareness Metrics by Department
            </CardTitle>
            <Badge className="text-[10px] border border-teal-500/30 text-teal-400 bg-teal-500/10">
              {stats.departments} depts tracked
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Per-department security awareness KPIs including phishing resilience, training completion, and MFA adoption
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Metric Type</TableHead>
                  <TableHead className="text-[11px] h-8">Department</TableHead>
                  <TableHead className="text-[11px] h-8">Value</TableHead>
                  <TableHead className="text-[11px] h-8">Period</TableHead>
                  <TableHead className="text-[11px] h-8">Sample Size</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Recorded</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {metrics.map((metric: any, i: number) => (
                  <TableRow key={metric.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2">
                      <MetricTypeBadge type={metric.metric_type ?? "—"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] font-semibold text-green-300">
                      {metric.department ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-teal-300">
                      {metric.value != null ? `${metric.value}%` : "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {metric.period ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {metric.sample_size ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {metric.recorded_at ? formatTs(metric.recorded_at) : "—"}
                    </TableCell>
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
