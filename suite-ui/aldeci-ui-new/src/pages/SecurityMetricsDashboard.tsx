/**
 * Security Metrics Dashboard
 *
 * Trend analysis and KPI tracking across all security domains.
 *   1. KPIs: MTTD, MTTR, Security Score, SLA Compliance
 *   2. 12-month MTTD/MTTR trend chart — div-based bar groups
 *   3. Top 10 metrics table — value, target, variance, trend
 *   4. Category breakdown — Vuln Mgmt, Incident Response, Compliance, Access Control
 *   5. Alert thresholds panel — 4 threshold rules
 *
 * API stubs: GET /api/v1/kpi/metrics, /api/v1/kpi/trends, /api/v1/kpi/thresholds
 */

import { useState, useEffect } from "react";
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
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";

// ── API helpers ────────────────────────────────────────────────

const apiKey = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || "dev-key";
const apiFetch = (path: string) =>
  fetch(`/api/v1${path}`, { headers: { "X-API-Key": apiKey } }).then((r) => {
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  });

// ── Mock data ──────────────────────────────────────────────────

const TREND_DATA = [
  { month: "May", mttd: 5.8, mttr: 9.2 },
  { month: "Jun", mttd: 5.4, mttr: 8.7 },
  { month: "Jul", mttd: 5.1, mttr: 8.3 },
  { month: "Aug", mttd: 4.9, mttr: 8.0 },
  { month: "Sep", mttd: 4.7, mttr: 7.6 },
  { month: "Oct", mttd: 4.5, mttr: 7.4 },
  { month: "Nov", mttd: 4.4, mttr: 7.2 },
  { month: "Dec", mttd: 4.6, mttr: 7.5 },
  { month: "Jan", mttd: 4.3, mttr: 7.1 },
  { month: "Feb", mttd: 4.1, mttr: 6.9 },
  { month: "Mar", mttd: 4.4, mttr: 7.0 },
  { month: "Apr", mttd: 4.2, mttr: 6.8 },
];

const TREND_MAX = 10;

const TOP_METRICS = [
  { name: "Mean Time to Detect",       current: "4.2h",  target: "4.0h",  variance: "-0.2h",  meeting: false, trend: "down" },
  { name: "Mean Time to Respond",      current: "6.8h",  target: "8.0h",  variance: "+1.2h",  meeting: true,  trend: "down" },
  { name: "Mean Time to Resolve",      current: "3.2d",  target: "3.5d",  variance: "+0.3d",  meeting: true,  trend: "down" },
  { name: "SLA Compliance",            current: "94.3%", target: "95%",   variance: "-0.7%",  meeting: false, trend: "up"   },
  { name: "Vulnerability Closure Rate",current: "82%",   target: "80%",   variance: "+2%",    meeting: true,  trend: "up"   },
  { name: "Critical Patch Coverage",   current: "91%",   target: "95%",   variance: "-4%",    meeting: false, trend: "up"   },
  { name: "False Positive Rate",       current: "7.3%",  target: "10%",   variance: "+2.7%",  meeting: true,  trend: "down" },
  { name: "Alert Fatigue Index",       current: "0.42",  target: "0.50",  variance: "+0.08",  meeting: true,  trend: "down" },
  { name: "Incident Recurrence Rate",  current: "11%",   target: "15%",   variance: "+4%",    meeting: true,  trend: "down" },
  { name: "Security Training Coverage",current: "88%",   target: "90%",   variance: "-2%",    meeting: false, trend: "up"   },
];

const CATEGORIES = [
  { name: "Vulnerability Management", score: 81, color: "bg-blue-500",   text: "text-blue-400"   },
  { name: "Incident Response",        score: 74, color: "bg-amber-500",  text: "text-amber-400"  },
  { name: "Compliance",               score: 91, color: "bg-green-500",  text: "text-green-400"  },
  { name: "Access Control",           score: 86, color: "bg-purple-500", text: "text-purple-400" },
];

const THRESHOLDS = [
  { name: "MTTD Alert",         condition: "MTTD > 6h",       status: "active",    detail: "Triggers PagerDuty P2 alert" },
  { name: "SLA Breach Warning", condition: "SLA Compliance < 90%", status: "active", detail: "Notifies security leadership" },
  { name: "Critical Vuln Spike",condition: "Critical vulns > 50",  status: "triggered", detail: "Emergency response protocol" },
  { name: "Score Degradation",  condition: "Security Score < 70",   status: "active", detail: "Initiates posture review" },
];

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
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch("/security-metrics/metrics?org_id=default"),
      apiFetch("/security-metrics/stats?org_id=default"),
    ]).then(([metricsResult, statsResult]) => {
      const metrics = metricsResult.status === "fulfilled" ? metricsResult.value : null;
      const stats   = statsResult.status   === "fulfilled" ? statsResult.value   : null;
      if (metrics || stats) setLiveData({ metrics, stats });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveMttd        = liveData?.stats?.mttd          ?? "4.2h";
  const liveMttr        = liveData?.stats?.mttr          ?? "6.8h";
  const liveScore       = liveData?.stats?.security_score ?? "78/100";
  const liveSla         = liveData?.stats?.sla_compliance ?? "94.3%";
  const liveTopMetrics: typeof TOP_METRICS =
    Array.isArray(liveData?.metrics)
      ? liveData.metrics.map((m: any) => ({
          name:    m.name    ?? m.metric_name ?? m.title,
          current: String(m.current ?? m.value ?? m.current_value ?? "—"),
          target:  String(m.target  ?? m.target_value ?? "—"),
          variance:String(m.variance ?? "—"),
          meeting: Boolean(m.meeting ?? m.on_target ?? false),
          trend:   m.trend  ?? "up",
        }))
      : TOP_METRICS;

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
        <KpiCard title="MTTD" value={liveMttd} icon={Clock} trend="down" className="border-blue-500/20" />
        <KpiCard title="MTTR" value={liveMttr} icon={Activity} trend="down" className="border-green-500/20" />
        <KpiCard title="Security Score" value={liveScore} icon={Shield} trend="up" className="border-purple-500/20" />
        <KpiCard title="SLA Compliance" value={liveSla} icon={CheckCircle2} trend="up" className="border-amber-500/20" />
      </div>

      {/* MTTD/MTTR 12-month trend chart */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-blue-400" />
            MTTD / MTTR — 12-Month Trend
          </CardTitle>
          <CardDescription className="text-xs">Hours — lower is better</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-2 h-40">
            {TREND_DATA.map((m) => (
              <div key={m.month} className="flex-1 flex flex-col items-center gap-0.5">
                <div className="w-full flex items-end gap-0.5 h-32">
                  <div
                    className="flex-1 rounded-t bg-blue-500/70 transition-all"
                    style={{ height: `${(m.mttd / TREND_MAX) * 100}%` }}
                    title={`MTTD: ${m.mttd}h`}
                  />
                  <div
                    className="flex-1 rounded-t bg-green-500/70 transition-all"
                    style={{ height: `${(m.mttr / TREND_MAX) * 100}%` }}
                    title={`MTTR: ${m.mttr}h`}
                  />
                </div>
                <span className="text-[9px] text-muted-foreground">{m.month}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 mt-3 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm bg-blue-500/70 inline-block" />MTTD
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-sm bg-green-500/70 inline-block" />MTTR
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Top 10 metrics table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Target className="h-4 w-4 text-indigo-400" />
            Top 10 Security Metrics
          </CardTitle>
          <CardDescription className="text-xs">Current vs. target with variance and trend direction</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
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
                {liveTopMetrics.map((row) => (
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
        </CardContent>
      </Card>

      {/* Category breakdown + alert thresholds */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Category breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-purple-400" />
              Category Scores
            </CardTitle>
            <CardDescription className="text-xs">Security posture score by domain (0–100)</CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            {CATEGORIES.map((cat) => (
              <div key={cat.name} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className={cn("font-semibold", cat.text)}>{cat.name}</span>
                  <span className="font-bold tabular-nums">{cat.score}/100</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${cat.score}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", cat.color)}
                  />
                </div>
              </div>
            ))}
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
            {THRESHOLDS.map((t) => (
              <div
                key={t.name}
                className={cn(
                  "flex items-start gap-3 rounded-lg border p-3",
                  t.status === "triggered"
                    ? "border-red-500/30 bg-red-500/5"
                    : "border-border bg-muted/10"
                )}
              >
                <div className={cn(
                  "mt-0.5 h-2 w-2 rounded-full flex-shrink-0",
                  t.status === "triggered" ? "bg-red-500 animate-pulse" : "bg-green-500"
                )} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold">{t.name}</span>
                    <Badge className={cn(
                      "text-[10px] border flex-shrink-0",
                      t.status === "triggered"
                        ? "border-red-500/30 text-red-400 bg-red-500/10"
                        : "border-green-500/30 text-green-400 bg-green-500/10"
                    )}>
                      {t.status}
                    </Badge>
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-0.5 font-mono">{t.condition}</p>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{t.detail}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
