import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell,
} from "recharts";
import {
  Shield, AlertTriangle, Activity, Clock, TrendingUp,
  TrendingDown, Zap, CheckCircle2, RefreshCw, Filter,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { DataTable } from "@/components/shared/data-table";
import {
  useDashboardOverview, useDashboardTopRisks,
  useDashboardTrends, useDashboardCompliance, useNervePulse,
} from "@/hooks/use-api";
import { cn } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

export default function CommandDashboard() {
  const [timeRange] = useState("30d");
  const overview = useDashboardOverview();
  const topRisks = useDashboardTopRisks();
  const trends = useDashboardTrends({ period: timeRange });
  const compliance = useDashboardCompliance();
  const pulse = useNervePulse();

  const isLoading = overview.isLoading || topRisks.isLoading;
  const isError = overview.isError && topRisks.isError;
  const refetch = useCallback(() => {
    overview.refetch();
    topRisks.refetch();
    trends.refetch();
    compliance.refetch();
    pulse.refetch();
  }, [overview, topRisks, trends, compliance, pulse]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState onRetry={refetch} />;

  const ov = overview.data ?? {};
  const pulseData = pulse.data ?? {};
  const trendData = trends.data ?? {};
  const compData = compliance.data ?? {};
  const risks = topRisks.data?.risks ?? [];

  // Build trend chart data from series
  const chartData = (trendData.series ?? []).map((s: Record<string, unknown>) => ({
    date: String(s.period ?? ""),
    critical: Number(s.critical ?? 0),
    high: Number(s.high ?? 0),
    medium: Number(s.medium ?? 0),
    low: Number(s.low ?? 0),
    total: Number(s.total ?? 0),
  }));

  // Severity breakdown for bar chart
  const sevTotals = trendData.severity_totals ?? {};
  const sevChart = Object.entries(sevTotals).map(([k, v]) => ({
    name: k.charAt(0).toUpperCase() + k.slice(1),
    count: Number(v),
    fill: SEVERITY_COLORS[k] ?? "#6b7280",
  }));

  const riskColumns = [
    { key: "title", header: "Finding", render: (r: Record<string, unknown>) => (
      <div className="max-w-xs">
        <p className="font-medium truncate">{String(r.title ?? "")}</p>
        <p className="text-xs text-muted-foreground">{String(r.source ?? "")} · {String(r.rule_id ?? "")}</p>
      </div>
    )},
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => (
      <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">
        {String(r.severity ?? "")}
      </Badge>
    )},
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => (
      <span className="font-mono text-sm">{Number(r.cvss_score ?? 0).toFixed(1)}</span>
    )},
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => (
      <Badge variant="outline" className="capitalize">{String(r.status ?? "")}</Badge>
    )},
    { key: "exploitable", header: "Exploitable", render: (r: Record<string, unknown>) => (
      r.exploitable ? <Zap className="h-4 w-4 text-red-400" /> : <CheckCircle2 className="h-4 w-4 text-green-400" />
    )},
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Command Dashboard"
        description="Real-time security posture overview and threat intelligence"
        badge="LIVE"
        actions={
          <Button variant="outline" size="sm" onClick={refetch}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard
          title="Total Findings"
          value={ov.total_findings ?? 0}
          icon={Shield}
          trend={ov.total_findings > 0 ? "up" : "flat"}
        />
        <KpiCard
          title="Critical Issues"
          value={ov.critical_findings ?? 0}
          icon={AlertTriangle}
          trend={(ov.critical_findings ?? 0) > 5 ? "up" : "down"}
          className={cn((ov.critical_findings ?? 0) > 0 && "border-red-500/30")}
        />
        <KpiCard
          title="Threat Pulse"
          value={`${Number(pulseData.score ?? 0).toFixed(1)} / 10`}
          icon={Activity}
          trend={Number(pulseData.score ?? 0) > 5 ? "up" : "down"}
        />
        <KpiCard
          title="Compliance Score"
          value={`${Number(compData.compliance_score ?? 0).toFixed(0)}%`}
          icon={CheckCircle2}
          trend={Number(compData.compliance_score ?? 0) > 50 ? "up" : "down"}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Trend Chart */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Finding Trends (30d)</CardTitle>
          </CardHeader>
          <CardContent>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <YAxis tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.3} />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.2} />
                  <Area type="monotone" dataKey="low" stackId="1" stroke="#22c55e" fill="#22c55e" fillOpacity={0.2} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">
                No trend data available yet. Run scans to populate.
              </div>
            )}
          </CardContent>
        </Card>

        {/* Severity Breakdown */}
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">By Severity</CardTitle>
          </CardHeader>
          <CardContent>
            {sevChart.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={sevChart} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis type="number" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" width={70} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {sevChart.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-[260px] text-muted-foreground text-sm">
                No severity data available.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Risks Table */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">
            Top Risks ({risks.length})
          </CardTitle>
          <Badge variant="outline">{ov.open_findings ?? 0} Open</Badge>
        </CardHeader>
        <CardContent>
          <DataTable columns={riskColumns} data={risks.slice(0, 15)} emptyMessage="No risks detected — run a scan to begin." />
        </CardContent>
      </Card>
    </div>
  );
}
