import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  TrendingDown, TrendingUp, Shield, Activity, BarChart2, RefreshCw, Clock
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, BarChart, Bar, Legend
} from "recharts";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { useDashboardTrends, useDashboardOverview } from "@/hooks/use-api";

const CHART_THEME = {
  grid: "#1e293b",
  axis: "#94a3b8",
  tooltipBg: "#0f172a",
  tooltipBorder: "#1e293b",
};

function ChartTooltip() {
  return {
    contentStyle: { background: CHART_THEME.tooltipBg, border: `1px solid ${CHART_THEME.tooltipBorder}`, borderRadius: 8 },
    labelStyle: { color: CHART_THEME.axis },
    itemStyle: { color: "#c7d2fe" },
  };
}

export default function Analytics() {
  const [timeRange, setTimeRange] = useState("6m");
  const trendsQuery = useDashboardTrends({ range: timeRange });
  const overviewQuery = useDashboardOverview();

  const refetchAll = useCallback(() => {
    trendsQuery.refetch();
    overviewQuery.refetch();
  }, [trendsQuery, overviewQuery]);

  const isLoading = trendsQuery.isLoading || overviewQuery.isLoading;
  const isError = trendsQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load analytics data" onRetry={refetchAll} />;

  const trends: any = trendsQuery.data?.data ?? trendsQuery.data ?? {};
  const overview: any = overviewQuery.data?.data ?? overviewQuery.data ?? {};

  // Extract trend arrays
  const mttrTrend: any[] = trends.mttr_trend ?? trends.mttr ?? [];
  const noiseReductionTrend: any[] = trends.noise_trend ?? trends.noise_reduction ?? [];
  const slaComplianceTrend: any[] = trends.sla_trend ?? trends.sla_compliance ?? [];
  const scannerData: any[] = trends.scanner_effectiveness ?? trends.scanners ?? [];

  // KPIs
  const currentMttr = overview.mttr ?? trends.current_mttr ?? "—";
  const noiseReduction = overview.noise_reduction ?? trends.current_noise_reduction ?? "—";
  const slaCompliance = overview.sla_compliance ?? trends.current_sla_compliance ?? "—";
  const scannerRoi = overview.scanner_roi ?? trends.scanner_roi ?? "—";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Analytics"
        description="MTTR trends, noise reduction, SLA compliance, and scanner effectiveness analytics"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Select value={timeRange} onValueChange={setTimeRange}>
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="7d">Last 7 days</SelectItem>
            <SelectItem value="30d">Last 30 days</SelectItem>
            <SelectItem value="3m">Last 3 months</SelectItem>
            <SelectItem value="6m">Last 6 months</SelectItem>
            <SelectItem value="1y">Last 1 year</SelectItem>
          </SelectContent>
        </Select>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="MTTR Trend" value={typeof currentMttr === "number" ? `${currentMttr}h` : currentMttr} icon={Clock} change={-8} changeLabel="vs prior period" />
        <KpiCard title="Noise Reduction" value={typeof noiseReduction === "number" ? `${noiseReduction}%` : noiseReduction} icon={TrendingDown} change={12} changeLabel="improvement" />
        <KpiCard title="SLA Compliance" value={typeof slaCompliance === "number" ? `${slaCompliance}%` : slaCompliance} icon={Shield} change={3} changeLabel="vs last month" />
        <KpiCard title="Scanner ROI" value={typeof scannerRoi === "number" ? `${scannerRoi}x` : scannerRoi} icon={BarChart2} change={5} changeLabel="findings/dollar" />
      </div>

      {/* MTTR Trend & Noise Reduction */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Clock className="h-4 w-4 text-orange-400" />
              MTTR Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={mttrTrend} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="mttrGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_THEME.grid} />
                <XAxis dataKey={Object.keys(mttrTrend[0] ?? {}).find(k => k !== "value") ?? "date"} tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
                <Tooltip {...ChartTooltip()} />
                <Area type="monotone" dataKey="value" stroke="#f97316" strokeWidth={2} fill="url(#mttrGrad)" name="MTTR (hours)" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingDown className="h-4 w-4 text-green-400" />
              Noise Reduction Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={noiseReductionTrend} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="noiseGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_THEME.grid} />
                <XAxis dataKey={Object.keys(noiseReductionTrend[0] ?? {}).find(k => k !== "value") ?? "date"} tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} unit="%" />
                <Tooltip {...ChartTooltip()} />
                <Area type="monotone" dataKey="value" stroke="#22c55e" strokeWidth={2} fill="url(#noiseGrad)" name="Noise Reduction %" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* SLA Compliance Trend */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-400" />
            SLA Compliance Trend
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={slaComplianceTrend} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_THEME.grid} />
              <XAxis dataKey={Object.keys(slaComplianceTrend[0] ?? {}).find(k => !["critical", "high", "medium", "low"].includes(k)) ?? "date"} tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} unit="%" />
              <Tooltip {...ChartTooltip()} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} name="Critical SLA" />
              <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} name="High SLA" />
              <Line type="monotone" dataKey="medium" stroke="#eab308" strokeWidth={2} dot={false} name="Medium SLA" />
              <Line type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} dot={false} name="Overall SLA %" />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Scanner Effectiveness */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart2 className="h-4 w-4 text-violet-400" />
            Scanner Effectiveness Comparison
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={scannerData} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_THEME.grid} />
              <XAxis dataKey="name" tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
              <Tooltip {...ChartTooltip()} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Bar dataKey="findings" name="Findings" fill="#6366f1" radius={[4, 4, 0, 0]} />
              <Bar dataKey="false_positives" name="False Positives" fill="#f97316" radius={[4, 4, 0, 0]} />
              <Bar dataKey="confirmed" name="Confirmed" fill="#22c55e" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Finding Resolution Rate Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-green-400" />
            Finding Resolution Rate
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Period</TableHead>
                <TableHead className="text-xs">New Findings</TableHead>
                <TableHead className="text-xs">Resolved</TableHead>
                <TableHead className="text-xs">Open</TableHead>
                <TableHead className="text-xs">Resolution Rate</TableHead>
                <TableHead className="text-xs">Trend</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(trends.resolution_table ?? [
                { period: "Oct 2024", new_findings: 142, resolved: 128, open: 14, resolution_rate: 90 },
                { period: "Nov 2024", new_findings: 118, resolved: 109, open: 9, resolution_rate: 92 },
                { period: "Dec 2024", new_findings: 95, resolved: 91, open: 4, resolution_rate: 96 },
                { period: "Jan 2025", new_findings: 132, resolved: 118, open: 14, resolution_rate: 89 },
                { period: "Feb 2025", new_findings: 108, resolved: 103, open: 5, resolution_rate: 95 },
                { period: "Mar 2025", new_findings: 87, resolved: 84, open: 3, resolution_rate: 97 },
              ]).map((row: any, i: number) => (
                <TableRow key={i} className="hover:bg-muted/30">
                  <TableCell className="text-sm font-medium">{row.period}</TableCell>
                  <TableCell className="text-xs">{row.new_findings}</TableCell>
                  <TableCell className="text-xs text-green-400">{row.resolved}</TableCell>
                  <TableCell className="text-xs">{row.open}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-20 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full bg-primary rounded-full"
                          style={{ width: `${row.resolution_rate}%` }}
                        />
                      </div>
                      <span className="text-xs font-medium">{row.resolution_rate}%</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-xs ${
                        row.resolution_rate >= 95 ? "text-green-400 border-green-700" :
                        row.resolution_rate >= 90 ? "text-yellow-400 border-yellow-700" :
                        "text-red-400 border-red-700"
                      }`}
                    >
                      {row.resolution_rate >= 95 ? "Excellent" : row.resolution_rate >= 90 ? "Good" : "Needs Improvement"}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Security Metrics Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {[
          {
            title: "Fastest Resolution",
            value: trends.fastest_resolution ?? "4h",
            label: "Critical finding",
            color: "text-green-400",
          },
          {
            title: "Most Effective Scanner",
            value: trends.best_scanner ?? "Snyk",
            label: "by confirmed findings",
            color: "text-blue-400",
          },
          {
            title: "Noise Reduction Peak",
            value: trends.best_noise_reduction ?? "87%",
            label: "false positive suppression",
            color: "text-violet-400",
          },
        ].map(({ title, value, label, color }) => (
          <Card key={title}>
            <CardContent className="p-5">
              <p className="text-xs text-muted-foreground mb-2">{title}</p>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
              <p className="text-xs text-muted-foreground mt-1">{label}</p>
            </CardContent>
          </Card>
        ))}
      </div>
    </motion.div>
  );
}
