import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  TrendingDown, TrendingUp, Shield, Activity, BarChart2, RefreshCw, Clock,
  Download, DollarSign, Cpu, Target
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, BarChart, Bar, Legend
} from "recharts";
import { useDashboardTrends, useDashboardOverview, useComplianceOverallStatus } from "@/hooks/use-api";

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

// Heatmap cell colors by utilization level
function heatColor(value: number) {
  if (value >= 90) return "#22c55e";
  if (value >= 70) return "#84cc16";
  if (value >= 50) return "#eab308";
  if (value >= 30) return "#f97316";
  return "#ef4444";
}

// Fallback data — Replace with real scanner cost/ROI metrics when available
const SCANNER_ROI_DATA = [
  { name: "Snyk", roi: 4.2, cost: 1200, findings: 87, confirmed: 72 },
  { name: "Semgrep", roi: 3.8, cost: 800, findings: 63, confirmed: 51 },
  { name: "Trivy", roi: 5.1, cost: 400, findings: 44, confirmed: 39 },
  { name: "Bandit", roi: 6.3, cost: 200, findings: 31, confirmed: 28 },
  { name: "SonarQube", roi: 3.1, cost: 2100, findings: 119, confirmed: 88 },
];

// Fallback data — Replace with real utilization metrics when available
const HEATMAP_DATA = [
  { scanner: "Snyk", mon: 78, tue: 92, wed: 85, thu: 71, fri: 66, sat: 12, sun: 8 },
  { scanner: "Semgrep", mon: 65, tue: 70, wed: 88, thu: 91, fri: 74, sat: 20, sun: 5 },
  { scanner: "Trivy", mon: 90, tue: 87, wed: 93, thu: 88, fri: 82, sat: 45, sun: 22 },
  { scanner: "Bandit", mon: 55, tue: 61, wed: 58, thu: 72, fri: 68, sat: 15, sun: 10 },
  { scanner: "SonarQube", mon: 82, tue: 79, wed: 84, thu: 80, fri: 77, sat: 30, sun: 18 },
];

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

export default function Analytics() {
  const [timeRange, setTimeRange] = useState("6m");
  const trendsQuery = useDashboardTrends({ range: timeRange });
  const overviewQuery = useDashboardOverview();
  const complianceQuery = useComplianceOverallStatus();

  const refetchAll = useCallback(() => {
    trendsQuery.refetch();
    overviewQuery.refetch();
    complianceQuery.refetch();
  }, [trendsQuery, overviewQuery, complianceQuery]);

  const isLoading = trendsQuery.isLoading || overviewQuery.isLoading;
  const isError = trendsQuery.isError && complianceQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load analytics data" onRetry={refetchAll} />;

  const trends: any = trendsQuery.data?.data ?? trendsQuery.data ?? {};
  const overview: any = overviewQuery.data?.data ?? overviewQuery.data ?? {};
  const complianceStatus: any = complianceQuery.data?.data ?? complianceQuery.data ?? {};

  // Extract trend arrays
  const mttrTrend: any[] = trends.mttr_trend ?? trends.mttr ?? [];
  const noiseReductionTrend: any[] = trends.noise_trend ?? trends.noise_reduction ?? [];
  const slaComplianceTrend: any[] = trends.sla_trend ?? trends.sla_compliance ?? [];
  const scannerData: any[] = trends.scanner_effectiveness ?? trends.scanners ?? [];
  const costPerFixTrend: any[] = trends.cost_per_fix ?? [];

  // KPIs — prefer live compliance status, then overview, then trends, then fallback
  const currentMttr = complianceStatus.mttr ?? overview.mttr ?? trends.current_mttr ?? "—";
  const noiseReduction = complianceStatus.noise_reduction ?? overview.noise_reduction ?? trends.current_noise_reduction ?? "—";
  const slaCompliance = complianceStatus.sla_compliance ?? complianceStatus.overall_compliance ?? overview.sla_compliance ?? trends.current_sla_compliance ?? "—";
  const scannerRoi = complianceStatus.scanner_roi ?? overview.scanner_roi ?? trends.scanner_roi ?? "—";

  const handleExportCSV = () => {
    const rows = [
      ["Metric", "Value", "Period"],
      ["MTTR", currentMttr, timeRange],
      ["Noise Reduction", noiseReduction, timeRange],
      ["SLA Compliance", slaCompliance, timeRange],
      ["Scanner ROI", scannerRoi, timeRange],
    ];
    const csv = rows.map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `analytics-export-${timeRange}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

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
            <Button variant="outline" size="sm" onClick={handleExportCSV} className="gap-2">
              <Download className="h-4 w-4" />
              Export CSV
            </Button>
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
        <KpiCard title="MTTR Trend" value={typeof currentMttr === "number" ? `${currentMttr}h` : currentMttr} icon={Clock} />
        <KpiCard title="Noise Reduction" value={typeof noiseReduction === "number" ? `${noiseReduction}%` : noiseReduction} icon={TrendingDown} />
        <KpiCard title="SLA Compliance" value={typeof slaCompliance === "number" ? `${slaCompliance}%` : slaCompliance} icon={Shield} />
        <KpiCard title="Scanner ROI" value={typeof scannerRoi === "number" ? `${scannerRoi}x` : scannerRoi} icon={BarChart2} />
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

      {/* Scanner ROI Comparison */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <DollarSign className="h-4 w-4 text-green-400" />
              Scanner ROI Comparison
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={trends.scanner_roi_data ?? SCANNER_ROI_DATA} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART_THEME.grid} />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
                  <Tooltip {...ChartTooltip()} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="roi" name="ROI Multiplier" fill="#6366f1" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="confirmed" name="Confirmed Findings" fill="#22c55e" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
              <div className="space-y-2">
                {(trends.scanner_roi_data ?? SCANNER_ROI_DATA).map((s: any) => (
                  <div key={s.name} className="flex items-center gap-3 p-2.5 rounded-lg bg-muted/30 border border-border/40">
                    <span className="text-sm font-medium w-24">{s.name}</span>
                    <div className="flex-1">
                      <div className="flex justify-between text-xs text-muted-foreground mb-1">
                        <span>ROI</span>
                        <span className="font-medium text-foreground">{s.roi}x</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                        <div className="h-full bg-violet-500 rounded-full" style={{ width: `${Math.min((s.roi / 7) * 100, 100)}%` }} />
                      </div>
                    </div>
                    <Badge variant="outline" className="text-xs shrink-0">${s.cost}/mo</Badge>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Cost-Per-Fix Trend */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-4 w-4 text-blue-400" />
              Cost-Per-Fix Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart
                data={costPerFixTrend.length > 0 ? costPerFixTrend : [
                  { date: "Oct", critical: 420, high: 180, medium: 65 },
                  { date: "Nov", critical: 390, high: 165, medium: 58 },
                  { date: "Dec", critical: 350, high: 148, medium: 52 },
                  { date: "Jan", critical: 310, high: 135, medium: 47 },
                  { date: "Feb", critical: 275, high: 122, medium: 41 },
                  { date: "Mar", critical: 240, high: 108, medium: 36 },
                ]}
                margin={{ top: 8, right: 16, left: 0, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_THEME.grid} />
                <XAxis dataKey="date" tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: CHART_THEME.axis }} axisLine={false} tickLine={false} unit="$" />
                <Tooltip {...ChartTooltip()} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} fill="url(#critGrad)" name="Critical $/fix" />
                <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={2} dot={false} name="High $/fix" />
                <Line type="monotone" dataKey="medium" stroke="#3b82f6" strokeWidth={2} dot={false} name="Medium $/fix" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </motion.div>

      {/* Tool Utilization Heatmap */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Cpu className="h-4 w-4 text-orange-400" />
              Tool Utilization Heatmap (% active scan time)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <th className="text-left text-muted-foreground font-medium pb-3 w-28">Scanner</th>
                    {DAYS.map((d) => (
                      <th key={d} className="text-center text-muted-foreground font-medium pb-3 w-12">{d}</th>
                    ))}
                    <th className="text-center text-muted-foreground font-medium pb-3 w-16">Avg</th>
                  </tr>
                </thead>
                <tbody className="space-y-1">
                  {(trends.utilization_heatmap ?? HEATMAP_DATA).map((row: any) => {
                    const vals = [row.mon, row.tue, row.wed, row.thu, row.fri, row.sat, row.sun];
                    const avg = Math.round(vals.reduce((a: number, b: number) => a + b, 0) / vals.length);
                    return (
                      <tr key={row.scanner}>
                        <td className="py-1.5 text-muted-foreground font-medium pr-4">{row.scanner}</td>
                        {vals.map((v: number, i: number) => (
                          <td key={i} className="py-1.5 text-center">
                            <div
                              className="mx-auto h-8 w-10 rounded flex items-center justify-center text-xs font-bold text-black"
                              style={{ background: heatColor(v), opacity: 0.85 }}
                            >
                              {v}%
                            </div>
                          </td>
                        ))}
                        <td className="py-1.5 text-center">
                          <Badge
                            variant="outline"
                            className="text-xs font-mono"
                            style={{ color: heatColor(avg), borderColor: `${heatColor(avg)}50` }}
                          >
                            {avg}%
                          </Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              <div className="flex items-center gap-3 mt-4 text-xs text-muted-foreground">
                <span>Utilization:</span>
                {[["< 30%", "#ef4444"], ["30–50%", "#f97316"], ["50–70%", "#eab308"], ["70–90%", "#84cc16"], ["> 90%", "#22c55e"]].map(([label, color]) => (
                  <div key={label} className="flex items-center gap-1">
                    <div className="h-3 w-3 rounded" style={{ background: color }} />
                    <span>{label}</span>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Finding Resolution Rate Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-green-400" />
            Finding Resolution Rate
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
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
          </div>
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
