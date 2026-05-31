/**
 * Comply / Analytics
 *
 * Data sources (real API):
 *   - /api/v1/analytics-engine/summary  → KPIs (grade, scores, counts)
 *   - /api/v1/analytics/* via useDashboardTrends / useDashboardOverview / useComplianceOverallStatus
 *
 * SCANNER_ROI_DATA and HEATMAP_DATA removed.
 * Charts render from real trend arrays; honest EmptyState when empty.
 * NO hardcoded fallback arrays.
 */

import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { EmptyState } from "@/components/shared/EmptyState";
import { motion } from "framer-motion";
import {
  TrendingDown, TrendingUp, Shield, Activity, BarChart2, RefreshCw, Clock,
  Download, DollarSign, Cpu, Target,
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, BarChart, Bar, Legend,
} from "recharts";
import { useDashboardTrends, useDashboardOverview, useComplianceOverallStatus } from "@/hooks/use-api";
import api, { buildApiUrl, getStoredAuthToken, getStoredAuthStrategy, getStoredOrgId } from "@/lib/api";

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

interface AnalyticsSummary {
  org_id: string;
  current_score: number | null;
  grade: string;
  total_risks: number;
  critical_risks: number;
  open_cases: number;
  total_findings: number;
  critical_findings: number;
  generated_at: string;
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

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

function heatColor(value: number) {
  if (value >= 90) return "#22c55e";
  if (value >= 70) return "#84cc16";
  if (value >= 50) return "#eab308";
  if (value >= 30) return "#f97316";
  return "#ef4444";
}

function apiHeaders(): Record<string, string> {
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const h: Record<string, string> = { "Content-Type": "application/json", "X-Org-ID": orgId };
  if (token) {
    if (strategy === "jwt") h.Authorization = token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
    else h["X-API-Key"] = token;
  }
  return h;
}

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

// ─────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────

export default function Analytics() {
  const orgId = getStoredOrgId();
  const [timeRange, setTimeRange] = useState("6m");

  const trendsQuery = useDashboardTrends({ range: timeRange });
  const overviewQuery = useDashboardOverview();
  const complianceQuery = useComplianceOverallStatus();

  // analytics-engine/summary — real KPIs
  const summaryQuery = useQuery<AnalyticsSummary>({
    queryKey: ["analytics-engine-summary", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/analytics-engine/summary", { org_id: orgId });
      const res = await api.get<AnalyticsSummary>(url);
      return res.data;
    },
    staleTime: 60_000,
  });

  const refetchAll = useCallback(() => {
    trendsQuery.refetch();
    overviewQuery.refetch();
    complianceQuery.refetch();
    summaryQuery.refetch();
  }, [trendsQuery, overviewQuery, complianceQuery, summaryQuery]);

  const isLoading = trendsQuery.isLoading || overviewQuery.isLoading || summaryQuery.isLoading;
  const isError = trendsQuery.isError && complianceQuery.isError && summaryQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load analytics data" onRetry={refetchAll} />;

  const trends: Record<string, unknown> = (trendsQuery.data as Record<string, unknown> | null)?.data as Record<string, unknown>
    ?? trendsQuery.data as Record<string, unknown>
    ?? {};
  const overview: Record<string, unknown> = (overviewQuery.data as Record<string, unknown> | null)?.data as Record<string, unknown>
    ?? overviewQuery.data as Record<string, unknown>
    ?? {};
  const complianceStatus: Record<string, unknown> = (complianceQuery.data as Record<string, unknown> | null)?.data as Record<string, unknown>
    ?? complianceQuery.data as Record<string, unknown>
    ?? {};
  const summary = summaryQuery.data;

  // Real KPIs — prefer analytics-engine/summary, then trend hooks
  const currentMttr = (complianceStatus.mttr ?? overview.mttr ?? (trends as Record<string, unknown>).current_mttr ?? summary?.open_cases ?? "—") as string | number;
  const noiseReduction = (complianceStatus.noise_reduction ?? overview.noise_reduction ?? (trends as Record<string, unknown>).current_noise_reduction ?? "—") as string | number;
  const slaCompliance = (complianceStatus.sla_compliance ?? complianceStatus.overall_compliance ?? overview.sla_compliance ?? (trends as Record<string, unknown>).current_sla_compliance ?? "—") as string | number;
  const scannerRoi = (complianceStatus.scanner_roi ?? overview.scanner_roi ?? (trends as Record<string, unknown>).scanner_roi ?? "—") as string | number;

  // Real trend arrays from API
  const mttrTrend = ((trends as Record<string, unknown>).mttr_trend ?? (trends as Record<string, unknown>).mttr ?? []) as Record<string, unknown>[];
  const noiseReductionTrend = ((trends as Record<string, unknown>).noise_trend ?? (trends as Record<string, unknown>).noise_reduction ?? []) as Record<string, unknown>[];
  const slaComplianceTrend = ((trends as Record<string, unknown>).sla_trend ?? (trends as Record<string, unknown>).sla_compliance ?? []) as Record<string, unknown>[];
  const scannerData = ((trends as Record<string, unknown>).scanner_effectiveness ?? (trends as Record<string, unknown>).scanners ?? []) as Record<string, unknown>[];
  const costPerFixTrend = ((trends as Record<string, unknown>).cost_per_fix ?? []) as Record<string, unknown>[];
  const scannerRoiData = ((trends as Record<string, unknown>).scanner_roi_data ?? []) as Record<string, unknown>[];
  const utilizationHeatmap = ((trends as Record<string, unknown>).utilization_heatmap ?? []) as Record<string, unknown>[];
  const resolutionTable = ((trends as Record<string, unknown>).resolution_table ?? []) as Record<string, unknown>[];

  const handleExportCSV = () => {
    const rows = [
      ["Metric", "Value", "Period"],
      ["MTTR", String(currentMttr), timeRange],
      ["Noise Reduction", String(noiseReduction), timeRange],
      ["SLA Compliance", String(slaCompliance), timeRange],
      ["Scanner ROI", String(scannerRoi), timeRange],
      ["Open Cases", String(summary?.open_cases ?? "—"), timeRange],
      ["Total Findings", String(summary?.total_findings ?? "—"), timeRange],
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
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="space-y-6">
      <PageHeader
        title="Analytics"
        description="MTTR trends, noise reduction, SLA compliance, and scanner effectiveness analytics"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleExportCSV} className="gap-2"><Download className="h-4 w-4" />Export CSV</Button>
            <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2"><RefreshCw className="h-4 w-4" />Refresh</Button>
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-32"><SelectValue /></SelectTrigger>
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

      {/* KPIs — from analytics-engine/summary */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Open Cases" value={summary?.open_cases ?? "—"} icon={Activity} />
        <KpiCard title="Total Findings" value={summary?.total_findings ?? "—"} icon={BarChart2} />
        <KpiCard title="Critical Findings" value={summary?.critical_findings ?? "—"} icon={Shield} />
        <KpiCard title="Grade" value={summary?.grade ?? "—"} icon={Target} />
      </div>

      {/* Secondary KPIs from trend hooks */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="MTTR" value={typeof currentMttr === "number" ? `${currentMttr}h` : currentMttr} icon={Clock} />
        <KpiCard title="Noise Reduction" value={typeof noiseReduction === "number" ? `${noiseReduction}%` : noiseReduction} icon={TrendingDown} />
        <KpiCard title="SLA Compliance" value={typeof slaCompliance === "number" ? `${slaCompliance}%` : slaCompliance} icon={Shield} />
        <KpiCard title="Scanner ROI" value={typeof scannerRoi === "number" ? `${scannerRoi}x` : scannerRoi} icon={BarChart2} />
      </div>

      {/* MTTR Trend & Noise Reduction */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><Clock className="h-4 w-4 text-orange-400" />MTTR Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {mttrTrend.length === 0 ? (
              <EmptyState icon={Clock} title="No MTTR trend data" description="MTTR trend data will appear here once available from the analytics engine." />
            ) : (
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
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><TrendingDown className="h-4 w-4 text-green-400" />Noise Reduction Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {noiseReductionTrend.length === 0 ? (
              <EmptyState icon={TrendingDown} title="No noise reduction data" description="Noise reduction trend data will appear here once available." />
            ) : (
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
            )}
          </CardContent>
        </Card>
      </div>

      {/* SLA Compliance Trend */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><Shield className="h-4 w-4 text-blue-400" />SLA Compliance Trend</CardTitle>
        </CardHeader>
        <CardContent>
          {slaComplianceTrend.length === 0 ? (
            <EmptyState icon={Shield} title="No SLA compliance trend data" description="SLA compliance trend data will appear here once available." />
          ) : (
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
          )}
        </CardContent>
      </Card>

      {/* Scanner Effectiveness */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><BarChart2 className="h-4 w-4 text-violet-400" />Scanner Effectiveness Comparison</CardTitle>
        </CardHeader>
        <CardContent>
          {scannerData.length === 0 ? (
            <EmptyState icon={BarChart2} title="No scanner effectiveness data" description="Scanner effectiveness data will appear here once scanners have run." />
          ) : (
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
          )}
        </CardContent>
      </Card>

      {/* Scanner ROI Comparison */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><DollarSign className="h-4 w-4 text-green-400" />Scanner ROI Comparison</CardTitle>
          </CardHeader>
          <CardContent>
            {scannerRoiData.length === 0 ? (
              <EmptyState icon={DollarSign} title="No scanner ROI data" description="Scanner ROI data will appear here once cost and findings metrics are collected." />
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={scannerRoiData} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
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
                  {scannerRoiData.map((s) => (
                    <div key={String(s.name)} className="flex items-center gap-3 p-2.5 rounded-lg bg-muted/30 border border-border/40">
                      <span className="text-sm font-medium w-24">{String(s.name)}</span>
                      <div className="flex-1">
                        <div className="flex justify-between text-xs text-muted-foreground mb-1">
                          <span>ROI</span>
                          <span className="font-medium text-foreground">{Number(s.roi ?? 0).toFixed(1)}x</span>
                        </div>
                        <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                          <div className="h-full bg-violet-500 rounded-full" style={{ width: `${Math.min((Number(s.roi ?? 0) / 7) * 100, 100)}%` }} />
                        </div>
                      </div>
                      {s.cost !== undefined && <Badge variant="outline" className="text-xs shrink-0">${Number(s.cost)}/mo</Badge>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Cost-Per-Fix Trend */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><Target className="h-4 w-4 text-blue-400" />Cost-Per-Fix Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {costPerFixTrend.length === 0 ? (
              <EmptyState icon={Target} title="No cost-per-fix data" description="Cost-per-fix trend data will appear here once remediation cost metrics are collected." />
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={costPerFixTrend} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
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
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Tool Utilization Heatmap */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2"><Cpu className="h-4 w-4 text-orange-400" />Tool Utilization Heatmap (% active scan time)</CardTitle>
          </CardHeader>
          <CardContent>
            {utilizationHeatmap.length === 0 ? (
              <EmptyState icon={Cpu} title="No utilization data" description="Scanner utilization heatmap will appear here once scan timing data is collected." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr>
                      <th className="text-left text-muted-foreground font-medium pb-3 w-28">Scanner</th>
                      {DAYS.map((d) => (<th key={d} className="text-center text-muted-foreground font-medium pb-3 w-12">{d}</th>))}
                      <th className="text-center text-muted-foreground font-medium pb-3 w-16">Avg</th>
                    </tr>
                  </thead>
                  <tbody>
                    {utilizationHeatmap.map((row) => {
                      const vals = [row.mon, row.tue, row.wed, row.thu, row.fri, row.sat, row.sun].map(Number);
                      const avg = Math.round(vals.reduce((a, b) => a + b, 0) / vals.length);
                      return (
                        <tr key={String(row.scanner)}>
                          <td className="py-1.5 text-muted-foreground font-medium pr-4">{String(row.scanner)}</td>
                          {vals.map((v, i) => (
                            <td key={i} className="py-1.5 text-center">
                              <div className="mx-auto h-8 w-10 rounded flex items-center justify-center text-xs font-bold text-black" style={{ background: heatColor(v), opacity: 0.85 }}>{v}%</div>
                            </td>
                          ))}
                          <td className="py-1.5 text-center">
                            <Badge variant="outline" className="text-xs font-mono" style={{ color: heatColor(avg), borderColor: `${heatColor(avg)}50` }}>{avg}%</Badge>
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
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Finding Resolution Rate Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><TrendingUp className="h-4 w-4 text-green-400" />Finding Resolution Rate</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {resolutionTable.length === 0 ? (
            <div className="p-6">
              <EmptyState icon={TrendingUp} title="No resolution data" description="Finding resolution rate data will appear here once findings are closed over time." />
            </div>
          ) : (
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
                  {resolutionTable.map((row, i) => {
                    const rate = Number(row.resolution_rate ?? 0);
                    return (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="text-sm font-medium">{String(row.period ?? "—")}</TableCell>
                        <TableCell className="text-xs">{String(row.new_findings ?? "—")}</TableCell>
                        <TableCell className="text-xs text-green-400">{String(row.resolved ?? "—")}</TableCell>
                        <TableCell className="text-xs">{String(row.open ?? "—")}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <div className="h-1.5 w-20 rounded-full bg-muted overflow-hidden">
                              <div className="h-full bg-primary rounded-full" style={{ width: `${rate}%` }} />
                            </div>
                            <span className="text-xs font-medium">{rate}%</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={`text-xs ${rate >= 95 ? "text-green-400 border-green-700" : rate >= 90 ? "text-yellow-400 border-yellow-700" : "text-red-400 border-red-700"}`}>
                            {rate >= 95 ? "Excellent" : rate >= 90 ? "Good" : "Needs Improvement"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Summary cards from real summary endpoint */}
      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { title: "Security Grade", value: summary.grade, label: "Overall posture", color: summary.grade === "A" ? "text-green-400" : summary.grade === "B" ? "text-blue-400" : "text-amber-400" },
            { title: "Critical Risks", value: summary.critical_risks, label: "Active critical risks", color: summary.critical_risks > 0 ? "text-red-400" : "text-green-400" },
            { title: "Total Risks", value: summary.total_risks, label: "All categories", color: "text-violet-400" },
          ].map(({ title, value, label, color }) => (
            <Card key={title}>
              <CardContent className="p-5">
                <p className="text-xs text-muted-foreground mb-2">{title}</p>
                <p className={`text-2xl font-bold ${color}`}>{value ?? "—"}</p>
                <p className="text-xs text-muted-foreground mt-1">{label}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </motion.div>
  );
}
