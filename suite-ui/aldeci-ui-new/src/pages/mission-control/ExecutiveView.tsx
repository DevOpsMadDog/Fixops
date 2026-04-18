import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, Cell, Legend,
} from "recharts";
import {
  TrendingUp, TrendingDown, DollarSign, Shield, CheckCircle2,
  AlertCircle, Download, Calendar, Award, BarChart3,
  Building2, Target, Layers, ArrowUpRight, ArrowDownRight,
  FileText, Clock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useDashboardOverview,
  useDashboardTrends,
  useComplianceStatus,
  useEvidenceBundles,
} from "@/hooks/use-api";
import { reportsApi } from "@/lib/api";
import { cn, formatCurrency } from "@/lib/utils";
import { toast } from "sonner";

const CHART_TOOLTIP_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 12,
};

const UNIT_COLORS = [
  "#3b82f6", "#8b5cf6", "#06b6d4", "#10b981", "#f59e0b",
  "#ef4444", "#ec4899", "#84cc16",
];

function ComplianceTile({ name, status, score }: { name: string; status: string; score?: number }) {
  const ok = status === "compliant" || status === "passing" || status === "active" || Number(score ?? 0) >= 90;
  const warn = status === "warning" || (Number(score ?? 100) >= 70 && Number(score ?? 100) < 90);
  return (
    <Card className={cn(
      "flex flex-col items-center gap-2 p-4 text-center transition-all",
      ok && "border-green-500/30 bg-green-500/5",
      warn && "border-yellow-500/30 bg-yellow-500/5",
      !ok && !warn && "border-red-500/30 bg-red-500/5"
    )}>
      {ok
        ? <CheckCircle2 className="h-6 w-6 text-green-400" />
        : warn
        ? <AlertCircle className="h-6 w-6 text-yellow-400" />
        : <AlertCircle className="h-6 w-6 text-red-400" />
      }
      <span className="text-sm font-bold tracking-wide">{name}</span>
      {score !== undefined && (
        <div className="w-full space-y-1">
          <Progress value={score} className="h-1.5" />
          <span className="text-xs text-muted-foreground">{score}%</span>
        </div>
      )}
      <Badge
        variant="outline"
        className={cn(
          "text-[10px] capitalize",
          ok && "border-green-500/30 text-green-400",
          warn && "border-yellow-500/30 text-yellow-400",
          !ok && !warn && "border-red-500/30 text-red-400",
        )}
      >
        {status}
      </Badge>
    </Card>
  );
}

function TrendArrow({ value }: { value: number }) {
  if (value > 0) return <ArrowUpRight className="h-4 w-4 text-green-400" />;
  if (value < 0) return <ArrowDownRight className="h-4 w-4 text-red-400" />;
  return null;
}

export default function ExecutiveView() {
  const [selectedQuarter, setSelectedQuarter] = useState("Q1-2026");
  const [selectedYear, setSelectedYear] = useState("2026");

  const overview = useDashboardOverview();
  const trends = useDashboardTrends({ period: "12m" });
  const complianceStatus = useComplianceStatus();
  const evidenceBundles = useEvidenceBundles({ status: "active" });

  const isLoading = overview.isLoading || trends.isLoading;
  const isError = overview.isError && trends.isError;
  const refetch = useCallback(() => {
    overview.refetch();
    trends.refetch();
    complianceStatus.refetch();
    evidenceBundles.refetch();
  }, [overview, trends, complianceStatus, evidenceBundles]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load executive data" onRetry={refetch} />;

  const ov = overview.data ?? {};
  const trendData = trends.data ?? {};
  const comp = complianceStatus.data ?? {};
  const bundles = evidenceBundles.data ?? {};

  // 12-month posture trend chart data
  const postureTrend = (trendData.monthly_posture ?? trendData.posture_trend ?? trendData.series ?? []).map(
    (p: Record<string, unknown>) => ({
      month: String(p.month ?? p.period ?? p.date ?? ""),
      score: Number(p.score ?? p.posture_score ?? p.total ?? 0),
      target: Number(p.target ?? 85),
    })
  );

  // Risk by business unit
  const riskByUnit = (trendData.risk_by_unit ?? trendData.risk_by_app ?? ov.risk_by_component ?? []).map(
    (u: Record<string, unknown>, i: number) => ({
      name: String(u.name ?? u.component ?? u.app_name ?? `Unit ${i + 1}`),
      score: Number(u.risk_score ?? u.score ?? u.finding_count ?? 0),
      findings: Number(u.findings ?? u.finding_count ?? 0),
    })
  );

  // ROI metrics
  const annualSavings = Number(ov.annual_savings ?? ov.cost_savings ?? 0);
  const costPerFix = Number(ov.cost_per_fix ?? ov.avg_fix_cost ?? 0);
  const toolsConsolidated = Number(ov.tools_consolidated ?? ov.tools_replaced ?? 0);
  const totalFindings = Number(ov.total_findings ?? 0);
  const resolvedThisQuarter = Number(ov.resolved_quarter ?? ov.resolved_findings ?? 0);
  const postureScore = Number(ov.posture_score ?? ov.security_score ?? 0);
  const postureChange = Number(ov.posture_change ?? trendData.posture_change ?? 0);

  // Key decisions
  const decisions = (bundles.decisions ?? bundles.items ?? evidenceBundles.data?.items ?? []).slice(0, 8);
  const decisionsThisQuarter = Number(ov.decisions_this_quarter ?? decisions.length ?? 0);

  // Compliance frameworks
  const frameworks = [
    {
      name: "SOC 2 Type II",
      status: comp.soc2_status ?? comp.soc2 ?? "pending",
      score: Number(comp.soc2_score ?? comp.soc2_pct ?? 0),
    },
    {
      name: "PCI-DSS",
      status: comp.pci_status ?? comp.pci ?? "pending",
      score: Number(comp.pci_score ?? comp.pci_pct ?? 0),
    },
    {
      name: "HIPAA",
      status: comp.hipaa_status ?? comp.hipaa ?? "pending",
      score: Number(comp.hipaa_score ?? comp.hipaa_pct ?? 0),
    },
    {
      name: "ISO 27001",
      status: comp.iso_status ?? comp.iso27001 ?? "pending",
      score: Number(comp.iso_score ?? comp.iso_pct ?? 0),
    },
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.07 } },
  };
  const itemVariants = {
    hidden: { opacity: 0, y: 14 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4 } },
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Executive View"
        description="Board-ready security posture summary, ROI metrics, and compliance status"
        badge="BOARD"
        actions={
          <div className="flex items-center gap-2">
            <Select value={selectedQuarter} onValueChange={setSelectedQuarter}>
              <SelectTrigger className="h-8 w-[120px] text-xs">
                <Calendar className="h-3.5 w-3.5 mr-1.5" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Q1-2026">Q1 2026</SelectItem>
                <SelectItem value="Q4-2025">Q4 2025</SelectItem>
                <SelectItem value="Q3-2025">Q3 2025</SelectItem>
                <SelectItem value="Q2-2025">Q2 2025</SelectItem>
              </SelectContent>
            </Select>
            <Select value={selectedYear} onValueChange={setSelectedYear}>
              <SelectTrigger className="h-8 w-[90px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="2026">2026</SelectItem>
                <SelectItem value="2025">2025</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" className="gap-1.5" onClick={async () => {
              try {
                const res = await reportsApi.generate({ report_type: "executive", format: "pdf", quarter: selectedQuarter });
                const data = res.data?.data ?? res.data;
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `executive-report-${selectedQuarter}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                toast.success("Executive report exported");
              } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : "Unknown error";
                toast.error(`Export failed: ${msg}`);
              }
            }}>
              <Download className="h-3.5 w-3.5" />
              Export Report
            </Button>
          </div>
        }
      />

      {/* Top KPI Row */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-2 gap-3 sm:grid-cols-4"
      >
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Security Posture Score"
            value={`${postureScore}/100`}
            icon={Shield}
            change={postureChange}
            changeLabel="vs last quarter"
            trend={postureChange >= 0 ? "up" : "down"}
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Annual Savings"
            value={annualSavings > 0 ? formatCurrency(annualSavings) : "—"}
            icon={DollarSign}
            trend="up"
            changeLabel="projected this year"
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Resolved This Quarter"
            value={resolvedThisQuarter}
            icon={CheckCircle2}
            trend={resolvedThisQuarter > 0 ? "up" : "flat"}
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Tools Consolidated"
            value={toolsConsolidated > 0 ? `${toolsConsolidated} tools` : "—"}
            icon={Layers}
            trend="up"
          />
        </motion.div>
      </motion.div>

      {/* ROI Summary Card */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.18 }}
      >
        <Card className="border-green-500/20 bg-gradient-to-r from-green-500/5 via-transparent to-transparent">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
                <DollarSign className="h-4 w-4" />
                ROI Summary — {selectedQuarter}
              </CardTitle>
              <Badge variant="outline" className="border-green-500/30 text-green-400 text-[10px]">
                Cost Efficiency
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Annual Savings</p>
                <p className="text-2xl font-bold text-green-400 tabular-nums">
                  {annualSavings > 0 ? formatCurrency(annualSavings) : "—"}
                </p>
                <div className="flex items-center gap-1 text-xs text-green-400">
                  <TrendingUp className="h-3 w-3" />
                  <span>vs manual processes</span>
                </div>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Cost Per Fix</p>
                <p className="text-2xl font-bold tabular-nums">
                  {costPerFix > 0 ? formatCurrency(costPerFix) : "—"}
                </p>
                <p className="text-xs text-muted-foreground">avg per resolved finding</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Tools Consolidated</p>
                <p className="text-2xl font-bold tabular-nums">{toolsConsolidated || "—"}</p>
                <p className="text-xs text-muted-foreground">platforms replaced</p>
              </div>
              <div className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Total Findings Managed</p>
                <p className="text-2xl font-bold tabular-nums">{totalFindings.toLocaleString()}</p>
                <p className="text-xs text-muted-foreground">across all environments</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        {/* Security Posture Trend — 12-month AreaChart */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.12 }}
          className="lg:col-span-3"
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-blue-400" />
                    Security Posture Trend
                  </CardTitle>
                  <CardDescription className="text-xs mt-0.5">12-month score trajectory vs target</CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <TrendArrow value={postureChange} />
                  <span className={cn(
                    "text-sm font-bold tabular-nums",
                    postureChange >= 0 ? "text-green-400" : "text-red-400"
                  )}>
                    {postureChange >= 0 ? "+" : ""}{postureChange}
                  </span>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {postureTrend.length > 0 ? (
                <ResponsiveContainer width="100%" height={260}>
                  <AreaChart data={postureTrend} margin={{ top: 4, right: 4, bottom: 0, left: -16 }}>
                    <defs>
                      <linearGradient id="gradScore" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                      </linearGradient>
                      <linearGradient id="gradTarget" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#22c55e" stopOpacity={0.15} />
                        <stop offset="95%" stopColor="#22c55e" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} />
                    <XAxis dataKey="month" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                    <Area type="monotone" dataKey="target" stroke="#22c55e" fill="url(#gradTarget)" strokeWidth={1.5} strokeDasharray="4 2" name="Target" />
                    <Area type="monotone" dataKey="score" stroke="#3b82f6" fill="url(#gradScore)" strokeWidth={2} name="Score" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
                  No posture trend data available yet
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Risk by Business Unit — Horizontal BarChart */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.18 }}
          className="lg:col-span-2"
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Building2 className="h-4 w-4 text-purple-400" />
                Risk by Business Unit
              </CardTitle>
              <CardDescription className="text-xs">Risk score per app / component</CardDescription>
            </CardHeader>
            <CardContent>
              {riskByUnit.length > 0 ? (
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart
                    data={riskByUnit.slice(0, 8)}
                    layout="vertical"
                    margin={{ top: 0, right: 16, bottom: 0, left: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} horizontal={false} />
                    <XAxis type="number" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} />
                    <YAxis
                      dataKey="name"
                      type="category"
                      tick={{ fontSize: 10 }}
                      stroke="hsl(var(--muted-foreground))"
                      width={80}
                      tickLine={false}
                      axisLine={false}
                    />
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                    <Bar dataKey="score" radius={[0, 4, 4, 0]} name="Risk Score">
                      {riskByUnit.slice(0, 8).map((_: unknown, i: number) => (
                        <Cell key={i} fill={UNIT_COLORS[i % UNIT_COLORS.length]} fillOpacity={0.8} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-[260px] items-center justify-center text-sm text-muted-foreground">
                  No business unit data available
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Bottom Row: Compliance + Key Decisions */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Compliance Status */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.22 }}
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Award className="h-4 w-4 text-yellow-400" />
                Compliance Status
              </CardTitle>
              <CardDescription className="text-xs">Framework adherence and audit readiness</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {frameworks.map((fw) => (
                  <ComplianceTile
                    key={fw.name}
                    name={fw.name}
                    status={String(fw.status)}
                    score={fw.score > 0 ? fw.score : undefined}
                  />
                ))}
              </div>
              <Separator className="my-3" />
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Overall compliance</span>
                <div className="flex items-center gap-2">
                  <Progress
                    value={Number(comp.overall_score ?? comp.compliance_score ?? 0)}
                    className="w-24 h-1.5"
                  />
                  <span className="font-semibold tabular-nums text-foreground">
                    {Number(comp.overall_score ?? comp.compliance_score ?? 0).toFixed(0)}%
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Key Decisions This Quarter */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.28 }}
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  Key Decisions — {selectedQuarter}
                </CardTitle>
                <Badge variant="outline" className="text-[10px]">
                  {decisionsThisQuarter} total
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {decisions.length > 0 ? (
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Decision</TableHead>
                      <TableHead className="text-[11px] h-8">Type</TableHead>
                      <TableHead className="text-[11px] h-8 text-right">Count</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {decisions.map((d: Record<string, unknown>, i: number) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="text-xs py-2">
                          <p className="font-medium truncate max-w-[160px]">{String(d.title ?? d.name ?? `Decision ${i + 1}`)}</p>
                          {!!d.created_at && (
                            <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {new Date(String(d.created_at)).toLocaleDateString()}
                            </p>
                          )}
                        </TableCell>
                        <TableCell className="py-2">
                          <Badge variant="outline" className="text-[10px] capitalize">
                            {String(d.type ?? d.category ?? "general")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right py-2">
                          <span className="text-sm font-bold tabular-nums">
                            {Number(d.count ?? d.finding_count ?? 1)}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                </div>
              ) : (
                <div className="flex h-[160px] items-center justify-center px-6">
                  <div className="text-center space-y-2">
                    <Target className="h-8 w-8 text-muted-foreground/40 mx-auto" />
                    <p className="text-sm text-muted-foreground">No decisions recorded for this quarter yet</p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Executive Summary Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.35 }}
        className="rounded-lg border border-border/50 bg-muted/10 p-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Executive Summary</p>
            <p className="text-sm text-foreground/80">
              {`Security posture at ${postureScore}/100 with ${totalFindings.toLocaleString()} total findings managed. `}
              {resolvedThisQuarter > 0 && `${resolvedThisQuarter} resolved this quarter.`}
            </p>
          </div>
          <Button variant="outline" size="sm" className="shrink-0 gap-1.5" onClick={refetch}>
            <Target className="h-3.5 w-3.5" />
            Refresh Data
          </Button>
        </div>
      </motion.div>
    </motion.div>
  );
}
