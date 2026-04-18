import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  Shield, AlertTriangle, TrendingUp, TrendingDown, RefreshCw,
  Target, Activity, ArrowUp, ArrowDown, Minus, BarChart3,
  Building2, Eye, ChevronUp, ChevronDown, Info, Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip as UITooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useDashboardOverview,
  useDashboardTopRisks,
  useDashboardTrends,
} from "@/hooks/use-api";
import { cn } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e"];

const CHART_TOOLTIP_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 12,
};

function RiskScoreGauge({ score, change }: { score: number; change: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 80 ? "#ef4444" : pct >= 60 ? "#f97316" : pct >= 40 ? "#eab308" : "#22c55e";
  const label = pct >= 80 ? "Critical" : pct >= 60 ? "High" : pct >= 40 ? "Moderate" : "Low";
  const r = 54;
  const cx = 72;
  const cy = 72;
  const startAngle = -210;
  const endAngle = 30;
  const totalArc = endAngle - startAngle;
  const fillAngle = startAngle + (totalArc * pct) / 100;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const arcPath = (a1: number, a2: number) => {
    const x1 = cx + r * Math.cos(toRad(a1));
    const y1 = cy + r * Math.sin(toRad(a1));
    const x2 = cx + r * Math.cos(toRad(a2));
    const y2 = cy + r * Math.sin(toRad(a2));
    const large = Math.abs(a2 - a1) > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={144} height={110} viewBox="0 0 144 110">
        <path d={arcPath(startAngle, endAngle)} fill="none" stroke="hsl(var(--border))" strokeWidth={10} strokeLinecap="round" />
        <path d={arcPath(startAngle, fillAngle)} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round" />
        <text x={cx} y={cy + 8} textAnchor="middle" fill={color} fontSize={26} fontWeight="bold" fontFamily="inherit">
          {pct}
        </text>
        <text x={cx} y={cy + 24} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={11} fontFamily="inherit">
          {label}
        </text>
      </svg>
      <div className="flex items-center gap-1 text-xs">
        {change > 0
          ? <><ArrowUp className="h-3.5 w-3.5 text-red-400" /><span className="text-red-400 font-medium">+{change} vs last period</span></>
          : change < 0
          ? <><ArrowDown className="h-3.5 w-3.5 text-green-400" /><span className="text-green-400 font-medium">{change} vs last period</span></>
          : <><Minus className="h-3.5 w-3.5 text-muted-foreground" /><span className="text-muted-foreground">Unchanged</span></>
        }
      </div>
      <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Org Risk Score</p>
    </div>
  );
}

function RiskScoreBar({ score, max = 100 }: { score: number; max?: number }) {
  const pct = Math.min(100, (score / max) * 100);
  const color = pct >= 80 ? "bg-red-500" : pct >= 60 ? "bg-orange-500" : pct >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${pct}%` }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className={cn("h-full rounded-full", color)}
      />
    </div>
  );
}

function SlaStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    compliant: "border-green-500/30 text-green-400 bg-green-500/10",
    at_risk: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    breached: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status?.replace("_", " ") || "—"}
    </Badge>
  );
}

interface AppRiskRow {
  name: string;
  riskScore: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  slaStatus: string;
}

export default function RiskOverview() {
  const [trendPeriod, setTrendPeriod] = useState("30d");
  const [sortField, setSortField] = useState<keyof AppRiskRow>("riskScore");
  const [sortAsc, setSortAsc] = useState(false);

  const overview = useDashboardOverview();
  const topRisks = useDashboardTopRisks();
  const trends = useDashboardTrends({ period: trendPeriod });

  const isLoading = overview.isLoading || topRisks.isLoading;
  const isError = overview.isError && topRisks.isError;
  const refetch = useCallback(() => {
    overview.refetch();
    topRisks.refetch();
    trends.refetch();
  }, [overview, topRisks, trends]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load risk data" onRetry={refetch} />;

  const ov = overview.data ?? {};
  const trendData = trends.data ?? {};
  const risksData = topRisks.data ?? {};

  const orgRiskScore = Number(ov.risk_score ?? ov.posture_score ?? 0);
  const riskChange = Number(ov.risk_change ?? ov.posture_change ?? 0);
  const criticalCount = Number(ov.critical_findings ?? 0);
  const highCount = Number(ov.high_findings ?? 0);
  const mediumCount = Number(ov.medium_findings ?? 0);
  const lowCount = Number(ov.low_findings ?? 0);
  const totalFindings = criticalCount + highCount + mediumCount + lowCount;

  // Top 10 riskiest apps
  const rawRisks: Record<string, unknown>[] = risksData.risks ?? risksData.top_risks ?? risksData.apps ?? [];
  const appRows: AppRiskRow[] = rawRisks.slice(0, 10).map((r) => ({
    name: String(r.name ?? r.app_name ?? r.title ?? r.component ?? "Unknown"),
    riskScore: Number(r.risk_score ?? r.cvss_score ?? r.score ?? 0),
    critical: Number(r.critical ?? r.critical_count ?? 0),
    high: Number(r.high ?? r.high_count ?? 0),
    medium: Number(r.medium ?? r.medium_count ?? 0),
    low: Number(r.low ?? r.low_count ?? 0),
    slaStatus: String(r.sla_status ?? r.status ?? "—"),
  }));

  // Sort
  const sortedAppRows = [...appRows].sort((a, b) => {
    const av = a[sortField];
    const bv = b[sortField];
    if (typeof av === "number" && typeof bv === "number") {
      return sortAsc ? av - bv : bv - av;
    }
    return sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
  });

  // Severity distribution for PieChart
  const pieData = [
    { name: "Critical", value: criticalCount, color: SEVERITY_COLORS.critical },
    { name: "High", value: highCount, color: SEVERITY_COLORS.high },
    { name: "Medium", value: mediumCount, color: SEVERITY_COLORS.medium },
    { name: "Low", value: lowCount, color: SEVERITY_COLORS.low },
  ].filter((d) => d.value > 0);

  // Risk trend chart
  const riskTrend = (trendData.risk_trend ?? trendData.series ?? []).map((d: Record<string, unknown>) => ({
    date: String(d.date ?? d.period ?? ""),
    score: Number(d.risk_score ?? d.score ?? d.total ?? 0),
    critical: Number(d.critical ?? 0),
    high: Number(d.high ?? 0),
  }));

  // Business impact assessment
  const impactScore = Number(ov.business_impact_score ?? ov.impact_score ?? 0);
  const impactAreas: { label: string; value: number; description: string }[] = [
    {
      label: "Data Exposure",
      value: Number(ov.data_exposure_risk ?? 0),
      description: "Risk of sensitive data compromise",
    },
    {
      label: "Service Availability",
      value: Number(ov.availability_risk ?? 0),
      description: "Risk to uptime and service continuity",
    },
    {
      label: "Compliance Exposure",
      value: Number(ov.compliance_risk ?? 0),
      description: "Regulatory and audit risk",
    },
    {
      label: "Reputation Impact",
      value: Number(ov.reputation_risk ?? 0),
      description: "Potential reputational damage",
    },
  ];

  const handleSort = (field: keyof AppRiskRow) => {
    if (sortField === field) setSortAsc(!sortAsc);
    else { setSortField(field); setSortAsc(false); }
  };

  const SortIcon = ({ field }: { field: keyof AppRiskRow }) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 opacity-30 inline ml-1" />;
    return sortAsc ? <ChevronUp className="h-3 w-3 inline ml-1" /> : <ChevronDown className="h-3 w-3 inline ml-1" />;
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.07 } },
  };
  const itemVariants = {
    hidden: { opacity: 0, y: 12 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.35 } },
  };

  return (
    <TooltipProvider>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="flex flex-col gap-6"
      >
        {/* Header */}
        <PageHeader
          title="Risk Overview"
          description="Organization-wide risk posture, top risky applications, and business impact assessment"
          actions={
            <div className="flex items-center gap-2">
              <Select value={trendPeriod} onValueChange={setTrendPeriod}>
                <SelectTrigger className="h-8 w-[110px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30d">30 days</SelectItem>
                  <SelectItem value="60d">60 days</SelectItem>
                  <SelectItem value="90d">90 days</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={refetch}>
                <RefreshCw className={cn("h-4 w-4", overview.isFetching && "animate-spin")} />
              </Button>
            </div>
          }
        />

        {/* KPI Row */}
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5"
        >
          <motion.div variants={itemVariants} className="sm:col-span-1">
            <Card className="h-full flex items-center justify-center p-4">
              <RiskScoreGauge score={orgRiskScore} change={riskChange} />
            </Card>
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="Critical Findings"
              value={criticalCount}
              icon={AlertTriangle}
              trend={criticalCount > 0 ? "up" : "down"}
              className={cn(criticalCount > 0 && "border-red-500/30 bg-red-500/5")}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="High Findings"
              value={highCount}
              icon={Shield}
              trend={highCount > 10 ? "up" : "flat"}
              className={cn(highCount > 10 && "border-orange-500/20")}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="Total Findings"
              value={totalFindings}
              icon={Layers}
              trend="flat"
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="Risky Apps"
              value={appRows.length}
              icon={Building2}
              trend={appRows.length > 5 ? "up" : "flat"}
            />
          </motion.div>
        </motion.div>

        {/* Charts Row */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
          {/* Risk Trend AreaChart */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.12 }}
            className="lg:col-span-3"
          >
            <Card className="h-full">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <BarChart3 className="h-4 w-4 text-red-400" />
                    Risk Trend
                  </CardTitle>
                  <span className="text-[10px] text-muted-foreground bg-muted/30 px-2 py-0.5 rounded-full">
                    {trendPeriod}
                  </span>
                </div>
                <CardDescription className="text-xs">Overall risk score and critical/high volume over time</CardDescription>
              </CardHeader>
              <CardContent>
                {riskTrend.length > 0 ? (
                  <ResponsiveContainer width="100%" height={240}>
                    <AreaChart data={riskTrend} margin={{ top: 4, right: 4, bottom: 0, left: -16 }}>
                      <defs>
                        <linearGradient id="gradRisk" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                          <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
                        </linearGradient>
                        <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#f97316" stopOpacity={0.2} />
                          <stop offset="95%" stopColor="#f97316" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} />
                      <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} />
                      <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                      <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                      <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                      <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="url(#gradHigh)" strokeWidth={1.5} name="High" />
                      <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="url(#gradRisk)" strokeWidth={1.5} name="Critical" />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-[240px] items-center justify-center text-sm text-muted-foreground">
                    No risk trend data available
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>

          {/* Risk by Severity PieChart */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.18 }}
            className="lg:col-span-2"
          >
            <Card className="h-full">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Target className="h-4 w-4 text-purple-400" />
                  Risk by Severity
                </CardTitle>
                <CardDescription className="text-xs">Distribution of {totalFindings.toLocaleString()} total findings</CardDescription>
              </CardHeader>
              <CardContent>
                {pieData.length > 0 ? (
                  <>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie
                          data={pieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={80}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {pieData.map((entry, i) => (
                            <Cell key={i} fill={entry.color} fillOpacity={0.85} />
                          )))}
                        </Pie>
                        <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                        <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="grid grid-cols-2 gap-2 mt-2">
                      {pieData.map((d) => (
                        <div key={d.name} className="flex items-center justify-between text-xs">
                          <div className="flex items-center gap-1.5">
                            <span className="h-2 w-2 rounded-full" style={{ backgroundColor: d.color }} />
                            <span className="text-muted-foreground">{d.name}</span>
                          </div>
                          <span className="font-bold tabular-nums">{d.value}</span>
                        </div>
                      )))}
                    </div>
                  </>
                ) : (
                  <div className="flex h-[200px] items-center justify-center text-sm text-muted-foreground">
                    No finding data available
                  </div>
                )}
              </CardContent>
            </Card>
          </motion.div>
        </div>

        {/* Top 10 Riskiest Apps */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.22 }}
        >
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Building2 className="h-4 w-4 text-orange-400" />
                    Top 10 Riskiest Apps
                  </CardTitle>
                  <CardDescription className="text-xs">Sorted by risk score — click column headers to re-sort</CardDescription>
                </div>
                <Badge variant="outline" className="text-[10px]">{appRows.length} apps</Badge>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {sortedAppRows.length > 0 ? (
                <ScrollArea className="h-[320px]">
                  <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent sticky top-0 bg-card z-10">
                        <TableHead className="text-[11px] h-8">Application</TableHead>
                        <TableHead
                          className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                          onClick={() => handleSort("riskScore")}
                        >
                          Risk Score <SortIcon field="riskScore" />
                        </TableHead>
                        <TableHead
                          className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                          onClick={() => handleSort("critical")}
                        >
                          <span className="text-red-400">Crit</span> <SortIcon field="critical" />
                        </TableHead>
                        <TableHead
                          className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                          onClick={() => handleSort("high")}
                        >
                          <span className="text-orange-400">High</span> <SortIcon field="high" />
                        </TableHead>
                        <TableHead
                          className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                          onClick={() => handleSort("medium")}
                        >
                          <span className="text-yellow-400">Med</span> <SortIcon field="medium" />
                        </TableHead>
                        <TableHead className="text-[11px] h-8">SLA Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {sortedAppRows.map((row, i) => (
                        <TableRow key={i} className="hover:bg-muted/30">
                          <TableCell className="py-2.5">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] font-mono text-muted-foreground w-4 shrink-0">
                                {String(i + 1).padStart(2, "0")}
                              </span>
                              <div className="min-w-0">
                                <p className="text-xs font-medium truncate max-w-[180px]">{row.name}</p>
                              </div>
                            </div>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <div className="space-y-1 w-28">
                              <div className="flex items-center justify-between">
                                <span className={cn(
                                  "text-xs font-bold tabular-nums",
                                  row.riskScore >= 80 ? "text-red-400" : row.riskScore >= 60 ? "text-orange-400" : row.riskScore >= 40 ? "text-yellow-400" : "text-green-400"
                                )}>
                                  {row.riskScore.toFixed(0)}
                                </span>
                              </div>
                              <RiskScoreBar score={row.riskScore} />
                            </div>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <span className={cn("text-xs font-bold tabular-nums", row.critical > 0 ? "text-red-400" : "text-muted-foreground")}>
                              {row.critical}
                            </span>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <span className={cn("text-xs font-bold tabular-nums", row.high > 0 ? "text-orange-400" : "text-muted-foreground")}>
                              {row.high}
                            </span>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <span className={cn("text-xs font-bold tabular-nums", row.medium > 0 ? "text-yellow-400" : "text-muted-foreground")}>
                              {row.medium}
                            </span>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <SlaStatusBadge status={row.slaStatus} />
                          </TableCell>
                        </TableRow>
                      )))}
                    </TableBody>
                  </Table>
                  </div>
                </ScrollArea>
              ) : (
                <div className="flex h-[180px] flex-col items-center justify-center gap-3 text-muted-foreground">
                  <Eye className="h-8 w-8 opacity-20" />
                  <p className="text-sm">No risk data available — run scans to populate</p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Business Impact Assessment */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
        >
          <Card className="border-yellow-500/20 bg-yellow-500/5">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 text-yellow-400">
                  <Activity className="h-4 w-4" />
                  Business Impact Assessment
                </CardTitle>
                <UITooltip>
                  <TooltipTrigger asChild>
                    <Button variant="ghost" size="icon" className="h-6 w-6">
                      <Info className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="text-xs max-w-[200px]">
                      Impact scores are derived from finding severity, asset criticality, and exposure surface area.
                    </p>
                  </TooltipContent>
                </UITooltip>
              </div>
              <CardDescription className="text-xs">Projected business exposure across key risk dimensions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                {impactAreas.map((area) => {
                  const pct = Math.min(100, area.value);
                  return (
                    <div key={area.label} className="space-y-2">
                      <div className="flex items-center justify-between text-xs">
                        <div>
                          <p className="font-semibold">{area.label}</p>
                          <p className="text-muted-foreground text-[10px]">{area.description}</p>
                        </div>
                        <span className={cn(
                          "font-bold tabular-nums text-sm",
                          pct >= 70 ? "text-red-400" : pct >= 40 ? "text-yellow-400" : "text-green-400"
                        )}>
                          {pct.toFixed(0)}
                        </span>
                      </div>
                      <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.9, ease: "easeOut" }}
                          className={cn(
                            "h-full rounded-full",
                            pct >= 70 ? "bg-red-500" : pct >= 40 ? "bg-yellow-500" : "bg-green-500"
                          )}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
              <Separator className="my-4" />
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Overall Business Impact Score</span>
                <div className="flex items-center gap-2">
                  <Progress value={impactScore} className="w-32 h-1.5" />
                  <span className={cn(
                    "font-bold tabular-nums",
                    impactScore >= 70 ? "text-red-400" : impactScore >= 40 ? "text-yellow-400" : "text-green-400"
                  )}>
                    {impactScore.toFixed(0)} / 100
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    </TooltipProvider>
  );
}
