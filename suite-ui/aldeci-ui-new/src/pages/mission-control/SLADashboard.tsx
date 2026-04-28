import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import {
  Clock, AlertTriangle, CheckCircle2, TrendingUp, TrendingDown,
  Users, Filter, RefreshCw, Timer, AlertCircle, Shield,
  ChevronUp, ChevronDown, Flame, Target, BarChart3,
  ExternalLink, Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useRemediationTasks,
  useDashboardOverview,
} from "@/hooks/use-api";
import { slaApi } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

const CHART_TOOLTIP_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 12,
};

function SLAGauge({ pct }: { pct: number }) {
  const value = Math.min(100, Math.max(0, pct));
  const color = value >= 95 ? "#22c55e" : value >= 80 ? "#eab308" : "#ef4444";
  const label = value >= 95 ? "On Track" : value >= 80 ? "At Risk" : "Breached";
  const r = 54;
  const cx = 72;
  const cy = 72;
  const startAngle = -210;
  const endAngle = 30;
  const totalArc = endAngle - startAngle;
  const fillAngle = startAngle + (totalArc * value) / 100;
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
        <text x={cx} y={cy + 10} textAnchor="middle" fill={color} fontSize={26} fontWeight="bold" fontFamily="inherit">
          {value.toFixed(0)}%
        </text>
        <text x={cx} y={cy + 26} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={11} fontFamily="inherit">
          {label}
        </text>
      </svg>
      <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">SLA Compliance</p>
    </div>
  );
}

function SeveritySlaBars({
  critical,
  high,
  medium,
}: {
  critical: number;
  high: number;
  medium: number;
}) {
  const items = [
    { label: "Critical", value: critical, color: "bg-red-500", textColor: "text-red-400", sla: "4h" },
    { label: "High", value: high, color: "bg-orange-500", textColor: "text-orange-400", sla: "24h" },
    { label: "Medium", value: medium, color: "bg-yellow-500", textColor: "text-yellow-400", sla: "72h" },
  ];
  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.label} className="space-y-1.5">
          <div className="flex items-center justify-between text-xs">
            <div className="flex items-center gap-2">
              <span className={cn("font-semibold", item.textColor)}>{item.label}</span>
              <span className="text-muted-foreground text-[10px]">SLA: {item.sla}</span>
            </div>
            <span className="font-bold tabular-nums">{item.value.toFixed(0)}%</span>
          </div>
          <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${item.value}%` }}
              transition={{ duration: 0.8, ease: "easeOut" }}
              className={cn("h-full rounded-full", item.color)}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; className: string }> = {
    compliant: { label: "Compliant", className: "border-green-500/30 text-green-400 bg-green-500/10" },
    at_risk: { label: "At Risk", className: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" },
    breached: { label: "Breached", className: "border-red-500/30 text-red-400 bg-red-500/10" },
    pending: { label: "Pending", className: "border-gray-500/30 text-gray-400 bg-gray-500/10" },
  };
  const cfg = map[status?.toLowerCase()] ?? map.pending;
  return <Badge className={cn("text-[10px] border capitalize", cfg.className)}>{cfg.label}</Badge>;
}

function UrgencyBadge({ hoursLeft }: { hoursLeft: number }) {
  if (hoursLeft <= 2) return <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Critical</Badge>;
  if (hoursLeft <= 8) return <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Urgent</Badge>;
  if (hoursLeft <= 24) return <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">Warning</Badge>;
  return <Badge className="text-[10px] border border-border text-muted-foreground">Normal</Badge>;
}

export default function SLADashboard() {
  const navigate = useNavigate();
  const [teamFilter, setTeamFilter] = useState("all");
  const [timeRange, setTimeRange] = useState("30d");
  const [sortField, setSortField] = useState<string | null>(null);
  const [sortAsc, setSortAsc] = useState(true);

  const tasks = useRemediationTasks({ include_sla: true });
  const overview = useDashboardOverview();

  // Real SLA backend queries
  const slaDashQuery = useQuery({
    queryKey: ["sla", "dashboard"],
    queryFn: async () => { const { data } = await slaApi.dashboard(); return data; },
    staleTime: 30_000,
  });
  const slaMetricsQuery = useQuery({
    queryKey: ["sla", "metrics"],
    queryFn: async () => { const { data } = await slaApi.metrics(); return data; },
    staleTime: 30_000,
  });

  const isLoading = tasks.isLoading || overview.isLoading;
  const isError = tasks.isError && overview.isError;
  const refetch = useCallback(() => {
    tasks.refetch();
    overview.refetch();
    slaDashQuery.refetch();
    slaMetricsQuery.refetch();
  }, [tasks, overview, slaDashQuery, slaMetricsQuery]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load SLA data" onRetry={refetch} />;

  const ov = overview.data ?? {};
  const sla = (slaDashQuery.data ?? {}) as Record<string, unknown>;
  const slaMetrics = (slaMetricsQuery.data ?? {}) as Record<string, unknown>;
  const taskList: Record<string, unknown>[] = toArray(tasks.data);

  // SLA metrics — prefer real SLA backend, fallback to overview
  const overallSla = Number(sla.compliance_rate ?? sla.sla_compliance_pct ?? ov.sla_compliance_pct ?? ov.sla_compliance ?? 0);
  const bySev = (sla.by_severity ?? {}) as Record<string, Record<string, number>>;
  const criticalSla = bySev.critical ? Math.round((bySev.critical.compliant / Math.max(bySev.critical.total, 1)) * 100) : Number(ov.critical_sla_pct ?? ov.sla_critical ?? 0);
  const highSla = bySev.high ? Math.round((bySev.high.compliant / Math.max(bySev.high.total, 1)) * 100) : Number(ov.high_sla_pct ?? ov.sla_high ?? 0);
  const mediumSla = bySev.medium ? Math.round((bySev.medium.compliant / Math.max(bySev.medium.total, 1)) * 100) : Number(ov.medium_sla_pct ?? ov.sla_medium ?? 0);

  // MTTR from real SLA metrics endpoint
  const mttrAvg = Number(slaMetrics.mttr_avg_hours ?? slaMetrics.avg_mttr ?? 0);
  const mttrP50 = Number(slaMetrics.mttr_p50_hours ?? slaMetrics.p50_mttr ?? 0);
  const mttrP90 = Number(slaMetrics.mttr_p90_hours ?? slaMetrics.p90_mttr ?? 0);

  // Aging analysis
  const overdueCount = taskList.filter((t) => t.sla_status === "breached" || t.overdue === true).length;
  const overdueHigh = taskList.filter((t) => (t.sla_status === "breached" || t.overdue) && t.severity === "high").length;
  const atRiskCount = taskList.filter((t) => t.sla_status === "at_risk").length;
  const atRiskCritical = taskList.filter((t) => t.sla_status === "at_risk" && t.severity === "critical").length;

  // By team table
  const teamMap = new Map<string, { total: number; onTime: number }>();
  taskList.forEach((t) => {
    const team = String(t.assigned_team ?? t.team ?? t.owner ?? "Unassigned");
    const existing = teamMap.get(team) ?? { total: 0, onTime: 0 };
    teamMap.set(team, {
      total: existing.total + 1,
      onTime: existing.onTime + (t.sla_status === "compliant" || !t.sla_status ? 1 : 0),
    });
  });
  const teamRows = Array.from(teamMap.entries()).map(([name, v]) => ({
    name,
    total: v.total,
    pct: v.total > 0 ? Math.round((v.onTime / v.total) * 100) : 0,
    status: v.total > 0
      ? (v.onTime / v.total) >= 0.95 ? "compliant"
        : (v.onTime / v.total) >= 0.8 ? "at_risk"
        : "breached"
      : "pending",
  })).filter((r) => teamFilter === "all" || r.status === teamFilter);

  // Sort team rows
  const sortedTeamRows = [...teamRows].sort((a, b) => {
    if (!sortField) return 0;
    const av = a[sortField as keyof typeof a];
    const bv = b[sortField as keyof typeof b];
    if (typeof av === "number" && typeof bv === "number") {
      return sortAsc ? av - bv : bv - av;
    }
    return sortAsc
      ? String(av).localeCompare(String(bv))
      : String(bv).localeCompare(String(av));
  });

  // Escalation queue: items approaching SLA breach
  const escalationQueue = taskList
    .filter((t) => t.sla_status === "at_risk" || t.sla_status === "breached" || Number(t.hours_remaining ?? 999) <= 24)
    .sort((a, b) => Number(a.hours_remaining ?? 999) - Number(b.hours_remaining ?? 999))
    .slice(0, 15);

  // SLA trend chart data
  const slaTrend = (ov.sla_trend ?? ov.sla_history ?? []).map((d: Record<string, unknown>) => ({
    date: String(d.date ?? d.period ?? ""),
    compliance: Number(d.compliance ?? d.sla_pct ?? d.value ?? 0),
    target: 95,
  }));

  const handleSort = (field: string) => {
    if (sortField === field) setSortAsc(!sortAsc);
    else { setSortField(field); setSortAsc(true); }
  };

  const SortIcon = ({ field }: { field: string }) => {
    if (sortField !== field) return null;
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
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="SLA Dashboard"
        description="Track SLA compliance, aging findings, and escalation queue across all teams"
        actions={
          <div className="flex items-center gap-2">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="h-8 w-[110px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7d">Last 7d</SelectItem>
                <SelectItem value="30d">Last 30d</SelectItem>
                <SelectItem value="90d">Last 90d</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={refetch}>
              <RefreshCw className="h-4 w-4" />
            </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6"
      >
        <motion.div variants={itemVariants} className="sm:col-span-1">
          <Card className="h-full flex items-center justify-center p-4">
            <SLAGauge pct={overallSla} />
          </Card>
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Overdue (Critical)"
            value={atRiskCritical + overdueCount}
            icon={Flame}         trend={(atRiskCritical + overdueCount) > 0 ? "up" : "down"}
            className={cn((atRiskCritical + overdueCount) > 0 && "border-red-500/30 bg-red-500/5")}
            onClick={() => navigate("/remediate?status=overdue&severity=critical")}
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="At Risk"
            value={atRiskCount}
            icon={AlertCircle}         trend={atRiskCount > 5 ? "up" : "flat"}
            className={cn(atRiskCount > 0 && "border-yellow-500/30 bg-yellow-500/5")}
            onClick={() => navigate("/remediate?status=at_risk")}
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="MTTR (Avg)"
            value={mttrAvg > 0 ? `${mttrAvg.toFixed(0)}h` : "—"}
            icon={Clock}
            className="border-blue-500/20"
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="MTTR (P50)"
            value={mttrP50 > 0 ? `${mttrP50.toFixed(0)}h` : "—"}
            icon={Activity}
            className="border-cyan-500/20"
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="MTTR (P90)"
            value={mttrP90 > 0 ? `${mttrP90.toFixed(0)}h` : "—"}
            icon={AlertTriangle}         trend={mttrP90 > 72 ? "up" : "down"}
            className={cn(mttrP90 > 72 && "border-orange-500/20")}
          />
        </motion.div>
      </motion.div>

      {/* Middle row: Severity SLA bars + SLA Trend Chart */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* By Severity */}
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.15 }}
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Target className="h-4 w-4 text-orange-400" />
                SLA by Severity
              </CardTitle>
              <CardDescription className="text-xs">Compliance rate per severity tier</CardDescription>
            </CardHeader>
            <CardContent>
              <SeveritySlaBars
                critical={criticalSla}
                high={highSla}
                medium={mediumSla}
              />
              <Separator className="my-4" />
              <div className="space-y-2 text-xs text-muted-foreground">
                <div className="flex justify-between">
                  <span>Critical SLA window</span>
                  <span className="font-medium text-foreground">4 hours</span>
                </div>
                <div className="flex justify-between">
                  <span>High SLA window</span>
                  <span className="font-medium text-foreground">24 hours</span>
                </div>
                <div className="flex justify-between">
                  <span>Medium SLA window</span>
                  <span className="font-medium text-foreground">72 hours</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* SLA Trend Chart */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.12 }}
          className="lg:col-span-2"
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-blue-400" />
                  SLA Compliance Trend
                </CardTitle>
                <span className="text-[10px] text-muted-foreground bg-muted/30 px-2 py-0.5 rounded-full">
                  {timeRange}
                </span>
              </div>
              <CardDescription className="text-xs">Daily compliance rate vs 95% target</CardDescription>
            </CardHeader>
            <CardContent>
              {slaTrend.length > 0 ? (
                <ResponsiveContainer width="100%" height={220}>
                  <AreaChart data={slaTrend} margin={{ top: 4, right: 4, bottom: 0, left: -16 }}>
                    <defs>
                      <linearGradient id="gradSla" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} />
                    <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} />
                    <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                    <Tooltip contentStyle={CHART_TOOLTIP_STYLE} formatter={(v: number) => [`${v.toFixed(1)}%`]} />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                    <Area
                      type="monotone"
                      dataKey="target"
                      stroke="#22c55e"
                      fill="none"
                      strokeWidth={1.5}
                      strokeDasharray="4 2"
                      name="Target (95%)"
                    />
                    <Area
                      type="monotone"
                      dataKey="compliance"
                      stroke="#3b82f6"
                      fill="url(#gradSla)"
                      strokeWidth={2}
                      name="Compliance %"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-[220px] items-center justify-center text-sm text-muted-foreground">
                  No SLA trend data available
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* By Team table */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Users className="h-4 w-4 text-purple-400" />
                  SLA by Team
                </CardTitle>
                <CardDescription className="text-xs">{teamRows.length} teams tracked</CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                <Select value={teamFilter} onValueChange={setTeamFilter}>
                  <SelectTrigger className="h-7 w-[120px] text-[11px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Teams</SelectItem>
                    <SelectItem value="compliant">Compliant</SelectItem>
                    <SelectItem value="at_risk">At Risk</SelectItem>
                    <SelectItem value="breached">Breached</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {sortedTeamRows.length > 0 ? (
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead
                      className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                      onClick={() => handleSort("name")}
                    >
                      Team <SortIcon field="name" />
                    </TableHead>
                    <TableHead
                      className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                      onClick={() => handleSort("total")}
                    >
                      Total Tasks <SortIcon field="total" />
                    </TableHead>
                    <TableHead className="text-[11px] h-8">Compliance Rate</TableHead>
                    <TableHead
                      className="text-[11px] h-8 cursor-pointer hover:text-foreground"
                      onClick={() => handleSort("pct")}
                    >
                      % <SortIcon field="pct" />
                    </TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedTeamRows.map((row, i) => (
                    <TableRow key={i} className="hover:bg-muted/30 cursor-pointer" onClick={() => navigate(`/remediate?assignee=${encodeURIComponent(row.name)}`)}>
                      <TableCell className="text-xs font-medium py-2.5">{row.name}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums">{row.total}</TableCell>
                      <TableCell className="py-2.5 w-40">
                        <div className="flex items-center gap-2">
                          <Progress value={row.pct} className="h-1.5 flex-1" />
                        </div>
                      </TableCell>
                      <TableCell className="text-xs font-bold tabular-nums py-2.5">
                        <span className={cn(
                          row.pct >= 95 ? "text-green-400" : row.pct >= 80 ? "text-yellow-400" : "text-red-400"
                        )}>
                          {row.pct}%
                        </span>
                      </TableCell>
                      <TableCell className="py-2.5">
                        <StatusBadge status={row.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              </div>
            ) : (
              <div className="flex h-[120px] items-center justify-center text-sm text-muted-foreground">
                No teams match the selected filter
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* Escalation Queue */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.28 }}
      >
        <Card className="border-orange-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
                <Flame className="h-4 w-4" />
                Escalation Queue
              </CardTitle>
              <Badge
                variant="outline"
                className={cn(
                  "text-[10px]",
                  escalationQueue.length > 0
                    ? "border-orange-500/30 text-orange-400 bg-orange-500/10"
                    : "border-green-500/30 text-green-400"
                )}
              >
                {escalationQueue.length} items
              </Badge>
            </div>
            <CardDescription className="text-xs">Findings approaching or breaching SLA — sorted by urgency</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {escalationQueue.length > 0 ? (
              <ScrollArea className="h-[280px]">
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Finding</TableHead>
                      <TableHead className="text-[11px] h-8">Severity</TableHead>
                      <TableHead className="text-[11px] h-8">Team</TableHead>
                      <TableHead className="text-[11px] h-8">Time Remaining</TableHead>
                      <TableHead className="text-[11px] h-8">Urgency</TableHead>
                      <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {escalationQueue.map((item: Record<string, unknown>, i: number) => {
                      const hoursLeft = Number(item.hours_remaining ?? item.sla_remaining_hours ?? 999);
                      const displayTime = hoursLeft >= 999
                        ? "Overdue"
                        : hoursLeft <= 0
                        ? "Overdue"
                        : hoursLeft < 1
                        ? `${Math.round(hoursLeft * 60)}m`
                        : `${hoursLeft.toFixed(0)}h`;
                      const findingName = String(item.title ?? item.name ?? item.finding_id ?? `Finding ${i + 1}`);
                      return (
                        <TableRow key={i} className="hover:bg-muted/30 cursor-pointer" onClick={() => navigate(`/remediate?search=${encodeURIComponent(findingName)}`)}>
                          <TableCell className="py-2.5">
                            <p className="text-xs font-medium truncate max-w-[200px]">
                              {findingName}
                            </p>
                            <p className="text-[10px] text-muted-foreground truncate">
                              {String(item.component ?? item.app_name ?? "")}
                            </p>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <Badge
                              variant="outline"
                              className={cn(
                                "text-[10px] capitalize",
                                String(item.severity) === "critical" && "border-red-500/30 text-red-400",
                                String(item.severity) === "high" && "border-orange-500/30 text-orange-400",
                                String(item.severity) === "medium" && "border-yellow-500/30 text-yellow-400",
                              )}
                            >
                              {String(item.severity ?? "unknown")}
                            </Badge>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <span className="text-xs text-muted-foreground">
                              {String(item.assigned_team ?? item.team ?? "—")}
                            </span>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <div className="flex items-center gap-1.5">
                              <Timer className={cn(
                                "h-3.5 w-3.5",
                                hoursLeft <= 4 ? "text-red-400" : hoursLeft <= 24 ? "text-yellow-400" : "text-muted-foreground"
                              )} />
                              <span className={cn(
                                "text-xs font-mono font-bold tabular-nums",
                                hoursLeft <= 4 ? "text-red-400" : hoursLeft <= 24 ? "text-yellow-400" : "text-foreground"
                              )}>
                                {displayTime}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="py-2.5">
                            <UrgencyBadge hoursLeft={hoursLeft} />
                          </TableCell>
                          <TableCell className="py-2.5 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 px-2 text-[10px] gap-1"
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/discover?search=${encodeURIComponent(findingName)}`);
                              }}
                            >
                              <ExternalLink className="h-3 w-3" /> View
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
                </div>
              </ScrollArea>
            ) : (
              <div className="flex h-[120px] items-center justify-center gap-3 text-sm text-green-400">
                <CheckCircle2 className="h-5 w-5" />
                No items approaching SLA breach — all on track
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
