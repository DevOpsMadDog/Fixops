import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
  BarChart, Bar, Cell,
} from "recharts";
import {
  Shield, AlertTriangle, Activity, Clock, CheckCircle2,
  RefreshCw, Filter,
  Zap, Radio, BrainCircuit, AlertCircle,
  BarChart3, Target, Timer, Wrench, Bell, Eye,
  XCircle, Circle, TrendingDown, Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip as UITooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useDashboardOverview,
  useNervePulse,
  useDashboardTrends,
  useDashboardCompliance,
  useIngestStats,
} from "@/hooks/use-api";
import { analyticsApi, scannerIngestApi } from "@/lib/api";
import { cn } from "@/lib/utils";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

const CHART_TOOLTIP_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 12,
};

function PostureGauge({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 80 ? "#22c55e" : pct >= 60 ? "#eab308" : "#ef4444";
  const label = pct >= 80 ? "Strong" : pct >= 60 ? "Moderate" : "Critical";
  // SVG arc gauge
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
    <div className="flex flex-col items-center justify-center gap-1">
      <svg width={144} height={110} viewBox="0 0 144 110">
        <path d={arcPath(startAngle, endAngle)} fill="none" stroke="hsl(var(--border))" strokeWidth={10} strokeLinecap="round" />
        <path d={arcPath(startAngle, fillAngle)} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round" />
        <text x={cx} y={cy + 10} textAnchor="middle" fill={color} fontSize={26} fontWeight="bold" fontFamily="inherit">
          {pct}
        </text>
        <text x={cx} y={cy + 26} textAnchor="middle" fill="hsl(var(--muted-foreground))" fontSize={11} fontFamily="inherit">
          {label}
        </text>
      </svg>
      <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Posture Score</p>
    </div>
  );
}

function SeverityPill({ severity, count, isNew, onClick }: { severity: string; count: number; isNew?: boolean; onClick?: () => void }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500/10 text-red-400 border-red-500/20 hover:bg-red-500/20",
    high: "bg-orange-500/10 text-orange-400 border-orange-500/20 hover:bg-orange-500/20",
    medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20 hover:bg-yellow-500/20",
    low: "bg-green-500/10 text-green-400 border-green-500/20 hover:bg-green-500/20",
  };
  return (
    <div
      className={cn("flex items-center justify-between rounded-lg border px-3 py-2 cursor-pointer transition-colors", colors[severity] ?? "bg-muted/10 border-border text-muted-foreground")}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === "Enter" && onClick?.()}
    >
      <div className="flex items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide">{severity}</span>
        {isNew && <Badge className="h-4 text-[10px] px-1 bg-blue-500/20 text-blue-400 border-blue-500/30">NEW</Badge>}
      </div>
      <span className="text-lg font-bold tabular-nums">{count}</span>
    </div>
  );
}

function ComplianceBadge({ name, status, onClick }: { name: string; status: string; onClick?: () => void }) {
  const ok = status === "compliant" || status === "passing" || status === "active";
  return (
    <div
      className={cn(
        "flex flex-col items-center gap-1.5 rounded-xl border p-3 transition-all cursor-pointer",
        ok ? "border-green-500/30 bg-green-500/5 hover:bg-green-500/10" : "border-yellow-500/30 bg-yellow-500/5 hover:bg-yellow-500/10"
      )}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === "Enter" && onClick?.()}
    >
      {ok
        ? <CheckCircle2 className="h-5 w-5 text-green-400" />
        : <AlertCircle className="h-5 w-5 text-yellow-400" />
      }
      <span className="text-[11px] font-semibold tracking-wider uppercase">{name}</span>
      <span className={cn("text-[10px] capitalize", ok ? "text-green-400" : "text-yellow-400")}>{status}</span>
    </div>
  );
}

function EventTypeBadge({ type }: { type: string }) {
  const map: Record<string, { label: string; className: string }> = {
    finding: { label: "Finding", className: "bg-red-500/10 text-red-400 border-red-500/20" },
    decision: { label: "Decision", className: "bg-purple-500/10 text-purple-400 border-purple-500/20" },
    deployment: { label: "Deploy", className: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
    policy: { label: "Policy", className: "bg-gray-500/10 text-gray-400 border-gray-500/20" },
    mpte: { label: "MPTE", className: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20" },
    fix: { label: "Fix", className: "bg-green-500/10 text-green-400 border-green-500/20" },
  };
  const cfg = map[type?.toLowerCase()] ?? { label: type, className: "bg-muted/10 text-muted-foreground border-border" };
  return <Badge className={cn("text-[10px] px-1.5 py-0 h-4 border font-medium", cfg.className)}>{cfg.label}</Badge>;
}

export default function CommandDashboard() {
  const navigate = useNavigate();
  const [timeRange, setTimeRange] = useState("30d");
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [eventFilter, setEventFilter] = useState("all");
  const [lastRefreshed, setLastRefreshed] = useState(new Date());

  const overview = useDashboardOverview();
  const pulse = useNervePulse();
  const trends = useDashboardTrends({ period: timeRange });
  const compliance = useDashboardCompliance();
  const ingestStats = useIngestStats();

  // ── Noise Reduction Funnel (real data from /analytics/triage-funnel) ──
  const funnelQuery = useQuery({
    queryKey: ["analytics", "triage-funnel"],
    queryFn: async () => {
      const { data } = await analyticsApi.triageFunnel();
      return data;
    },
    staleTime: 60_000,
  });

  const isLoading = overview.isLoading;
  const isError = overview.isError;

  const refetch = useCallback(() => {
    overview.refetch();
    pulse.refetch();
    trends.refetch();
    compliance.refetch();
    funnelQuery.refetch();
    setLastRefreshed(new Date());
  }, [overview, pulse, trends, compliance, funnelQuery]);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(refetch, 30_000);
    return () => clearInterval(interval);
  }, [autoRefresh, refetch]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load dashboard data" onRetry={refetch} />;

  const ov = overview.data ?? {};
  const pulseData = pulse.data ?? {};
  const trendData = trends.data ?? {};
  const compData = compliance.data ?? {};
  const funnelData = funnelQuery.data ?? {};

  const postureScore = Number(ov.posture_score ?? ov.security_score ?? 0);
  const activeThreats = Number(ov.active_threats ?? ov.critical_findings ?? 0);
  const mttr = Number(ov.mttr_hours ?? ov.avg_resolution_hours ?? 0);
  const slaCompliance = Number(ov.sla_compliance_pct ?? compData.compliance_score ?? 0);
  const noiseReductionFromFunnel = Number(funnelData.reduction_percentage ?? 0);
  const noiseReduction = noiseReductionFromFunnel > 0 ? noiseReductionFromFunnel : Number(ov.noise_reduction_pct ?? pulseData.noise_reduction ?? 0);
  const fixesToday = Number(ov.fixes_today ?? ov.resolved_today ?? 0);

  // Funnel stages
  const funnel = funnelData.funnel ?? {};
  const funnelStages = [
    { label: "Raw Findings", value: Number(funnel.raw_findings ?? 0), color: "#ef4444" },
    { label: "After Dedup", value: Number(funnel.after_dedup ?? 0), color: "#f97316" },
    { label: "After Correlation", value: Number(funnel.after_correlation ?? 0), color: "#eab308" },
    { label: "Exposure Cases", value: Number(funnel.exposure_cases ?? 0), color: "#22c55e" },
  ];
  const funnelHasData = funnelData.data_available === true || Number(funnel.raw_findings ?? 0) > 0;
  const failDist = funnelData.fail_distribution ?? {};

  const criticalCount = Number(ov.critical_findings ?? 0);
  const highCount = Number(ov.high_findings ?? 0);
  const mediumCount = Number(ov.medium_findings ?? 0);

  // Chart data from trend series
  const chartData = (trendData.series ?? []).map((s: Record<string, unknown>) => ({
    date: String(s.period ?? s.date ?? ""),
    critical: Number(s.critical ?? 0),
    high: Number(s.high ?? 0),
    medium: Number(s.medium ?? 0),
    low: Number(s.low ?? 0),
  }));

  // Top threats from risks
  const topThreats = (trendData.top_cves ?? ov.top_risks ?? []).slice(0, 8);

  // Activity timeline from pulse events
  const allEvents = (pulseData.events ?? pulseData.recent_events ?? []);
  const filteredEvents = allEvents.filter((e: Record<string, unknown>) =>
    eventFilter === "all" || String(e.type ?? "").toLowerCase() === eventFilter
  );

  // Compliance frameworks
  const frameworks = [
    { name: "SOC 2", status: compData.soc2_status ?? compData.soc2 ?? "pending" },
    { name: "PCI-DSS", status: compData.pci_status ?? compData.pci ?? "pending" },
    { name: "HIPAA", status: compData.hipaa_status ?? compData.hipaa ?? "pending" },
    { name: "ISO 27001", status: compData.iso_status ?? compData.iso27001 ?? "pending" },
  ];

  // AI overnight summary
  const aiSummary = pulseData.ai_summary ?? ov.overnight_summary ?? pulseData.summary ?? "";

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
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
          title="Command Dashboard"
          description="Real-time security posture overview, threat intelligence, and compliance status"
          badge="LIVE"
          actions={
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <Radio className={cn("h-3.5 w-3.5", autoRefresh ? "text-green-400 animate-pulse" : "text-muted-foreground")} />
                <span className="text-xs text-muted-foreground hidden sm:block">Auto-refresh</span>
                <Switch checked={autoRefresh} onCheckedChange={setAutoRefresh} />
              </div>
              <Select value={timeRange} onValueChange={setTimeRange}>
                <SelectTrigger className="w-[110px] h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="24h">Last 24h</SelectItem>
                  <SelectItem value="7d">Last 7d</SelectItem>
                  <SelectItem value="30d">Last 30d</SelectItem>
                </SelectContent>
              </Select>
              <UITooltip>
                <TooltipTrigger asChild>
                  <Button variant="outline" size="sm" onClick={refetch}>
                    <RefreshCw className="h-4 w-4" />
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  <p className="text-xs">Last refreshed: {lastRefreshed.toLocaleTimeString()}</p>
                </TooltipContent>
              </UITooltip>
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
          {/* Posture Score Gauge — spans 2 */}
          <motion.div variants={itemVariants} className="col-span-2 sm:col-span-1 lg:col-span-2">
            <Card className="h-full flex items-center justify-center p-4">
              <PostureGauge score={postureScore} />
            </Card>
          </motion.div>

          <motion.div variants={itemVariants}>
            <KpiCard
              title="Active Threats"
              value={activeThreats}
              icon={AlertTriangle}         trend={activeThreats > 10 ? "up" : activeThreats > 0 ? "flat" : "down"}
              className={cn(activeThreats > 5 && "border-red-500/30 bg-red-500/5")}
              onClick={() => navigate("/discover?severity=critical")}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="MTTR (hours)"
              value={mttr > 0 ? `${mttr.toFixed(1)}h` : "—"}
              icon={Timer}         trend={mttr < 24 ? "up" : mttr < 72 ? "flat" : "down"}
              onClick={() => navigate("/remediate?status=in_progress")}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="SLA Compliance"
              value={`${slaCompliance.toFixed(0)}%`}
              icon={Target}         trend={slaCompliance >= 95 ? "up" : slaCompliance >= 80 ? "flat" : "down"}
              onClick={() => navigate("/comply")}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="Noise Reduction"
              value={`${noiseReduction.toFixed(0)}%`}
              icon={Zap}         trend={noiseReduction > 50 ? "up" : "flat"}
              onClick={() => navigate("/discover?status=suppressed")}
            />
          </motion.div>
          <motion.div variants={itemVariants}>
            <KpiCard
              title="Fixes Today"
              value={fixesToday}
              icon={Wrench}         trend={fixesToday > 0 ? "up" : "flat"}
              onClick={() => navigate("/remediate?status=resolved")}
            />
          </motion.div>
        </motion.div>

        {/* Main 3-column layout */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* Left column: Priority Queue + Compliance */}
          <div className="flex flex-col gap-4">
            {/* Priority Queue */}
            <motion.div initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.15 }}>
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Bell className="h-4 w-4 text-orange-400" />
                      Priority Queue
                    </CardTitle>
                    <Badge variant="outline" className="text-[10px]">
                      {criticalCount + highCount + mediumCount} Total
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2">
                  <SeverityPill
                    severity="critical"
                    count={criticalCount}
                    isNew={(criticalCount > 0)}
                    onClick={() => navigate("/discover?severity=critical")}
                  />
                  <SeverityPill
                    severity="high"
                    count={highCount}
                    isNew={(highCount > 0)}
                    onClick={() => navigate("/discover?severity=high")}
                  />
                  <SeverityPill
                    severity="medium"
                    count={mediumCount}
                    onClick={() => navigate("/discover?severity=medium")}
                  />
                  <SeverityPill
                    severity="low"
                    count={Number(ov.low_findings ?? 0)}
                    onClick={() => navigate("/discover?severity=low")}
                  />
                  <Separator className="my-3" />
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>Open findings</span>
                    <span className="font-semibold text-foreground tabular-nums">{ov.open_findings ?? 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>Fixes today</span>
                    <span className="font-semibold text-green-400 tabular-nums">{fixesToday}</span>
                  </div>
                </CardContent>
              </Card>
            </motion.div>

            {/* Compliance Status */}
            <motion.div initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.25 }}>
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Shield className="h-4 w-4 text-blue-400" />
                    Compliance Status
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-2">
                    {frameworks.map((fw) => (
                      <ComplianceBadge key={fw.name} name={fw.name} status={String(fw.status)} onClick={() => navigate(`/comply?framework=${encodeURIComponent(fw.name)}`)} />
                    ))}
                  </div>
                  {compData.last_assessed && (
                    <p className="text-[10px] text-muted-foreground mt-3 text-center">
                      Last assessed: {new Date(compData.last_assessed).toLocaleDateString()}
                    </p>
                  )}
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Center column: Finding Trends chart + AI Summary */}
          <div className="flex flex-col gap-4">
            {/* Finding Trends AreaChart */}
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <BarChart3 className="h-4 w-4 text-purple-400" />
                      Finding Trends
                    </CardTitle>
                    <span className="text-[10px] text-muted-foreground bg-muted/30 px-2 py-0.5 rounded-full">
                      {timeRange}
                    </span>
                  </div>
                </CardHeader>
                <CardContent>
                  {chartData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={200}>
                      <AreaChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                        <defs>
                          <linearGradient id="gradCrit" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
                          </linearGradient>
                          <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#f97316" stopOpacity={0.2} />
                            <stop offset="95%" stopColor="#f97316" stopOpacity={0.02} />
                          </linearGradient>
                          <linearGradient id="gradMed" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#eab308" stopOpacity={0.15} />
                            <stop offset="95%" stopColor="#eab308" stopOpacity={0.02} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} />
                        <XAxis dataKey="date" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} />
                        <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" tickLine={false} axisLine={false} />
                        <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                        <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                        <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="url(#gradCrit)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="url(#gradHigh)" strokeWidth={1.5} />
                        <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="url(#gradMed)" strokeWidth={1.5} />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex h-[200px] items-center justify-center text-sm text-muted-foreground">
                      No trend data — run a scan to populate
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>

            {/* Noise Reduction Funnel */}
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
              <Card className="border-emerald-500/20 bg-emerald-500/5">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2 text-emerald-400">
                      <TrendingDown className="h-4 w-4" />
                      Noise Reduction Funnel
                    </CardTitle>
                    {noiseReduction > 0 && (
                      <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px]">
                        {noiseReduction.toFixed(0)}% reduced
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  {funnelHasData ? (
                    <div className="space-y-3">
                      {/* Funnel bars */}
                      <div className="space-y-2">
                        {funnelStages.map((stage, i) => {
                          const maxVal = funnelStages[0].value || 1;
                          const pct = maxVal > 0 ? (stage.value / maxVal) * 100 : 0;
                          const prevVal = i > 0 ? funnelStages[i - 1].value : stage.value;
                          const reduction = prevVal > 0 && i > 0 ? Math.round(((prevVal - stage.value) / prevVal) * 100) : 0;
                          return (
                            <div key={stage.label} className="space-y-1">
                              <div className="flex items-center justify-between text-xs">
                                <span className="text-muted-foreground">{stage.label}</span>
                                <div className="flex items-center gap-2">
                                  <span className="font-mono font-semibold tabular-nums" style={{ color: stage.color }}>
                                    {stage.value.toLocaleString()}
                                  </span>
                                  {reduction > 0 && (
                                    <span className="text-[10px] text-emerald-400">-{reduction}%</span>
                                  )}
                                </div>
                              </div>
                              <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                                <motion.div
                                  className="h-full rounded-full"
                                  style={{ backgroundColor: stage.color }}
                                  initial={{ width: 0 }}
                                  animate={{ width: `${Math.max(pct, 2)}%` }}
                                  transition={{ duration: 0.6, delay: i * 0.1 }}
                                />
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      {/* FAIL distribution mini-bar */}
                      {(Number(failDist.critical ?? 0) + Number(failDist.high ?? 0) + Number(failDist.medium ?? 0)) > 0 && (
                        <div className="pt-2 border-t border-border/50">
                          <p className="text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider font-semibold">
                            <Layers className="inline h-3 w-3 mr-1" />
                            Severity Distribution (Exposure Cases)
                          </p>
                          <div className="flex gap-3 text-xs">
                            {["critical", "high", "medium", "low"].map(sev => {
                              const count = Number(failDist[sev] ?? 0);
                              if (count === 0) return null;
                              return (
                                <span
                                  key={sev}
                                  className="cursor-pointer hover:opacity-80"
                                  style={{ color: SEVERITY_COLORS[sev] }}
                                  onClick={() => navigate(`/discover?severity=${sev}`)}
                                  role="button"
                                  tabIndex={0}
                                  onKeyDown={(e) => e.key === "Enter" && navigate(`/discover?severity=${sev}`)}
                                >
                                  <span className="font-semibold tabular-nums">{count}</span>{" "}
                                  <span className="capitalize">{sev}</span>
                                </span>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="flex h-[120px] items-center justify-center text-sm text-muted-foreground">
                      No funnel data — run the Brain Pipeline to populate
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>

            {/* AI Overnight Summary */}
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
              <Card className="border-purple-500/20 bg-purple-500/5">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
                    <BrainCircuit className="h-4 w-4" />
                    AI Overnight Summary
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {aiSummary ? (
                    <p className="text-sm text-muted-foreground leading-relaxed">{aiSummary}</p>
                  ) : (
                    <p className="text-sm text-muted-foreground italic">
                      No overnight summary available yet. The copilot will generate a summary after the next scheduled analysis run.
                    </p>
                  )}
                  {pulseData.summary_generated_at && (
                    <p className="text-[10px] text-muted-foreground mt-2">
                      Generated: {new Date(pulseData.summary_generated_at).toLocaleString()}
                    </p>
                  )}
                </CardContent>
              </Card>
            </motion.div>

            {/* Connected Scanners */}
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Radio className="h-4 w-4 text-green-400" />
                    Connected Scanners
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {(() => {
                    const stats = ingestStats.data as Record<string, unknown> | undefined;
                    const scanners = (stats?.scanners ?? stats?.parsers ?? stats?.supported ?? []) as Record<string, unknown>[];
                    const totalFindings = Number(stats?.total_findings ?? stats?.findings_count ?? 0);
                    const lastIngest = stats?.last_ingest_at as string | undefined;
                    const defaultScanners = [
                      { name: "Semgrep", type: "SAST" },
                      { name: "Trivy", type: "SCA/Container" },
                      { name: "Bandit", type: "SAST" },
                      { name: "Checkov", type: "IaC" },
                      { name: "Gitleaks", type: "Secrets" },
                      { name: "SonarQube", type: "SAST" },
                    ];
                    const items = scanners.length > 0
                      ? scanners.map(s => ({ name: String(s.name ?? s.scanner ?? "Unknown"), type: String(s.type ?? s.category ?? ""), active: s.active !== false }))
                      : defaultScanners.map(s => ({ ...s, active: totalFindings > 0 }));
                    return (
                      <div className="space-y-2">
                        <div className="grid grid-cols-2 gap-2">
                          {items.slice(0, 6).map((s) => (
                            <div key={s.name} className="flex items-center gap-2 text-xs py-1">
                              <Circle className={cn("h-2 w-2 shrink-0", s.active ? "fill-green-400 text-green-400" : "fill-slate-500 text-slate-500")} />
                              <span className="font-medium truncate">{s.name}</span>
                              {s.type && <span className="text-muted-foreground text-[10px] ml-auto">{s.type}</span>}
                            </div>
                          ))}
                        </div>
                        <Separator />
                        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>{totalFindings > 0 ? `${totalFindings.toLocaleString()} findings ingested` : "No findings ingested yet"}</span>
                          {lastIngest && <span>Last: {new Date(lastIngest).toLocaleDateString()}</span>}
                        </div>
                      </div>
                    );
                  })()}
                </CardContent>
              </Card>
            </motion.div>
          </div>

          {/* Right column: Top Threats + Activity Timeline */}
          <div className="flex flex-col gap-4">
            {/* Top Threats */}
            <motion.div initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.15 }}>
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Eye className="h-4 w-4 text-red-400" />
                      Top Threats
                    </CardTitle>
                    <Badge variant="destructive" className="text-[10px]">{topThreats.length} Active</Badge>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[200px]">
                    <div className="space-y-0 px-6 pb-4">
                      {topThreats.length > 0 ? topThreats.map((t: Record<string, unknown>, i: number) => (
                        <div
                          key={i}
                          className="flex items-center gap-3 py-2 border-b border-border/50 last:border-0 cursor-pointer hover:bg-muted/30 rounded px-1 -mx-1 transition-colors"
                          onClick={() => navigate(`/discover?search=${encodeURIComponent(String(t.cve_id ?? t.id ?? ""))}`)}
                          role="button"
                          tabIndex={0}
                          onKeyDown={(e) => e.key === "Enter" && navigate(`/discover?search=${encodeURIComponent(String(t.cve_id ?? t.id ?? ""))}`)}
                        >
                          <div
                            className="h-2 w-2 rounded-full shrink-0"
                            style={{ backgroundColor: SEVERITY_COLORS[String(t.severity ?? "medium")] }}
                          />
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-mono font-medium truncate">{String(t.cve_id ?? t.id ?? `CVE-${i}`)}</p>
                            <p className="text-[10px] text-muted-foreground truncate">{String(t.title ?? t.description ?? "")}</p>
                          </div>
                          <div className="flex flex-col items-end gap-1 shrink-0">
                            <Badge
                              variant="outline"
                              className={cn("text-[9px] h-4 px-1 capitalize", {
                                "border-red-500/30 text-red-400": String(t.severity) === "critical",
                                "border-orange-500/30 text-orange-400": String(t.severity) === "high",
                                "border-yellow-500/30 text-yellow-400": String(t.severity) === "medium",
                              })}
                            >
                              {String(t.severity ?? "med")}
                            </Badge>
                            {!!t.mpte_verified && (
                              <Badge className="text-[9px] h-4 px-1 bg-cyan-500/10 text-cyan-400 border-cyan-500/30">
                                MPTE ✓
                              </Badge>
                            )}
                          </div>
                        </div>
                      )) : (
                        <div className="flex h-[160px] items-center justify-center text-xs text-muted-foreground">
                          No active threats detected
                        </div>
                      )}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </motion.div>

            {/* Activity Timeline */}
            <motion.div initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.25 }}>
              <Card>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Activity className="h-4 w-4 text-blue-400" />
                      Activity Timeline
                    </CardTitle>
                    <Select value={eventFilter} onValueChange={setEventFilter}>
                      <SelectTrigger className="h-7 w-[100px] text-[11px]">
                        <Filter className="h-3 w-3 mr-1" />
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All</SelectItem>
                        <SelectItem value="finding">Findings</SelectItem>
                        <SelectItem value="decision">Decisions</SelectItem>
                        <SelectItem value="mpte">MPTE</SelectItem>
                        <SelectItem value="deployment">Deploys</SelectItem>
                        <SelectItem value="fix">Fixes</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <ScrollArea className="h-[220px]">
                    <div className="space-y-0 px-6 pb-4">
                      <AnimatePresence>
                        {filteredEvents.length > 0 ? filteredEvents.slice(0, 20).map((ev: Record<string, unknown>, i: number) => (
                          <motion.div
                            key={i}
                            initial={{ opacity: 0, x: 8 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ delay: i * 0.03 }}
                            className="flex items-start gap-3 py-2 border-b border-border/50 last:border-0"
                          >
                            <div className="mt-1 shrink-0">
                              <Circle className="h-1.5 w-1.5 fill-current text-muted-foreground" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 mb-0.5">
                                <EventTypeBadge type={String(ev.type ?? "")} />
                                <span className="text-[10px] text-muted-foreground">
                                  {ev.timestamp ? new Date(String(ev.timestamp)).toLocaleTimeString() : ""}
                                </span>
                              </div>
                              <p className="text-xs text-foreground/80 truncate">{String(ev.message ?? ev.description ?? "")}</p>
                              {!!ev.component && (
                                <p className="text-[10px] text-muted-foreground truncate">{String(ev.component)}</p>
                              )}
                            </div>
                          </motion.div>
                        )) : (
                          <div className="flex h-[160px] items-center justify-center text-xs text-muted-foreground">
                            No events for this filter
                          </div>
                        )}
                      </AnimatePresence>
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </motion.div>
          </div>
        </div>

        {/* Footer status bar */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.4 }}
          className="flex items-center justify-between rounded-lg border border-border/50 bg-muted/20 px-4 py-2 text-[11px] text-muted-foreground"
        >
          <div className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className={cn("h-2 w-2 rounded-full", autoRefresh ? "bg-green-400 animate-pulse" : "bg-gray-500")} />
              {autoRefresh ? "Live" : "Paused"}
            </span>
            <Separator orientation="vertical" className="h-3" />
            <span>Total findings: <span className="text-foreground font-medium">{ov.total_findings ?? 0}</span></span>
            <Separator orientation="vertical" className="h-3" />
            <span>MTTR: <span className="text-foreground font-medium">{mttr > 0 ? `${mttr.toFixed(1)}h` : "—"}</span></span>
            {noiseReduction > 0 && (
              <>
                <Separator orientation="vertical" className="h-3" />
                <span>Noise: <span className="text-emerald-400 font-medium">↓{noiseReduction.toFixed(0)}%</span></span>
              </>
            )}
          </div>
          <span>Updated: {lastRefreshed.toLocaleTimeString()}</span>
        </motion.div>
      </motion.div>
    </TooltipProvider>
  );
}
