import { useState, useEffect, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Shield,
  AlertTriangle,
  Activity,
  Clock,
  TrendingUp,
  TrendingDown,
  Zap,
  CheckCircle2,
  XCircle,
  RefreshCw,
  ChevronRight,
  Bot,
  Lock,
  Server,
  Globe,
  Filter,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { dashboardApi, nerveCenterApi } from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// ─── Mock Data ───────────────────────────────────────────────────────────────

const MOCK_POSTURE_TREND = [
  { date: "Mar 01", score: 68, critical: 12 },
  { date: "Mar 03", score: 71, critical: 10 },
  { date: "Mar 05", score: 69, critical: 11 },
  { date: "Mar 07", score: 74, critical: 8 },
  { date: "Mar 09", score: 72, critical: 9 },
  { date: "Mar 11", score: 76, critical: 7 },
  { date: "Mar 13", score: 78, critical: 6 },
  { date: "Mar 15", score: 75, critical: 8 },
  { date: "Mar 17", score: 80, critical: 5 },
  { date: "Mar 19", score: 82, critical: 4 },
  { date: "Mar 21", score: 79, critical: 6 },
  { date: "Mar 23", score: 84, critical: 3 },
];

const MOCK_THREATS = [
  { id: "THR-2841", title: "Critical RCE in Apache Tomcat 9.x", cve: "CVE-2024-50379", severity: "critical", app: "payments-gateway-prod", score: 9.8, age: "2h" },
  { id: "THR-2840", title: "SQL Injection in auth endpoint /api/v2/login", cve: "CVE-2024-49138", severity: "critical", app: "identity-service", score: 9.1, age: "5h" },
  { id: "THR-2839", title: "Privilege Escalation via sudo misconfiguration", cve: "CVE-2024-48990", severity: "high", app: "k8s-worker-node-07", score: 7.8, age: "8h" },
  { id: "THR-2838", title: "OpenSSL Memory Corruption", cve: "CVE-2024-45768", severity: "high", app: "data-pipeline-service", score: 7.5, age: "12h" },
  { id: "THR-2837", title: "Exposed S3 bucket with PII data", cve: "ALDECI-SEC-0441", severity: "critical", app: "customer-data-lake", score: 9.4, age: "14h" },
];

const MOCK_PRIORITY_QUEUE = [
  { id: "PQ-001", title: "payments-gateway: 3 critical CVEs unpatched", team: "Platform Eng", due: "2h", severity: "critical" },
  { id: "PQ-002", title: "identity-service: Auth bypass requires emergency patch", team: "Security", due: "4h", severity: "critical" },
  { id: "PQ-003", title: "SLA breach imminent: 12 high-severity aging >72h", team: "AppSec", due: "6h", severity: "high" },
  { id: "PQ-004", title: "SOC2 audit evidence gap: 8 controls missing proof", team: "Compliance", due: "1d", severity: "high" },
  { id: "PQ-005", title: "customer-data-lake: S3 ACL policy regression", team: "Cloud Ops", due: "1d", severity: "high" },
];

const MOCK_COMPLIANCE = [
  { framework: "SOC 2 Type II", status: "passing", controls: 214, passing: 198, failing: 8, waived: 8 },
  { framework: "PCI DSS 4.0", status: "warning", controls: 156, passing: 140, failing: 12, waived: 4 },
  { framework: "ISO 27001:2022", status: "passing", controls: 93, passing: 89, failing: 4, waived: 0 },
  { framework: "HIPAA", status: "passing", controls: 54, passing: 51, failing: 3, waived: 0 },
  { framework: "NIST CSF 2.0", status: "warning", controls: 108, passing: 94, failing: 14, waived: 0 },
  { framework: "CIS Controls v8", status: "passing", controls: 153, passing: 146, failing: 7, waived: 0 },
];

const MOCK_ACTIVITY = [
  { id: 1, type: "finding", icon: AlertTriangle, text: "New critical finding THR-2841 ingested from Tenable.io", time: "2m ago", color: "text-red-400" },
  { id: 2, type: "decision", icon: CheckCircle2, text: "AI auto-triaged 47 low-severity findings as noise (FP score > 0.92)", time: "8m ago", color: "text-green-400" },
  { id: 3, type: "deployment", icon: Zap, text: "Autofix deployed for CVE-2024-44082 on payments-gateway-prod", time: "15m ago", color: "text-primary" },
  { id: 4, type: "policy", icon: Lock, text: "Policy 'S3-encryption-at-rest' updated by admin@aldeci.io", time: "32m ago", color: "text-yellow-400" },
  { id: 5, type: "scan", icon: Server, text: "Scheduled scan completed: 3,412 assets scanned, 18 new findings", time: "1h ago", color: "text-blue-400" },
  { id: 6, type: "mpte", icon: Bot, text: "MPTE consensus reached: CVE-2024-48990 severity downgraded to Medium", time: "1h 20m ago", color: "text-purple-400" },
  { id: 7, type: "finding", icon: Globe, text: "External threat intel: TA558 group targeting Apache Tomcat deployments", time: "2h ago", color: "text-orange-400" },
  { id: 8, type: "compliance", icon: CheckCircle2, text: "SOC2 CC6.1 evidence auto-collected and verified for March cycle", time: "3h ago", color: "text-green-400" },
];

const MOCK_AI_SUMMARY = `Overnight analysis identified 3 high-priority attack surface expansions. The payments-gateway cluster shows active exploitation attempts against CVE-2024-50379 (CVSS 9.8) — immediate patching recommended. identity-service auth endpoint anomaly detected at 02:14 UTC with 14 failed auth bypass probes from IP range 185.220.x.x (known Tor exit nodes). Data pipeline services show OpenSSL 1.1.1 still in use across 7 containers — EOL risk. AI models suppressed 231 false positives overnight, saving approximately 4.6 engineering hours.`;

// ─── SVG Posture Gauge ────────────────────────────────────────────────────────

function PostureGauge({ score }: { score: number }) {
  const radius = 80;
  const stroke = 12;
  const cx = 100;
  const cy = 100;
  const startAngle = -220;
  const endAngle = 40;
  const totalAngle = endAngle - startAngle;
  const scoreAngle = startAngle + (score / 100) * totalAngle;

  const polarToXY = (angle: number, r: number) => {
    const rad = (angle * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  };

  const describeArc = (from: number, to: number) => {
    const start = polarToXY(from, radius);
    const end = polarToXY(to, radius);
    const large = to - from > 180 ? 1 : 0;
    return `M ${start.x} ${start.y} A ${radius} ${radius} 0 ${large} 1 ${end.x} ${end.y}`;
  };

  const scoreColor = score >= 80 ? "#34d399" : score >= 60 ? "#fbbf24" : "#f87171";
  const needle = polarToXY(scoreAngle, radius - 6);

  return (
    <svg viewBox="0 0 200 160" className="w-full max-w-[200px]">
      {/* Track */}
      <path d={describeArc(startAngle, endAngle)} fill="none" stroke="hsl(var(--muted))" strokeWidth={stroke} strokeLinecap="round" />
      {/* Fill */}
      <motion.path
        d={describeArc(startAngle, scoreAngle)}
        fill="none"
        stroke={scoreColor}
        strokeWidth={stroke}
        strokeLinecap="round"
        initial={{ pathLength: 0 }}
        animate={{ pathLength: 1 }}
        transition={{ duration: 1.4, ease: "easeOut" }}
      />
      {/* Needle dot */}
      <motion.circle
        cx={needle.x}
        cy={needle.y}
        r={6}
        fill={scoreColor}
        initial={{ opacity: 0, scale: 0 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 1.3, duration: 0.3 }}
      />
      {/* Center score */}
      <text x={cx} y={cy + 8} textAnchor="middle" className="fill-foreground" style={{ fontSize: 28, fontWeight: 700 }}>
        {score}
      </text>
      <text x={cx} y={cy + 26} textAnchor="middle" style={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}>
        POSTURE SCORE
      </text>
    </svg>
  );
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function CommandDashboard() {
  const [timeRange, setTimeRange] = useState("24h");
  const [liveRefresh, setLiveRefresh] = useState(true);
  const [tick, setTick] = useState(0);

  const { data: dashData, refetch: refetchDash } = useQuery({
    queryKey: ["dashboard-summary", timeRange],
    queryFn: () => dashboardApi.summary(),
    retry: false,
  });

  const { data: nerveCenterData, refetch: refetchNerve } = useQuery({
    queryKey: ["nerve-center-metrics"],
    queryFn: () => nerveCenterApi.metrics(),
    retry: false,
  });

  const refresh = useCallback(() => {
    refetchDash();
    refetchNerve();
    setTick((t) => t + 1);
    toast.success("Dashboard refreshed");
  }, [refetchDash, refetchNerve]);

  useEffect(() => {
    if (!liveRefresh) return;
    const id = setInterval(() => setTick((t) => t + 1), 30_000);
    return () => clearInterval(id);
  }, [liveRefresh]);

  const postureScore = (dashData as { data?: { posture_score?: number } })?.data?.posture_score ?? 84;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* Header */}
      <PageHeader
        title="Command Dashboard"
        description="Unified security posture, threat prioritization, and operational health"
        badge="LIVE"
        actions={
          <div className="flex items-center gap-2">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-[130px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="24h">Last 24h</SelectItem>
                <SelectItem value="7d">Last 7 days</SelectItem>
                <SelectItem value="30d">Last 30 days</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={liveRefresh ? "default" : "outline"}
              size="sm"
              onClick={() => setLiveRefresh((v) => !v)}
              className="gap-1.5"
            >
              <Activity className={cn("h-3.5 w-3.5", liveRefresh && "animate-pulse")} />
              {liveRefresh ? "Live" : "Paused"}
            </Button>
            <Button variant="outline" size="sm" onClick={refresh} className="gap-1.5">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="MTTR (Critical)" value="4.2h" change={-18} changeLabel="vs last period" trend="up" icon={Clock} />
        <KpiCard title="SLA Compliance" value="94.1%" change={2.3} changeLabel="vs last period" trend="up" icon={CheckCircle2} />
        <KpiCard title="Noise Reduction" value="89%" change={5} changeLabel="AI suppression" trend="up" icon={TrendingUp} />
        <KpiCard title="False Positive Rate" value="3.2%" change={-1.1} changeLabel="vs last period" trend="up" icon={Filter} />
      </div>

      {/* Top row: Gauge + Priority Queue + Compliance */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {/* Posture Gauge */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Security Posture
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 flex flex-col items-center gap-4">
            <PostureGauge score={postureScore} />
            <div className="w-full grid grid-cols-3 gap-2 text-center">
              {[{ label: "Critical", val: 4, color: "text-red-400" }, { label: "High", val: 22, color: "text-orange-400" }, { label: "Open", val: 187, color: "text-muted-foreground" }].map((s) => (
                <div key={s.label}>
                  <p className={cn("text-lg font-bold tabular-nums", s.color)}>{s.val}</p>
                  <p className="text-xs text-muted-foreground">{s.label}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Priority Queue */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
              Priority Queue
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-2">
            {MOCK_PRIORITY_QUEUE.map((item) => (
              <div
                key={item.id}
                className="flex items-start gap-2 rounded-md p-2 hover:bg-muted/40 transition-colors cursor-pointer group"
              >
                <div className={cn("mt-0.5 h-2 w-2 rounded-full shrink-0", item.severity === "critical" ? "bg-red-500" : "bg-orange-500")} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium truncate">{item.title}</p>
                  <p className="text-xs text-muted-foreground">{item.team} · Due in {item.due}</p>
                </div>
                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Compliance Status */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-primary" />
              Compliance Status
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-2.5">
            {MOCK_COMPLIANCE.map((fw) => {
              const pct = Math.round((fw.passing / fw.controls) * 100);
              return (
                <div key={fw.framework} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium">{fw.framework}</span>
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-muted-foreground tabular-nums">{pct}%</span>
                      {fw.status === "passing" ? (
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                      ) : (
                        <AlertTriangle className="h-3 w-3 text-yellow-400" />
                      )}
                    </div>
                  </div>
                  <div className="h-1.5 rounded-full bg-muted overflow-hidden">
                    <motion.div
                      className={cn("h-full rounded-full", fw.status === "passing" ? "bg-green-500" : "bg-yellow-500")}
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                    />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>
      </div>

      {/* Middle row: Threats + AI Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top Threats */}
        <div className="lg:col-span-2">
          <Card className="p-5">
            <CardHeader className="p-0 pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Zap className="h-4 w-4 text-red-400" />
                Top Threats
                <Badge variant="destructive" className="ml-auto text-xs">{MOCK_THREATS.filter((t) => t.severity === "critical").length} Critical</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0 space-y-2">
              {MOCK_THREATS.map((t, i) => (
                <motion.div
                  key={t.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.06 }}
                  className="flex items-center gap-3 rounded-md border border-border/40 p-3 hover:bg-muted/30 transition-colors cursor-pointer"
                >
                  <div className={cn("text-xs font-bold tabular-nums w-10 shrink-0", t.score >= 9 ? "text-red-400" : "text-orange-400")}>
                    {t.score}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate">{t.title}</p>
                    <p className="text-xs text-muted-foreground">{t.cve} · {t.app}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge variant={t.severity === "critical" ? "critical" : "high"} className="text-xs">{t.severity}</Badge>
                    <span className="text-xs text-muted-foreground">{t.age}</span>
                  </div>
                </motion.div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* AI Summary */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" />
              AI Overnight Summary
              <Badge variant="secondary" className="ml-auto text-xs">GPT-4o</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <p className="text-xs text-muted-foreground leading-relaxed">{MOCK_AI_SUMMARY}</p>
            <div className="mt-3 space-y-2">
              {[
                { label: "FPs suppressed", val: "231", icon: XCircle, color: "text-green-400" },
                { label: "Eng. hours saved", val: "4.6h", icon: Clock, color: "text-primary" },
                { label: "Auto-resolved", val: "18", icon: CheckCircle2, color: "text-green-400" },
              ].map((s) => (
                <div key={s.label} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <s.icon className={cn("h-3 w-3", s.color)} />
                    <span className="text-muted-foreground">{s.label}</span>
                  </div>
                  <span className="font-semibold tabular-nums">{s.val}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Posture Trend Chart */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-4">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-primary" />
            Posture Score Trend — {timeRange === "24h" ? "Last 24 Hours" : timeRange === "7d" ? "Last 7 Days" : "Last 30 Days"}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0 h-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={MOCK_POSTURE_TREND} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#14b8a6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#14b8a6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f87171" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f87171" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.3)" />
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                labelStyle={{ color: "hsl(var(--foreground))", fontWeight: 600 }}
              />
              <Area type="monotone" dataKey="score" name="Posture Score" stroke="#14b8a6" fill="url(#scoreGrad)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="critical" name="Critical Findings" stroke="#f87171" fill="url(#critGrad)" strokeWidth={1.5} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Activity Timeline */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            Activity Timeline
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="space-y-0">
            <AnimatePresence>
              {MOCK_ACTIVITY.map((event, i) => (
                <motion.div
                  key={`${event.id}-${tick}`}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="flex items-start gap-3 py-2.5 border-b border-border/30 last:border-0 hover:bg-muted/20 rounded-sm px-1 transition-colors"
                >
                  <div className={cn("mt-0.5 rounded-md p-1 bg-muted/50", event.color)}>
                    <event.icon className="h-3.5 w-3.5" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs">{event.text}</p>
                  </div>
                  <span className="text-xs text-muted-foreground shrink-0 tabular-nums">{event.time}</span>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
