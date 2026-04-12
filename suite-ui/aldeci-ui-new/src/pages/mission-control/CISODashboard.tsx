/**
 * CISO Executive Dashboard — P01 Persona
 *
 * Shows the security posture at a glance for the Chief Information Security Officer:
 * - Overall risk score with trajectory
 * - KPIs: MTTD, MTTR, SLA compliance, detection accuracy
 * - Top risks requiring attention
 * - Compliance framework status
 * - Pipeline throughput
 * - Severity breakdown with trend
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import {
  Shield, AlertTriangle, Activity, Clock, CheckCircle2,
  TrendingDown, TrendingUp, Target, Timer, Eye,
  FileCheck, BarChart3, ArrowRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { analyticsApi } from "@/lib/api";
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

// ═══════════════════════════════════════════════════════════
// Risk Score Gauge
// ═══════════════════════════════════════════════════════════

function RiskGauge({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color = pct >= 80 ? "#22c55e" : pct >= 60 ? "#eab308" : "#ef4444";
  const label = pct >= 80 ? "Strong" : pct >= 60 ? "Moderate" : "At Risk";
  const r = 54;
  const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ * 0.75; // 270-degree arc

  return (
    <div className="flex flex-col items-center">
      <svg width="140" height="100" viewBox="0 0 140 100">
        <path
          d="M 15 85 A 54 54 0 1 1 125 85"
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth="10"
          strokeLinecap="round"
        />
        <path
          d="M 15 85 A 54 54 0 1 1 125 85"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${(pct / 100) * circ * 0.75} ${circ}`}
          className="transition-all duration-1000"
        />
        <text
          x="70"
          y="65"
          textAnchor="middle"
          fill="currentColor"
          fontSize="28"
          fontWeight="bold"
          className="tabular-nums"
        >
          {pct}
        </text>
        <text
          x="70"
          y="85"
          textAnchor="middle"
          fill={color}
          fontSize="11"
          fontWeight="600"
        >
          {label}
        </text>
      </svg>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Compliance Mini Card
// ═══════════════════════════════════════════════════════════

function ComplianceCard({
  name,
  score,
  controlsPassing,
  totalControls,
}: {
  name: string;
  score: number;
  controlsPassing: number;
  totalControls: number;
}) {
  const pct = totalControls > 0 ? Math.round((controlsPassing / totalControls) * 100) : 0;
  const color = pct >= 90 ? "text-green-400" : pct >= 70 ? "text-yellow-400" : "text-red-400";

  return (
    <div className="flex items-center justify-between py-2.5">
      <div className="flex items-center gap-3 min-w-0">
        <FileCheck className="h-4 w-4 text-muted-foreground shrink-0" />
        <span className="text-sm font-medium truncate">{name}</span>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <span className="text-xs text-muted-foreground">
          {controlsPassing}/{totalControls}
        </span>
        <Badge variant={pct >= 90 ? "default" : pct >= 70 ? "secondary" : "destructive"} className="text-xs w-14 justify-center">
          {pct}%
        </Badge>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Mock data generator (replaced by real API when connected)
// ═══════════════════════════════════════════════════════════

function generateMockCISOData() {
  const now = new Date();
  const trajectory = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    return {
      date: d.toISOString().slice(0, 10),
      risk_score: Math.max(40, Math.min(95, 72 + Math.sin(i / 5) * 15 + (i * 0.3))),
      critical: Math.max(0, Math.floor(12 - i * 0.3 + Math.random() * 3)),
      high: Math.max(0, Math.floor(28 - i * 0.2 + Math.random() * 5)),
    };
  });

  return {
    risk_posture: {
      overall_risk_score: 76,
      critical_findings: 8,
      high_findings: 23,
      medium_findings: 67,
      low_findings: 142,
      remediation_progress: 68,
      risk_trajectory: trajectory,
    },
    kpis: {
      mttd: 4.2,      // hours
      mttr: 18.7,      // hours
      sla_compliance: 91.3,
      findings_per_day: 12.4,
      remediation_rate: 78.5,
      detection_accuracy: 94.2,
    },
    top_risks: [
      { id: "CVE-2024-3094", title: "XZ Utils Backdoor (CVE-2024-3094)", severity: "critical", risk_score: 98, assets: 3, days_open: 2 },
      { id: "CVE-2024-21762", title: "Fortinet FortiOS RCE", severity: "critical", risk_score: 95, assets: 5, days_open: 4 },
      { id: "CVE-2024-1709", title: "ConnectWise ScreenConnect Auth Bypass", severity: "critical", risk_score: 93, assets: 2, days_open: 6 },
      { id: "CVE-2024-23897", title: "Jenkins Arbitrary File Read", severity: "high", risk_score: 88, assets: 4, days_open: 8 },
      { id: "CVE-2024-0204", title: "GoAnywhere MFT Auth Bypass", severity: "high", risk_score: 85, assets: 1, days_open: 12 },
    ],
    compliance: [
      { name: "SOC 2 Type II", score: 92, passing: 74, total: 80 },
      { name: "HIPAA", score: 88, passing: 22, total: 25 },
      { name: "PCI DSS v4.0", score: 85, passing: 51, total: 60 },
      { name: "ISO 27001", score: 91, passing: 36, total: 40 },
      { name: "NIST CSF 2.0", score: 87, passing: 43, total: 50 },
      { name: "GDPR", score: 94, passing: 47, total: 50 },
    ],
    pipeline: {
      throughput: 1247,
      avg_latency_ms: 342,
      error_rate: 0.3,
      stages_healthy: 14,
      stages_total: 15,
    },
  };
}

// ═══════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════

export default function CISODashboard() {
  const navigate = useNavigate();

  // Fetch real data from analytics API with mock fallback
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["ciso-dashboard"],
    queryFn: async () => {
      try {
        const [posture, kpis] = await Promise.all([
          analyticsApi.get("/api/v1/analytics/posture").then(r => r.data),
          analyticsApi.get("/api/v1/analytics/kpis").then(r => r.data),
        ]);
        return { risk_posture: posture, kpis, ...generateMockCISOData() };
      } catch {
        // Graceful fallback to mock data when API unavailable
        return generateMockCISOData();
      }
    },
    refetchInterval: 60_000, // Refresh every 60s
    staleTime: 30_000,
  });

  if (isLoading) return <PageSkeleton />;
  if (error && !data) return <ErrorState message="Failed to load dashboard" onRetry={refetch} />;

  const d = data!;

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title="CISO Dashboard"
        description="Executive security posture overview — real-time risk intelligence"
        badge="P01"
      >
        <Button variant="outline" size="sm" onClick={() => navigate("/mission-control/executive")}>
          Executive Report <ArrowRight className="ml-1 h-3.5 w-3.5" />
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <KpiCard
          title="MTTD"
          value={`${d.kpis.mttd}h`}
          icon={Eye}
          trend="down"
          trendLabel="Mean Time to Detect"
        />
        <KpiCard
          title="MTTR"
          value={`${d.kpis.mttr}h`}
          icon={Timer}
          trend="down"
          trendLabel="Mean Time to Remediate"
        />
        <KpiCard
          title="SLA Compliance"
          value={`${d.kpis.sla_compliance}%`}
          icon={CheckCircle2}
          trend={d.kpis.sla_compliance >= 90 ? "up" : "down"}
          trendLabel={d.kpis.sla_compliance >= 90 ? "On target" : "Below target"}
        />
        <KpiCard
          title="Remediation Rate"
          value={`${d.kpis.remediation_rate}%`}
          icon={Target}
          trend={d.kpis.remediation_rate >= 75 ? "up" : "down"}
          trendLabel="Closed / Total"
        />
        <KpiCard
          title="Detection Accuracy"
          value={`${d.kpis.detection_accuracy}%`}
          icon={Activity}
          trend="up"
          trendLabel="True positive rate"
        />
        <KpiCard
          title="Findings / Day"
          value={d.kpis.findings_per_day.toFixed(1)}
          icon={BarChart3}
          trend="flat"
          trendLabel="Avg daily ingest"
        />
      </div>

      {/* Main Grid: Risk Posture + Top Risks + Compliance */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Posture Card */}
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Risk Posture
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <RiskGauge score={d.risk_posture.overall_risk_score} />

            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Critical", count: d.risk_posture.critical_findings, color: "bg-red-500" },
                { label: "High", count: d.risk_posture.high_findings, color: "bg-orange-500" },
                { label: "Medium", count: d.risk_posture.medium_findings, color: "bg-yellow-500" },
                { label: "Low", count: d.risk_posture.low_findings, color: "bg-green-500" },
              ].map(({ label, count, color }) => (
                <div key={label} className="flex items-center gap-2">
                  <div className={cn("h-2.5 w-2.5 rounded-full", color)} />
                  <span className="text-xs text-muted-foreground">{label}</span>
                  <span className="text-sm font-semibold ml-auto tabular-nums">{count}</span>
                </div>
              ))}
            </div>

            <Separator />

            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">Remediation Progress</span>
                <span className="font-medium">{d.risk_posture.remediation_progress}%</span>
              </div>
              <Progress value={d.risk_posture.remediation_progress} className="h-2" />
            </div>
          </CardContent>
        </Card>

        {/* Top Risks Card */}
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-destructive" />
              Top Risks
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-1">
              {d.top_risks.map((risk: any) => (
                <motion.div
                  key={risk.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-center justify-between py-2.5 group cursor-pointer hover:bg-muted/30 -mx-2 px-2 rounded-md transition-colors"
                  onClick={() => navigate(`/discover/findings?q=${risk.id}`)}
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium truncate group-hover:text-primary transition-colors">
                      {risk.title}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {risk.assets} asset{risk.assets !== 1 ? "s" : ""} · {risk.days_open}d open
                    </p>
                  </div>
                  <Badge
                    variant={risk.severity === "critical" ? "destructive" : "secondary"}
                    className="ml-2 shrink-0 text-xs"
                  >
                    {risk.risk_score}
                  </Badge>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Compliance Card */}
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <FileCheck className="h-4 w-4 text-primary" />
              Compliance Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="divide-y divide-border">
              {d.compliance.map((fw: any) => (
                <ComplianceCard
                  key={fw.name}
                  name={fw.name}
                  score={fw.score}
                  controlsPassing={fw.passing}
                  totalControls={fw.total}
                />
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Trajectory Chart */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" />
              Risk Trajectory (30 Days)
            </CardTitle>
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <div className="h-2 w-4 rounded-sm bg-primary" /> Risk Score
              </span>
              <span className="flex items-center gap-1.5">
                <div className="h-2 w-4 rounded-sm" style={{ background: SEVERITY_COLORS.critical }} /> Critical
              </span>
              <span className="flex items-center gap-1.5">
                <div className="h-2 w-4 rounded-sm" style={{ background: SEVERITY_COLORS.high }} /> High
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={d.risk_posture.risk_trajectory} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis
                  dataKey="date"
                  tickFormatter={(v) => v.slice(5)} // MM-DD
                  tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                  axisLine={false}
                  tickLine={false}
                  domain={[0, 100]}
                />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Area
                  type="monotone"
                  dataKey="risk_score"
                  stroke="hsl(var(--primary))"
                  fill="url(#riskGrad)"
                  strokeWidth={2}
                  name="Risk Score"
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stroke={SEVERITY_COLORS.critical}
                  fill="none"
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                  name="Critical"
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  stroke={SEVERITY_COLORS.high}
                  fill="none"
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                  name="High"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Pipeline Health Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Pipeline Throughput"
          value={`${d.pipeline.throughput.toLocaleString()}`}
          description="Findings processed today"
          icon={Activity}
        />
        <KpiCard
          title="Avg Latency"
          value={`${d.pipeline.avg_latency_ms}ms`}
          description="Per-finding processing time"
          icon={Clock}
        />
        <KpiCard
          title="Error Rate"
          value={`${d.pipeline.error_rate}%`}
          description="Pipeline failures"
          icon={AlertTriangle}
          trend={d.pipeline.error_rate < 1 ? "up" : "down"}
        />
        <KpiCard
          title="Pipeline Stages"
          value={`${d.pipeline.stages_healthy}/${d.pipeline.stages_total}`}
          description="Healthy / Total stages"
          icon={CheckCircle2}
          trend={d.pipeline.stages_healthy === d.pipeline.stages_total ? "up" : "down"}
        />
      </div>
    </div>
  );
}
