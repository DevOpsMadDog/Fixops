import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  TrendingUp,
  DollarSign,
  Shield,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Download,
  Briefcase,
  Target,
  BarChart2,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { dashboardApi } from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_POSTURE_12M = [
  { month: "Apr '24", score: 61, benchmark: 55 },
  { month: "May '24", score: 63, benchmark: 56 },
  { month: "Jun '24", score: 65, benchmark: 57 },
  { month: "Jul '24", score: 64, benchmark: 57 },
  { month: "Aug '24", score: 68, benchmark: 58 },
  { month: "Sep '24", score: 70, benchmark: 59 },
  { month: "Oct '24", score: 73, benchmark: 60 },
  { month: "Nov '24", score: 72, benchmark: 60 },
  { month: "Dec '24", score: 76, benchmark: 61 },
  { month: "Jan '25", score: 79, benchmark: 62 },
  { month: "Feb '25", score: 81, benchmark: 63 },
  { month: "Mar '25", score: 84, benchmark: 63 },
];

const MOCK_RISK_BY_BU = [
  { bu: "Payments", critical: 4, high: 12, medium: 34 },
  { bu: "Identity & Auth", critical: 3, high: 9, medium: 21 },
  { bu: "Data Platform", critical: 2, high: 14, medium: 28 },
  { bu: "Customer Portal", critical: 1, high: 7, medium: 19 },
  { bu: "Corporate IT", critical: 0, high: 5, medium: 41 },
  { bu: "DevOps Infra", critical: 1, high: 11, medium: 16 },
];

const MOCK_COMPLIANCE_EXEC = [
  { framework: "SOC 2 Type II", score: 92, trend: +3, status: "passing", audit: "Jun 2025" },
  { framework: "PCI DSS 4.0", score: 87, trend: -1, status: "warning", audit: "Sep 2025" },
  { framework: "ISO 27001:2022", score: 95, trend: +2, status: "passing", audit: "Dec 2025" },
  { framework: "HIPAA", score: 94, trend: +1, status: "passing", audit: "Nov 2025" },
];

const MOCK_KEY_DECISIONS = [
  { id: "QD-001", title: "Approved emergency patch window for CVE-2024-50379", owner: "CISO", date: "Mar 06, 2025", impact: "high" },
  { id: "QD-002", title: "Consolidated 3 DAST tools into ALdeci scanner pipeline", owner: "CTO", date: "Feb 28, 2025", impact: "medium" },
  { id: "QD-003", title: "Renewed cyber insurance — premium reduced 12% post-posture improvement", owner: "CFO", date: "Feb 20, 2025", impact: "high" },
  { id: "QD-004", title: "Waived 8 SOC2 controls pending vendor remediation (agreed SLA: 90 days)", owner: "CISO", date: "Feb 15, 2025", impact: "medium" },
  { id: "QD-005", title: "Approved $2.1M security tooling budget reallocation from legacy SIEM", owner: "CFO + CISO", date: "Jan 31, 2025", impact: "high" },
];

const ROI_DATA = {
  annualSavings: "$4.2M",
  costPerFix: "$214",
  toolsConsolidated: 7,
  engineeringHoursSaved: 1840,
  incidentCostAvoidance: "$1.8M",
  auditCostReduction: "38%",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const impactColors: Record<string, string> = {
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
};

const statusVariants: Record<string, "success" | "warning"> = {
  passing: "success",
  warning: "warning",
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function ExecutiveView() {
  const [exportLoading, setExportLoading] = useState(false);

  useQuery({
    queryKey: ["executive-dashboard"],
    queryFn: () => dashboardApi.summary(),
    retry: false,
  });

  const handleExport = (format: "pdf" | "csv") => {
    setExportLoading(true);
    setTimeout(() => {
      setExportLoading(false);
      toast.success(`Executive report exported as ${format.toUpperCase()}`);
    }, 1400);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* Header */}
      <PageHeader
        title="Executive View"
        description="Board-ready security posture, ROI, and compliance summary for CISO & CFO"
        badge="Q1 2025"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={exportLoading}
              onClick={() => handleExport("csv")}
              className="gap-1.5"
            >
              <Download className="h-3.5 w-3.5" />
              CSV
            </Button>
            <Button
              size="sm"
              disabled={exportLoading}
              onClick={() => handleExport("pdf")}
              className="gap-1.5"
            >
              <FileText className="h-3.5 w-3.5" />
              {exportLoading ? "Exporting…" : "Export PDF"}
            </Button>
          </div>
        }
      />

      {/* Top KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Posture Score" value="84 / 100" change={23} changeLabel="since deployment" trend="up" icon={Shield} />
        <KpiCard title="Annual Savings" value="$4.2M" change={18} changeLabel="vs prior toolset" trend="up" icon={DollarSign} />
        <KpiCard title="Critical Open" value={4} change={-72} changeLabel="vs Q4 2024" trend="up" icon={AlertTriangle} />
        <KpiCard title="Compliance Score" value="92%" change={7} changeLabel="vs last quarter" trend="up" icon={CheckCircle2} />
      </div>

      {/* Posture Trend + ROI */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* 12-Month Trend */}
        <Card className="lg:col-span-2 p-5">
          <CardHeader className="p-0 pb-4">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" />
              12-Month Security Posture Trend
            </CardTitle>
            <CardDescription className="text-xs">ALdeci score vs. industry benchmark (Gartner CSPM Peer Group)</CardDescription>
          </CardHeader>
          <CardContent className="p-0 h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={MOCK_POSTURE_12M} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.3)" />
                <XAxis dataKey="month" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                <YAxis domain={[40, 100]} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ fontWeight: 600 }}
                />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="score" name="ALdeci Score" stroke="#14b8a6" strokeWidth={2.5} dot={{ r: 3, fill: "#14b8a6" }} />
                <Line type="monotone" dataKey="benchmark" name="Industry Benchmark" stroke="hsl(var(--muted-foreground))" strokeWidth={1.5} strokeDasharray="4 4" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* ROI Summary */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <DollarSign className="h-4 w-4 text-green-400" />
              ROI Summary
            </CardTitle>
            <CardDescription className="text-xs">Annual value delivered by ALdeci platform</CardDescription>
          </CardHeader>
          <CardContent className="p-0 space-y-3">
            {[
              { label: "Annual Savings", value: ROI_DATA.annualSavings, icon: DollarSign, color: "text-green-400" },
              { label: "Cost Per Fix", value: ROI_DATA.costPerFix, icon: Target, color: "text-primary" },
              { label: "Tools Consolidated", value: `${ROI_DATA.toolsConsolidated} tools`, icon: Layers, color: "text-blue-400" },
              { label: "Eng. Hours Saved", value: `${ROI_DATA.engineeringHoursSaved.toLocaleString()}h`, icon: Briefcase, color: "text-primary" },
              { label: "Incident Cost Avoided", value: ROI_DATA.incidentCostAvoidance, icon: Shield, color: "text-green-400" },
              { label: "Audit Cost Reduction", value: ROI_DATA.auditCostReduction, icon: CheckCircle2, color: "text-green-400" },
            ].map((item) => (
              <div key={item.label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <item.icon className={cn("h-3.5 w-3.5", item.color)} />
                  <span className="text-xs text-muted-foreground">{item.label}</span>
                </div>
                <span className="text-sm font-bold tabular-nums">{item.value}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Risk By BU + Compliance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Risk by Business Unit */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-4">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-primary" />
              Risk by Business Unit
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 h-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={MOCK_RISK_BY_BU}
                layout="vertical"
                margin={{ top: 0, right: 10, left: 60, bottom: 0 }}
                barSize={14}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.3)" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                <YAxis dataKey="bu" type="category" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                />
                <Legend wrapperStyle={{ fontSize: 10 }} />
                <Bar dataKey="critical" name="Critical" stackId="a" fill="#f87171" radius={[0, 0, 0, 0]} />
                <Bar dataKey="high" name="High" stackId="a" fill="#fb923c" />
                <Bar dataKey="medium" name="Medium" stackId="a" fill="#fbbf24" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Compliance per Framework */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-primary" />
              Compliance Framework Status
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-4">
            {MOCK_COMPLIANCE_EXEC.map((fw) => (
              <div key={fw.framework} className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{fw.framework}</span>
                    <Badge variant={statusVariants[fw.status]}>{fw.status}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={cn("text-xs font-medium", fw.trend >= 0 ? "text-green-400" : "text-red-400")}>
                      {fw.trend >= 0 ? "+" : ""}{fw.trend}%
                    </span>
                    <span className="text-xs font-bold tabular-nums">{fw.score}%</span>
                  </div>
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden">
                  <motion.div
                    className={cn("h-full rounded-full", fw.status === "passing" ? "bg-green-500" : "bg-yellow-500")}
                    initial={{ width: 0 }}
                    animate={{ width: `${fw.score}%` }}
                    transition={{ duration: 0.9, ease: "easeOut" }}
                  />
                </div>
                <p className="text-xs text-muted-foreground">Next audit: {fw.audit}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Key Decisions */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Briefcase className="h-4 w-4 text-primary" />
            Key Decisions This Quarter
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="space-y-0">
            {MOCK_KEY_DECISIONS.map((d, i) => (
              <motion.div
                key={d.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07 }}
                className="flex items-start gap-4 py-3 border-b border-border/30 last:border-0"
              >
                <div className="shrink-0 mt-0.5">
                  <div className={cn("h-2 w-2 rounded-full", impactColors[d.impact].replace("text-", "bg-"))} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">{d.title}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{d.owner} · {d.date}</p>
                </div>
                <Badge variant="outline" className={cn("text-xs shrink-0", impactColors[d.impact])}>
                  {d.impact} impact
                </Badge>
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
