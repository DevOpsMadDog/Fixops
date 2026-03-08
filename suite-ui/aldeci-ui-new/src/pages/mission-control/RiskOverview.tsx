import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import {
  Shield,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Activity,
  Server,
  Globe,
  CreditCard,
  Database,
  Users,
  Lock,
  ChevronUp,
  ChevronDown,
  Minus,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { dashboardApi } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_TOP_RISKY_APPS = [
  { rank: 1, appId: "APP-0041", name: "payments-gateway-prod", riskScore: 96, critical: 4, high: 12, medium: 28, trend: "up", delta: +8, bu: "Payments", cves: ["CVE-2024-50379", "CVE-2024-44082"] },
  { rank: 2, appId: "APP-0017", name: "identity-service", riskScore: 91, critical: 3, high: 9, medium: 21, trend: "up", delta: +5, bu: "Identity & Auth", cves: ["CVE-2024-49138"] },
  { rank: 3, appId: "APP-0094", name: "customer-data-lake", riskScore: 89, critical: 2, high: 8, medium: 31, trend: "down", delta: -3, bu: "Data Platform", cves: ["ALDECI-SEC-0441"] },
  { rank: 4, appId: "APP-0058", name: "data-pipeline-service", riskScore: 84, critical: 2, high: 14, medium: 19, trend: "up", delta: +2, bu: "Data Platform", cves: ["CVE-2024-45768", "CVE-2024-48990"] },
  { rank: 5, appId: "APP-0033", name: "admin-portal", riskScore: 79, critical: 1, high: 11, medium: 22, trend: "flat", delta: 0, bu: "Corporate IT", cves: [] },
  { rank: 6, appId: "APP-0012", name: "checkout-service", riskScore: 74, critical: 1, high: 7, medium: 18, trend: "down", delta: -6, bu: "Payments", cves: ["CVE-2024-47176"] },
  { rank: 7, appId: "APP-0081", name: "notification-service", riskScore: 68, critical: 0, high: 8, medium: 14, trend: "flat", delta: 0, bu: "Platform", cves: [] },
  { rank: 8, appId: "APP-0067", name: "reporting-service", riskScore: 63, critical: 0, high: 6, medium: 24, trend: "up", delta: +4, bu: "Analytics", cves: [] },
  { rank: 9, appId: "APP-0029", name: "search-service", riskScore: 58, critical: 0, high: 5, medium: 17, trend: "down", delta: -2, bu: "Platform", cves: [] },
  { rank: 10, appId: "APP-0073", name: "audit-log-service", riskScore: 52, critical: 0, high: 3, medium: 11, trend: "flat", delta: 0, bu: "Compliance", cves: [] },
];

const MOCK_RISK_TREND_BY_APP: Record<string, { month: string; score: number }[]> = {
  "APP-0041": [
    { month: "Oct", score: 78 }, { month: "Nov", score: 81 }, { month: "Dec", score: 84 },
    { month: "Jan", score: 88 }, { month: "Feb", score: 91 }, { month: "Mar", score: 96 },
  ],
  "APP-0017": [
    { month: "Oct", score: 72 }, { month: "Nov", score: 76 }, { month: "Dec", score: 80 },
    { month: "Jan", score: 84 }, { month: "Feb", score: 87 }, { month: "Mar", score: 91 },
  ],
  "APP-0094": [
    { month: "Oct", score: 91 }, { month: "Nov", score: 94 }, { month: "Dec", score: 92 },
    { month: "Jan", score: 90 }, { month: "Feb", score: 88 }, { month: "Mar", score: 89 },
  ],
  "APP-0058": [
    { month: "Oct", score: 70 }, { month: "Nov", score: 74 }, { month: "Dec", score: 79 },
    { month: "Jan", score: 80 }, { month: "Feb", score: 83 }, { month: "Mar", score: 84 },
  ],
  "APP-0033": [
    { month: "Oct", score: 77 }, { month: "Nov", score: 80 }, { month: "Dec", score: 81 },
    { month: "Jan", score: 79 }, { month: "Feb", score: 79 }, { month: "Mar", score: 79 },
  ],
};

const MOCK_RISK_DISTRIBUTION = [
  { name: "Critical", value: 13, color: "#f87171" },
  { name: "High", value: 83, color: "#fb923c" },
  { name: "Medium", value: 204, color: "#fbbf24" },
  { name: "Low", value: 312, color: "#60a5fa" },
  { name: "Informational", value: 447, color: "#6b7280" },
];

const MOCK_BUSINESS_IMPACT = [
  { domain: "Payment Processing", icon: CreditCard, risk: "critical", summary: "Active RCE vulnerability in payment gateway. PCI DSS scope. Potential for full transaction compromise.", financialExposure: "$48M", likelihood: "High" },
  { domain: "Customer PII & Data", icon: Database, risk: "high", summary: "S3 bucket ACL misconfiguration exposes 2.4M customer records. GDPR/CCPA breach risk.", financialExposure: "$12M", likelihood: "Medium" },
  { domain: "Authentication & IAM", icon: Lock, risk: "high", summary: "SQL injection in auth service. Credential theft and account takeover pathway exists.", financialExposure: "$8M", likelihood: "Medium" },
  { domain: "Internal Operations", icon: Users, risk: "medium", summary: "Admin portal missing rate limiting. Risk of credential stuffing against internal tooling.", financialExposure: "$2M", likelihood: "Low" },
];

// Heatmap: Business Unit × Risk Category
const HEATMAP_BUS = ["Payments", "Identity & Auth", "Data Platform", "Customer Portal", "Corporate IT", "DevOps Infra"];
const HEATMAP_CATS = ["Network", "App Code", "Config", "IAM", "Data", "3rd Party"];

const MOCK_RISK_HEATMAP: number[][] = [
  [92, 88, 74, 61, 45, 79],
  [68, 94, 71, 88, 52, 64],
  [74, 81, 69, 55, 91, 70],
  [52, 76, 63, 44, 88, 57],
  [41, 55, 82, 71, 62, 48],
  [61, 72, 88, 66, 51, 84],
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskHeatColor(score: number): string {
  if (score >= 85) return "bg-red-500/70 text-red-200";
  if (score >= 70) return "bg-orange-500/60 text-orange-200";
  if (score >= 55) return "bg-yellow-500/50 text-yellow-100";
  if (score >= 40) return "bg-green-500/40 text-green-200";
  return "bg-green-500/25 text-green-300";
}

function riskScoreColor(score: number): string {
  if (score >= 85) return "text-red-400";
  if (score >= 70) return "text-orange-400";
  if (score >= 55) return "text-yellow-400";
  return "text-blue-400";
}

function TrendIcon({ trend, delta }: { trend: string; delta: number }) {
  if (trend === "up") return <ChevronUp className="h-3.5 w-3.5 text-red-400" />;
  if (trend === "down") return <ChevronDown className="h-3.5 w-3.5 text-green-400" />;
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function RiskOverview() {
  const [selectedApp, setSelectedApp] = useState(MOCK_TOP_RISKY_APPS[0].appId);
  const [trendApps, setTrendApps] = useState<string[]>(["APP-0041", "APP-0017", "APP-0094"]);

  useQuery({
    queryKey: ["risk-overview"],
    queryFn: () => dashboardApi.summary(),
    retry: false,
  });

  useQuery({
    queryKey: ["risk-trends"],
    queryFn: () => dashboardApi.trends(),
    retry: false,
  });

  // Build combined trend data for selected apps
  const trendData = ["Oct", "Nov", "Dec", "Jan", "Feb", "Mar"].map((month) => {
    const point: Record<string, unknown> = { month };
    trendApps.forEach((appId) => {
      const app = MOCK_TOP_RISKY_APPS.find((a) => a.appId === appId);
      if (app) {
        const series = MOCK_RISK_TREND_BY_APP[appId];
        const found = series?.find((d) => d.month === month);
        point[app.name] = found?.score ?? null;
      }
    });
    return point;
  });

  const APP_COLORS = ["#14b8a6", "#f87171", "#fb923c", "#60a5fa", "#a78bfa"];

  const totalRisk = MOCK_RISK_DISTRIBUTION.reduce((s, d) => s + d.value, 0);
  const criticalCount = MOCK_TOP_RISKY_APPS.reduce((s, a) => s + a.critical, 0);
  const highCount = MOCK_TOP_RISKY_APPS.reduce((s, a) => s + a.high, 0);
  const avgRisk = Math.round(MOCK_TOP_RISKY_APPS.reduce((s, a) => s + a.riskScore, 0) / MOCK_TOP_RISKY_APPS.length);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* Header */}
      <PageHeader
        title="Risk Overview"
        description="Organization-wide risk posture, application risk ranking, and business impact assessment"
        actions={
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => {}}>
            <Activity className="h-3.5 w-3.5" />
            Risk Report
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Avg App Risk Score" value={avgRisk} change={4} changeLabel="vs last month" trend="down" icon={Shield} />
        <KpiCard title="Critical Risk Apps" value={MOCK_TOP_RISKY_APPS.filter((a) => a.riskScore >= 85).length} change={1} changeLabel="new this week" trend="down" icon={AlertTriangle} />
        <KpiCard title="Critical Findings" value={criticalCount} change={-33} changeLabel="vs last month" trend="up" icon={TrendingDown} />
        <KpiCard title="Total Risk Items" value={totalRisk} change={-8} changeLabel="vs last period" trend="up" icon={TrendingUp} />
      </div>

      {/* Top Risky Apps + Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Top 10 Riskiest Apps */}
        <div className="lg:col-span-2">
          <Card className="p-5">
            <CardHeader className="p-0 pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
                Top 10 Riskiest Applications
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0 space-y-2">
              {MOCK_TOP_RISKY_APPS.map((app, i) => (
                <motion.div
                  key={app.appId}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                  onClick={() => setSelectedApp(app.appId)}
                  className={cn(
                    "flex items-center gap-3 rounded-lg border p-3 cursor-pointer transition-all",
                    selectedApp === app.appId ? "border-primary/50 bg-primary/5" : "border-border/40 hover:bg-muted/30"
                  )}
                >
                  {/* Rank */}
                  <span className="text-xs font-bold text-muted-foreground w-5 tabular-nums text-right">{app.rank}</span>

                  {/* App info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold truncate">{app.name}</span>
                      <span className="text-xs text-muted-foreground font-mono shrink-0">{app.appId}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs text-muted-foreground">{app.bu}</span>
                      {app.cves.length > 0 && (
                        <>
                          <span className="text-muted-foreground/40">·</span>
                          <span className="text-xs text-red-400/80 font-mono truncate">{app.cves[0]}{app.cves.length > 1 ? ` +${app.cves.length - 1}` : ""}</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Severity counts */}
                  <div className="flex items-center gap-2 shrink-0">
                    {app.critical > 0 && <span className="text-xs text-red-400 font-semibold">{app.critical}C</span>}
                    {app.high > 0 && <span className="text-xs text-orange-400 font-semibold">{app.high}H</span>}
                    <span className="text-xs text-muted-foreground">{app.medium}M</span>
                  </div>

                  {/* Risk score */}
                  <div className="flex items-center gap-1 shrink-0">
                    <TrendIcon trend={app.trend} delta={app.delta} />
                    <span className={cn("text-sm font-bold tabular-nums w-8 text-right", riskScoreColor(app.riskScore))}>
                      {app.riskScore}
                    </span>
                  </div>
                </motion.div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Risk Distribution Donut */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Risk Distribution
            </CardTitle>
            <CardDescription className="text-xs">{totalRisk} total findings across all apps</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={MOCK_RISK_DISTRIBUTION}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={85}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {MOCK_RISK_DISTRIBUTION.map((entry, i) => (
                      <Cell key={i} fill={entry.color} opacity={0.85} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                    formatter={(value: number) => [`${value} (${Math.round((value / totalRisk) * 100)}%)`, ""]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 space-y-1.5">
              {MOCK_RISK_DISTRIBUTION.map((d) => (
                <div key={d.name} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div className="h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: d.color }} />
                    <span className="text-muted-foreground">{d.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-semibold tabular-nums">{d.value}</span>
                    <span className="text-muted-foreground/60 tabular-nums w-10 text-right">{Math.round((d.value / totalRisk) * 100)}%</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Trend Chart */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-4">
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-primary" />
                Risk Score Trend by Application
              </CardTitle>
              <CardDescription className="text-xs mt-1">6-month historical risk trajectory for top applications</CardDescription>
            </div>
            <Select
              value={trendApps.join(",")}
              onValueChange={(v) => setTrendApps(v.split(",").filter(Boolean))}
            >
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="Select apps" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="APP-0041,APP-0017,APP-0094">Top 3 Riskiest</SelectItem>
                <SelectItem value="APP-0041,APP-0017,APP-0058,APP-0033">Top 4</SelectItem>
                <SelectItem value="APP-0094,APP-0012">Trending Down</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0 h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trendData} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.3)" />
              <XAxis dataKey="month" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
              <YAxis domain={[40, 100]} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                labelStyle={{ fontWeight: 600 }}
              />
              <Legend wrapperStyle={{ fontSize: 10 }} />
              {trendApps.map((appId, idx) => {
                const app = MOCK_TOP_RISKY_APPS.find((a) => a.appId === appId);
                if (!app) return null;
                return (
                  <Line
                    key={appId}
                    type="monotone"
                    dataKey={app.name}
                    stroke={APP_COLORS[idx % APP_COLORS.length]}
                    strokeWidth={2}
                    dot={{ r: 3, fill: APP_COLORS[idx % APP_COLORS.length] }}
                    connectNulls
                  />
                );
              })}
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Risk Heatmap */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-3">
          <CardTitle className="text-sm font-semibold">Risk Heatmap — Business Unit × Risk Category</CardTitle>
          <CardDescription className="text-xs">Composite risk score (0–100) across business units and risk domains</CardDescription>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr>
                <th className="text-left py-2 pr-4 text-muted-foreground font-medium">Business Unit</th>
                {HEATMAP_CATS.map((cat) => (
                  <th key={cat} className="text-center py-2 px-2 text-muted-foreground font-medium">{cat}</th>
                ))}
                <th className="text-center py-2 px-2 text-muted-foreground font-medium">Avg</th>
              </tr>
            </thead>
            <tbody>
              {HEATMAP_BUS.map((bu, buIdx) => {
                const row = MOCK_RISK_HEATMAP[buIdx];
                const avg = Math.round(row.reduce((s, v) => s + v, 0) / row.length);
                return (
                  <tr key={bu} className="border-t border-border/20">
                    <td className="py-2 pr-4 font-medium whitespace-nowrap">{bu}</td>
                    {row.map((score, catIdx) => (
                      <td key={catIdx} className="py-2 px-2 text-center">
                        <motion.div
                          initial={{ opacity: 0, scale: 0.8 }}
                          animate={{ opacity: 1, scale: 1 }}
                          transition={{ delay: (buIdx * 6 + catIdx) * 0.01 }}
                          className={cn("inline-flex h-8 w-12 items-center justify-center rounded-md font-bold tabular-nums", riskHeatColor(score))}
                        >
                          {score}
                        </motion.div>
                      </td>
                    ))}
                    <td className="py-2 px-2 text-center">
                      <div className={cn("inline-flex h-8 w-12 items-center justify-center rounded-md font-bold tabular-nums border", riskScoreColor(avg))}>
                        {avg}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="mt-3 flex items-center gap-3 text-xs text-muted-foreground">
            <span>Risk scale:</span>
            {[{ label: "≥85 Critical", cls: "bg-red-500/70" }, { label: "70–85 High", cls: "bg-orange-500/60" }, { label: "55–70 Medium", cls: "bg-yellow-500/50" }, { label: "<55 Low", cls: "bg-green-500/40" }].map((l) => (
              <div key={l.label} className="flex items-center gap-1">
                <div className={cn("h-3 w-3 rounded", l.cls)} />
                <span>{l.label}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Business Impact Cards */}
      <div>
        <h2 className="text-sm font-semibold mb-3">Business Impact Assessment</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {MOCK_BUSINESS_IMPACT.map((item, i) => (
            <motion.div
              key={item.domain}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.08 }}
            >
              <Card className={cn("p-5 border-l-2", item.risk === "critical" ? "border-l-red-500" : item.risk === "high" ? "border-l-orange-500" : "border-l-yellow-500")}>
                <div className="flex items-start gap-3 mb-3">
                  <div className={cn("rounded-lg p-2", item.risk === "critical" ? "bg-red-500/10" : item.risk === "high" ? "bg-orange-500/10" : "bg-yellow-500/10")}>
                    <item.icon className={cn("h-4 w-4", item.risk === "critical" ? "text-red-400" : item.risk === "high" ? "text-orange-400" : "text-yellow-400")} />
                  </div>
                  <div>
                    <p className="text-xs font-semibold">{item.domain}</p>
                    <Badge variant={item.risk === "critical" ? "critical" : item.risk === "high" ? "high" : "warning"} className="text-xs mt-0.5">{item.risk}</Badge>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed mb-3">{item.summary}</p>
                <div className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Financial exposure</span>
                    <span className="font-bold text-red-400">{item.financialExposure}</span>
                  </div>
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">Likelihood</span>
                    <span className={cn("font-medium", item.likelihood === "High" ? "text-red-400" : item.likelihood === "Medium" ? "text-yellow-400" : "text-green-400")}>{item.likelihood}</span>
                  </div>
                </div>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
