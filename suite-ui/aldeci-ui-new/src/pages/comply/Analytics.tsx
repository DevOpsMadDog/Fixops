import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import {
  Clock,
  TrendingDown,
  TrendingUp,
  Target,
  Zap,
  BarChart2,
  Calendar,
  Shield,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { dashboardApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

const MTTR_DATA_90D = [
  { week: "Oct W1", critical: 4.2, high: 12.1, medium: 28.4, sla: 7 },
  { week: "Oct W2", critical: 3.8, high: 11.4, medium: 26.1, sla: 7 },
  { week: "Oct W3", critical: 5.1, high: 13.2, medium: 29.8, sla: 7 },
  { week: "Oct W4", critical: 4.5, high: 10.9, medium: 25.3, sla: 7 },
  { week: "Nov W1", critical: 3.2, high: 9.8, medium: 23.7, sla: 7 },
  { week: "Nov W2", critical: 2.9, high: 8.7, medium: 21.4, sla: 7 },
  { week: "Nov W3", critical: 3.4, high: 9.1, medium: 22.8, sla: 7 },
  { week: "Nov W4", critical: 2.7, high: 8.2, medium: 20.1, sla: 7 },
  { week: "Dec W1", critical: 2.4, high: 7.6, medium: 18.9, sla: 7 },
  { week: "Dec W2", critical: 2.1, high: 7.1, medium: 17.5, sla: 7 },
  { week: "Dec W3", critical: 1.9, high: 6.8, medium: 16.2, sla: 7 },
  { week: "Dec W4", critical: 1.8, high: 6.4, medium: 15.8, sla: 7 },
];

const NOISE_DATA_90D = [
  { week: "Oct W1", rawFindings: 1240, afterDedup: 820, afterPriority: 340, falsePositiveRate: 33.9 },
  { week: "Oct W2", rawFindings: 1180, afterDedup: 790, afterPriority: 320, falsePositiveRate: 33.1 },
  { week: "Oct W3", rawFindings: 1310, afterDedup: 850, afterPriority: 360, falsePositiveRate: 35.1 },
  { week: "Oct W4", rawFindings: 1150, afterDedup: 760, afterPriority: 300, falsePositiveRate: 34.0 },
  { week: "Nov W1", rawFindings: 1090, afterDedup: 700, afterPriority: 275, falsePositiveRate: 30.7 },
  { week: "Nov W2", rawFindings: 980, afterDedup: 630, afterPriority: 245, falsePositiveRate: 28.4 },
  { week: "Nov W3", rawFindings: 920, afterDedup: 590, afterPriority: 220, falsePositiveRate: 26.9 },
  { week: "Nov W4", rawFindings: 870, afterDedup: 550, afterPriority: 200, falsePositiveRate: 25.0 },
  { week: "Dec W1", rawFindings: 810, afterDedup: 510, afterPriority: 185, falsePositiveRate: 23.9 },
  { week: "Dec W2", rawFindings: 760, afterDedup: 480, afterPriority: 170, falsePositiveRate: 22.6 },
  { week: "Dec W3", rawFindings: 710, afterDedup: 450, afterPriority: 158, falsePositiveRate: 21.3 },
  { week: "Dec W4", rawFindings: 680, afterDedup: 430, afterPriority: 148, falsePositiveRate: 20.1 },
];

const SLA_DATA_90D = [
  { month: "October", critical: 72, high: 85, medium: 91, overall: 83 },
  { month: "November", critical: 79, high: 88, medium: 93, overall: 87 },
  { month: "December", critical: 86, high: 92, medium: 96, overall: 91 },
];

const SCANNER_ROI_DATA = [
  { scanner: "Trivy", findings: 1240, uniqueFindings: 890, falsePositives: 180, costScore: 92 },
  { scanner: "Semgrep", findings: 980, uniqueFindings: 760, falsePositives: 140, costScore: 88 },
  { scanner: "Snyk", findings: 850, uniqueFindings: 620, falsePositives: 200, costScore: 74 },
  { scanner: "Grype", findings: 720, uniqueFindings: 540, falsePositives: 95, costScore: 85 },
  { scanner: "Checkov", findings: 560, uniqueFindings: 410, falsePositives: 60, costScore: 91 },
  { scanner: "Nuclei", findings: 340, uniqueFindings: 280, falsePositives: 45, costScore: 87 },
];

const TOOLTIP_STYLE = {
  contentStyle: {
    backgroundColor: "#1a1a2e",
    border: "1px solid rgba(255,255,255,0.1)",
    borderRadius: "8px",
    fontSize: "12px",
  },
  labelStyle: { color: "#e5e7eb" },
  itemStyle: { color: "#9ca3af" },
};

// ─── Main Component ──────────────────────────────────────────────────────────

export default function Analytics() {
  const [timeRange, setTimeRange] = useState("90d");

  const { data } = useQuery({
    queryKey: ["analytics-trends", timeRange],
    queryFn: () => dashboardApi.trends({ period: timeRange }),
  });

  const _ = data; // used for cache hydration

  // Compute KPIs from latest data point
  const latestMTTR = MTTR_DATA_90D[MTTR_DATA_90D.length - 1];
  const firstMTTR = MTTR_DATA_90D[0];
  const mttrImprovement = Math.round(
    ((firstMTTR.critical - latestMTTR.critical) / firstMTTR.critical) * 100
  );

  const latestNoise = NOISE_DATA_90D[NOISE_DATA_90D.length - 1];
  const firstNoise = NOISE_DATA_90D[0];
  const noiseReduction = Math.round(
    ((firstNoise.rawFindings - latestNoise.rawFindings) / firstNoise.rawFindings) * 100
  );

  const latestSLA = SLA_DATA_90D[SLA_DATA_90D.length - 1];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Analytics"
        description="MTTR trends, noise reduction metrics, SLA compliance, and scanner ROI comparison"
        actions={
          <div className="flex items-center gap-2">
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-32">
                <Calendar className="mr-2 h-4 w-4" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30d">Last 30 days</SelectItem>
                <SelectItem value="90d">Last 90 days</SelectItem>
                <SelectItem value="180d">Last 180 days</SelectItem>
                <SelectItem value="365d">Last Year</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="sm"
              onClick={() => toast.success("Generating analytics export...")}
            >
              Export
            </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="MTTR Critical (days)"
          value={latestMTTR.critical.toFixed(1)}
          change={-mttrImprovement}
          changeLabel="improvement vs period start"
          icon={Clock}
          trend="up"
        />
        <KpiCard
          title="Noise Reduction"
          value={`${noiseReduction}%`}
          change={noiseReduction}
          changeLabel="raw → prioritized"
          icon={TrendingDown}
          trend="up"
        />
        <KpiCard
          title="Overall SLA Compliance"
          value={`${latestSLA.overall}%`}
          change={latestSLA.overall - SLA_DATA_90D[0].overall}
          changeLabel="vs period start"
          icon={Target}
          trend="up"
        />
        <KpiCard
          title="Critical SLA Compliance"
          value={`${latestSLA.critical}%`}
          change={latestSLA.critical - SLA_DATA_90D[0].critical}
          changeLabel="vs period start"
          icon={Shield}
          trend="up"
        />
      </div>

      {/* MTTR Trends */}
      <Card className="border-border/50">
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" />
                Mean Time to Remediate (MTTR) Trends
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-1">
                Days to remediate by severity — {timeRange} view
              </p>
            </div>
            <Badge variant="success" className="shrink-0">
              ↓ {mttrImprovement}% improvement
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={MTTR_DATA_90D} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis
                dataKey="week"
                tick={{ fill: "#6b7280", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#6b7280", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
                label={{ value: "Days", angle: -90, position: "insideLeft", fill: "#6b7280", fontSize: 11 }}
              />
              <Tooltip {...TOOLTIP_STYLE} />
              <Legend
                wrapperStyle={{ fontSize: "12px", color: "#9ca3af" }}
              />
              <ReferenceLine y={7} stroke="#ef4444" strokeDasharray="4 4" opacity={0.5} label={{ value: "SLA 7d", fill: "#ef4444", fontSize: 11 }} />
              <Line
                type="monotone"
                dataKey="critical"
                name="Critical"
                stroke="#ef4444"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
              <Line
                type="monotone"
                dataKey="high"
                name="High"
                stroke="#f59e0b"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
              <Line
                type="monotone"
                dataKey="medium"
                name="Medium"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
                activeDot={{ r: 4 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Noise Reduction */}
      <Card className="border-border/50">
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <TrendingDown className="h-4 w-4 text-primary" />
                Noise Reduction Over Time
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-1">
                Raw findings → after deduplication → after AI prioritization
              </p>
            </div>
            <Badge variant="success" className="shrink-0">
              ↓ {noiseReduction}% total noise
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={NOISE_DATA_90D} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="gradRaw" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6b7280" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6b7280" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gradDedup" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="gradPriority" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#14b8a6" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#14b8a6" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis
                dataKey="week"
                tick={{ fill: "#6b7280", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#6b7280", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip {...TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: "12px", color: "#9ca3af" }} />
              <Area
                type="monotone"
                dataKey="rawFindings"
                name="Raw Findings"
                stroke="#6b7280"
                fill="url(#gradRaw)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="afterDedup"
                name="After Dedup"
                stroke="#3b82f6"
                fill="url(#gradDedup)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="afterPriority"
                name="AI Prioritized"
                stroke="#14b8a6"
                fill="url(#gradPriority)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* SLA + Scanner ROI row */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        {/* SLA Compliance Trends */}
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" />
              SLA Compliance Trends
            </CardTitle>
            <p className="text-xs text-muted-foreground">% findings remediated within SLA window</p>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={SLA_DATA_90D} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis
                  dataKey="month"
                  tick={{ fill: "#6b7280", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#6b7280", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  domain={[50, 100]}
                />
                <Tooltip {...TOOLTIP_STYLE} formatter={(v: number) => `${v}%`} />
                <Legend wrapperStyle={{ fontSize: "11px", color: "#9ca3af" }} />
                <ReferenceLine y={90} stroke="#22c55e" strokeDasharray="4 4" opacity={0.5} label={{ value: "Target 90%", fill: "#22c55e", fontSize: 10 }} />
                <Bar dataKey="critical" name="Critical" fill="#ef4444" fillOpacity={0.85} radius={[2, 2, 0, 0]} />
                <Bar dataKey="high" name="High" fill="#f59e0b" fillOpacity={0.85} radius={[2, 2, 0, 0]} />
                <Bar dataKey="overall" name="Overall" fill="#14b8a6" fillOpacity={0.85} radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Scanner ROI */}
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="h-4 w-4 text-primary" />
              Scanner ROI Comparison
            </CardTitle>
            <p className="text-xs text-muted-foreground">
              Unique findings vs. false positives per scanner
            </p>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart
                data={SCANNER_ROI_DATA}
                layout="vertical"
                margin={{ top: 4, right: 16, left: 40, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" horizontal={false} />
                <XAxis
                  type="number"
                  tick={{ fill: "#6b7280", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  dataKey="scanner"
                  type="category"
                  tick={{ fill: "#6b7280", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip {...TOOLTIP_STYLE} />
                <Legend wrapperStyle={{ fontSize: "11px", color: "#9ca3af" }} />
                <Bar dataKey="uniqueFindings" name="Unique Findings" fill="#14b8a6" fillOpacity={0.85} radius={[0, 2, 2, 0]} />
                <Bar dataKey="falsePositives" name="False Positives" fill="#ef4444" fillOpacity={0.6} radius={[0, 2, 2, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          {
            title: "Best Scanner ROI",
            value: "Trivy",
            detail: "890 unique findings · 14.5% FP rate",
            icon: BarChart2,
            color: "text-teal-400",
          },
          {
            title: "Fastest MTTR Improvement",
            value: `${mttrImprovement}% faster`,
            detail: "Critical findings: 4.2 → 1.8 days",
            icon: TrendingUp,
            color: "text-green-400",
          },
          {
            title: "SLA Target Achievement",
            value: `${latestSLA.overall}% overall`,
            detail: "Exceeded 90% target this month",
            icon: Target,
            color: "text-blue-400",
          },
        ].map((stat) => {
          const Icon = stat.icon;
          return (
            <Card key={stat.title} className="border-border/50">
              <CardContent className="p-4 flex items-center gap-3">
                <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                  <Icon className={`h-5 w-5 ${stat.color}`} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">{stat.title}</p>
                  <p className="text-base font-bold">{stat.value}</p>
                  <p className="text-xs text-muted-foreground">{stat.detail}</p>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </motion.div>
  );
}
