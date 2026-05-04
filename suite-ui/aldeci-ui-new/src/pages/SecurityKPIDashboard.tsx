/**
 * Security KPI Scorecard Dashboard
 *
 * CISO-level dashboard showing security KPIs:
 *   1. Overall Grade Badge
 *   2. Top 6 KPI Cards (MTTD, MTTR, Patch Compliance, Vuln Density, SLA Compliance, FP Rate)
 *   3. Industry Benchmarks Comparison Table
 *   4. 7-day Trend Charts (div-based sparklines, no chart library)
 *   5. Scorecard Breakdown by Category
 *   6. Strengths & Weaknesses Two-Column Layout
 *
 * API: GET /api/v1/kpi/scorecard, /api/v1/kpi/current
 * Fallback: mock data on API failure
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Clock,
  Zap,
  CheckCircle2,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  BarChart3,
  Shield,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type GradeLevel = "A" | "B" | "C" | "D" | "F";
type TrendDirection = "up" | "down" | "stable";
type BenchmarkStatus = "good" | "average" | "poor";

interface KPIMetric {
  id: string;
  name: string;
  value: number | string;
  unit: string;
  trend: TrendDirection;
  benchmark: BenchmarkStatus;
  industryAvg: number | string;
  target: number | string;
}

interface CategoryScore {
  category: string;
  score: number;
  controls_total: number;
  controls_passing: number;
  status: "good" | "warning" | "critical";
}

interface Strength {
  title: string;
  description: string;
  icon: "trend_up" | "check" | "target";
}

interface Weakness {
  title: string;
  description: string;
  icon: "warning" | "clock" | "alert";
  priority: "critical" | "high" | "medium";
}

// ══════════════════════════════════════════════════════════════
// Empty defaults (no mock data)
// ══════════════════════════════════════════════════════════════

const EMPTY_SCORECARD = {
  overall_grade: "C" as GradeLevel,
  overall_score: 0,
  last_updated: new Date().toISOString(),
  kpis: [] as KPIMetric[],
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function gradeColor(grade: GradeLevel): string {
  const map: Record<GradeLevel, string> = {
    A: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
    B: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
    C: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    D: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    F: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return map[grade];
}

function benchmarkColor(status: BenchmarkStatus): string {
  const map: Record<BenchmarkStatus, string> = {
    good: "bg-emerald-500/10 text-emerald-400",
    average: "bg-amber-500/10 text-amber-400",
    poor: "bg-red-500/10 text-red-400",
  };
  return map[status];
}

function trendIcon(trend: TrendDirection) {
  if (trend === "up") return <TrendingUp className="w-4 h-4 text-red-400" />;
  if (trend === "down") return <TrendingDown className="w-4 h-4 text-emerald-400" />;
  return <div className="w-4 h-4 rounded-full bg-slate-500" />;
}

function categoryColor(status: "good" | "warning" | "critical"): string {
  const map = {
    good: "bg-emerald-500/10 border-emerald-500/30",
    warning: "bg-amber-500/10 border-amber-500/30",
    critical: "bg-red-500/10 border-red-500/30",
  };
  return map[status];
}

function categoryTextColor(status: "good" | "warning" | "critical"): string {
  const map = {
    good: "text-emerald-400",
    warning: "text-amber-400",
    critical: "text-red-400",
  };
  return map[status];
}

// Render a simple 7-day sparkline using divs
function Sparkline({ data, label, trend }: { data: number[]; label: string; trend: TrendDirection }) {
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  return (
    <div className="space-y-1">
      <div className="text-xs text-slate-400">{label}</div>
      <div className="flex gap-0.5 h-8 items-end">
        {data.map((value, i) => {
          const height = ((value - min) / range) * 100;
          const bgColor =
            trend === "down"
              ? "bg-emerald-500/60"
              : trend === "up"
                ? "bg-red-500/60"
                : "bg-slate-500/60";
          return (
            <div
              key={i}
              className={cn("flex-1 rounded-sm", bgColor)}
              style={{ height: `${Math.max(height, 5)}%` }}
              title={`Day ${i + 1}: ${value}`}
            />
          );
        })}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function SecurityKPIDashboard() {
  const [isRefreshing, setIsRefreshing]       = useState(false);
  const [dataLoading, setDataLoading]         = useState(true);
  const [scorecard, setScorecard]             = useState(EMPTY_SCORECARD);
  const [categoryScores, setCategoryScores]   = useState<CategoryScore[]>([]);
  const [strengths, setStrengths]             = useState<Strength[]>([]);
  const [weaknesses, setWeaknesses]           = useState<Weakness[]>([]);
  const [trendData, setTrendData]             = useState<Record<string, number[]>>({});

  const load = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/kpis/scorecard?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/kpis/categories?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/kpis/strengths?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/kpis/weaknesses?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/kpis/trends?org_id=${ORG_ID}`),
    ]).then(([scRes, catRes, strRes, weakRes, trendRes]) => {
      if (scRes.status === "fulfilled") {
        const s = scRes.value;
        setScorecard({
          overall_grade: s.overall_grade ?? s.overall_health ?? "C",
          overall_score: s.overall_score ?? s.portfolio_score ?? 0,
          last_updated: s.last_updated ?? s.generated_at ?? new Date().toISOString(),
          kpis: Array.isArray(s.kpis) ? s.kpis.map((k: any) => ({
            id: k.id ?? k.name,
            name: k.name ?? k.display_name,
            value: k.value,
            unit: k.unit ?? "",
            trend: k.trend ?? "stable",
            benchmark: k.benchmark ?? (k.health === "green" ? "good" : k.health === "yellow" ? "average" : "poor"),
            industryAvg: k.industryAvg ?? k.industry_avg ?? k.target ?? k.value,
            target: k.target ?? k.value,
          })) : [],
        });
      }
      if (catRes.status === "fulfilled") setCategoryScores(catRes.value?.categories ?? catRes.value ?? []);
      if (strRes.status === "fulfilled") setStrengths(strRes.value?.strengths ?? strRes.value ?? []);
      if (weakRes.status === "fulfilled") setWeaknesses(weakRes.value?.weaknesses ?? weakRes.value ?? []);
      if (trendRes.status === "fulfilled") setTrendData(trendRes.value?.trends ?? trendRes.value ?? {});
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setIsRefreshing(true); load(); setTimeout(() => setIsRefreshing(false), 1000); };

  if (dataLoading) return <PageSkeleton />;

  const data = scorecard;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-4"
      >
        <PageHeader
          title="Security KPI Scorecard"
          description="CISO-level metrics dashboard with trend analysis and benchmarking"
        />

        {/* Grade Badge and Overall Metrics Row */}
        <div className="flex items-center justify-between gap-4">
          <motion.div
            initial={{ scale: 0.8 }}
            animate={{ scale: 1 }}
            className={cn(
              "flex items-center gap-4 px-6 py-4 rounded-lg border",
              gradeColor(data.overall_grade)
            )}
          >
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-slate-900/50 border-2 border-current">
              <span className="text-4xl font-bold">{data.overall_grade}</span>
            </div>
            <div>
              <div className="text-sm text-slate-400">Overall Security Grade</div>
              <div className="text-2xl font-bold">{data.overall_score}/100</div>
            </div>
          </motion.div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="gap-2"
          >
            <RefreshCw className={cn("w-4 h-4", isRefreshing && "animate-spin")} />
            {isRefreshing ? "Updating..." : "Refresh"}
          </Button>
        </div>
      </motion.div>

      {/* Top 6 KPI Cards */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
      >
        {data.kpis.map((kpi: KPIMetric, idx: number) => (
          <motion.div
            key={kpi.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.05 }}
          >
            <Card className="border-slate-800 bg-slate-950/40 hover:border-slate-700 transition-colors">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm text-slate-300 flex items-center justify-between">
                  <span>{kpi.name}</span>
                  {trendIcon(kpi.trend)}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-bold">{kpi.value}</span>
                  <span className="text-xs text-slate-400">{kpi.unit}</span>
                </div>

                <div className="space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400">vs Target</span>
                    <span className="text-slate-300 font-medium">{kpi.target} {kpi.unit}</span>
                  </div>
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400">vs Industry Avg</span>
                    <span className="text-slate-300 font-medium">
                      {kpi.industryAvg} {kpi.unit}
                    </span>
                  </div>
                </div>

                <Badge className={cn("w-full justify-center", benchmarkColor(kpi.benchmark))}>
                  {kpi.benchmark.charAt(0).toUpperCase() + kpi.benchmark.slice(1)}
                </Badge>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      {/* Benchmarks Table */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5" />
              Industry Benchmarks Comparison
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-800 hover:bg-transparent">
                    <TableHead className="text-slate-400">KPI</TableHead>
                    <TableHead className="text-slate-400 text-right">Your Score</TableHead>
                    <TableHead className="text-slate-400 text-right">Industry Avg</TableHead>
                    <TableHead className="text-slate-400 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.kpis.map((kpi: KPIMetric) => (
                    <TableRow key={kpi.id} className="border-slate-800/50 hover:bg-slate-900/20">
                      <TableCell className="text-sm font-medium text-slate-300">
                        {kpi.name}
                      </TableCell>
                      <TableCell className="text-right text-slate-300 font-semibold">
                        {kpi.value} {kpi.unit}
                      </TableCell>
                      <TableCell className="text-right text-slate-400">
                        {kpi.industryAvg} {kpi.unit}
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge className={benchmarkColor(kpi.benchmark)}>
                          {kpi.benchmark.charAt(0).toUpperCase() + kpi.benchmark.slice(1)}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Trend Charts Section */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              7-Day Trend Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 p-4 bg-slate-900/20 rounded-lg">
              {Object.keys(trendData).length === 0 ? (
                <p className="text-xs text-slate-500 col-span-3">No trend data available.</p>
              ) : (
                Object.entries(trendData).map(([key, values]) => (
                  <Sparkline key={key} data={values} label={key.replace(/_/g, " ")} trend="stable" />
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Scorecard Breakdown by Category */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
      >
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Scorecard Breakdown by Category
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {categoryScores.length === 0 ? (
              <p className="text-xs text-slate-500">No category data available.</p>
            ) : null}
            {categoryScores.map((cat) => (
              <motion.div
                key={cat.category}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className={cn(
                  "p-4 rounded-lg border",
                  categoryColor(cat.status)
                )}
              >
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h4 className="font-semibold text-slate-200">{cat.category}</h4>
                    <p className="text-xs text-slate-400">
                      {cat.controls_passing}/{cat.controls_total} controls passing
                    </p>
                  </div>
                  <span className={cn("text-2xl font-bold", categoryTextColor(cat.status))}>
                    {cat.score}
                  </span>
                </div>
                <Progress
                  value={cat.score}
                  className="h-2 bg-slate-900/30"
                />
              </motion.div>
            ))}
          </CardContent>
        </Card>
      </motion.div>

      {/* Strengths & Weaknesses */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {/* Strengths */}
        <Card className="border-emerald-500/20 bg-emerald-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
              Strengths
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {strengths.length === 0 && <p className="text-xs text-slate-500">No strengths data available.</p>}
            {strengths.map((strength, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.1 }}
                className="border-l-2 border-emerald-500/30 pl-3 py-1"
              >
                <h4 className="font-semibold text-slate-200">{strength.title}</h4>
                <p className="text-sm text-slate-400 mt-1">{strength.description}</p>
              </motion.div>
            ))}
          </CardContent>
        </Card>

        {/* Weaknesses */}
        <Card className="border-orange-500/20 bg-orange-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-orange-400">
              <AlertTriangle className="w-5 h-5" />
              Weaknesses & Opportunities
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {weaknesses.length === 0 && <p className="text-xs text-slate-500">No weaknesses data available.</p>}
            {weaknesses.map((weakness, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.1 }}
                className={cn(
                  "border-l-2 pl-3 py-1",
                  weakness.priority === "critical"
                    ? "border-red-500/40"
                    : weakness.priority === "high"
                      ? "border-orange-500/40"
                      : "border-amber-500/40"
                )}
              >
                <div className="flex items-center justify-between">
                  <h4 className="font-semibold text-slate-200">{weakness.title}</h4>
                  <Badge
                    className={cn(
                      "text-xs",
                      weakness.priority === "critical"
                        ? "bg-red-500/20 text-red-400"
                        : weakness.priority === "high"
                          ? "bg-orange-500/20 text-orange-400"
                          : "bg-amber-500/20 text-amber-400"
                    )}
                  >
                    {weakness.priority}
                  </Badge>
                </div>
                <p className="text-sm text-slate-400 mt-1">{weakness.description}</p>
              </motion.div>
            ))}
          </CardContent>
        </Card>
      </motion.div>

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="text-center text-xs text-slate-500 pt-4"
      >
        Last updated: {new Date(data.last_updated).toLocaleString()}
      </motion.div>
    </div>
  );
}
