/**
 * Security Posture Dashboard
 *
 * Overall security health and component scoring.
 *   1. Large score circle (74/100), grade B, trend +3pts
 *   2. 4 KPI cards
 *   3. 8 component score bars (lowest 3 highlighted red)
 *   4. Industry benchmark comparison (3 sectors)
 *   5. 12-month score history line chart (div-based)
 *   6. Top 5 improvement recommendations ranked by impact
 *
 * API stub: GET /api/v1/posture/score
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, TrendingUp, AlertTriangle, BarChart3,
  RefreshCw, Target, CheckCircle2, ChevronUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == API helpers ================================================
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const COMPONENTS = [
  { name: "Vulnerability Management", score: 68, weight: "25%", low: true },
  { name: "Identity Security",        score: 61, weight: "20%", low: true },
  { name: "Endpoint Protection",      score: 79, weight: "15%", low: false },
  { name: "Network Security",         score: 55, weight: "15%", low: true },
  { name: "Cloud Security Posture",   score: 82, weight: "10%", low: false },
  { name: "Compliance Coverage",      score: 87, weight: "8%",  low: false },
  { name: "Incident Response",        score: 76, weight: "5%",  low: false },
  { name: "Security Awareness",       score: 91, weight: "2%",  low: false },
];

const BENCHMARKS = [
  { sector: "Healthcare",  avg: 61, color: "bg-blue-500/60",   text: "text-blue-400"   },
  { sector: "Financial",   avg: 72, color: "bg-purple-500/60", text: "text-purple-400" },
  { sector: "Technology",  avg: 78, color: "bg-cyan-500/60",   text: "text-cyan-400"   },
];

const MY_SCORE = 74;

const HISTORY = [
  { month: "May",  score: 58 },
  { month: "Jun",  score: 60 },
  { month: "Jul",  score: 62 },
  { month: "Aug",  score: 63 },
  { month: "Sep",  score: 65 },
  { month: "Oct",  score: 66 },
  { month: "Nov",  score: 68 },
  { month: "Dec",  score: 69 },
  { month: "Jan",  score: 70 },
  { month: "Feb",  score: 71 },
  { month: "Mar",  score: 71 },
  { month: "Apr",  score: 74 },
];

const RECOMMENDATIONS = [
  { title: "Remediate critical identity vulnerabilities",    area: "Identity Security",        gain: 6, effort: "Medium", impact: "High" },
  { title: "Deploy network micro-segmentation",             area: "Network Security",         gain: 5, effort: "High",   impact: "High" },
  { title: "Implement automated vulnerability triage",      area: "Vulnerability Management", gain: 4, effort: "Low",    impact: "High" },
  { title: "Enable MFA on all privileged accounts",         area: "Identity Security",        gain: 3, effort: "Low",    impact: "Medium" },
  { title: "Integrate SIEM with endpoint telemetry",        area: "Endpoint Protection",      gain: 2, effort: "Medium", impact: "Medium" },
];

// == Helpers ====================================================

const SCORE_MIN = 45;
const SCORE_MAX = 100;

function scoreColor(score: number) {
  if (score < 65) return "text-red-400";
  if (score < 75) return "text-amber-400";
  return "text-green-400";
}

function scoreBg(score: number) {
  if (score < 65) return "bg-red-500";
  if (score < 75) return "bg-amber-500";
  return "bg-green-500";
}

function effortBadge(effort: string) {
  const cls =
    effort === "Low"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
    effort === "Medium" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-red-500/30 text-red-400 bg-red-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{effort} effort</Badge>;
}

// == Component ==================================================

export default function SecurityPostureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/posture-advisor/score?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-advisor/components?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-advisor/stats?org_id=${ORG_ID}`),
    ]).then(([scoreResult, componentsResult, statsResult]) => {
      const score      = scoreResult.status      === "fulfilled" ? scoreResult.value      : null;
      const components = componentsResult.status === "fulfilled" ? componentsResult.value : null;
      const stats      = statsResult.status      === "fulfilled" ? statsResult.value      : null;
      if (score || components || stats) {
        setLiveData({ score, components, stats });
      }
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveScore = liveData?.score?.overall_score ?? liveData?.score?.score ?? MY_SCORE;
  const liveGrade = liveData?.score?.grade ?? "B";
  const liveTrend = liveData?.score?.trend ?? liveData?.stats?.trend ?? "+3 pts this month";
  const liveComponents: typeof COMPONENTS =
    Array.isArray(liveData?.components)
      ? liveData.components.map((c: any) => ({
          name: c.name ?? c.component ?? c.domain,
          score: c.score ?? c.value ?? 0,
          weight: c.weight ?? "=",
          low: (c.score ?? c.value ?? 0) < 65,
        }))
      : COMPONENTS;
  const liveOverallScore = liveScore;
  const liveCriticalGaps = liveData?.stats?.critical_gaps ?? liveData?.stats?.gaps ?? 8;
  const liveDaysSince = liveData?.stats?.days_since_incident ?? 47;
  const livePercentile = liveData?.stats?.industry_percentile ?? liveData?.score?.percentile ?? "68th";

  const chartMin = SCORE_MIN;
  const chartRange = SCORE_MAX - chartMin;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Security Posture Score"
        description="Overall security health and component scoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* Score hero + KPIs */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        {/* Big score circle */}
        <Card className="lg:col-span-1 flex flex-col items-center justify-center py-8 border-blue-500/20">
          <CardContent className="flex flex-col items-center gap-3 p-0">
            <div
              className="relative flex items-center justify-center"
              style={{
                width: 140,
                height: 140,
                borderRadius: "50%",
                border: "8px solid hsl(var(--muted)/0.3)",
                boxShadow: "0 0 0 4px hsl(220 90% 56% / 0.15)",
              }}
            >
              <div
                className="absolute inset-0 rounded-full"
                style={{
                  background: `conic-gradient(hsl(220 90% 56%) ${MY_SCORE * 3.6}deg, transparent 0deg)`,
                  borderRadius: "50%",
                  mask: "radial-gradient(farthest-side, transparent calc(100% - 8px), black calc(100% - 8px))",
                  WebkitMask: "radial-gradient(farthest-side, transparent calc(100% - 8px), black calc(100% - 8px))",
                }}
              />
              <div className="flex flex-col items-center">
                <span className="text-4xl font-black tabular-nums text-foreground">{liveOverallScore}</span>
                <span className="text-xs text-muted-foreground">/100</span>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge className="text-base font-bold px-3 py-1 border border-blue-500/30 text-blue-400 bg-blue-500/10">
                Grade {liveGrade}
              </Badge>
            </div>
            <div className="flex items-center gap-1 text-green-400 text-sm font-medium">
              <ChevronUp className="h-4 w-4" />
              <span>{typeof liveTrend === "string" ? liveTrend : `+${liveTrend} pts this month`}</span>
            </div>
            <p className="text-[11px] text-muted-foreground text-center px-2">
              Above industry avg of 70.4
            </p>
          </CardContent>
        </Card>

        {/* KPI cards 2=2 */}
        <div className="lg:col-span-4 grid grid-cols-2 gap-3">
          <KpiCard title="Overall Score"       value={`${liveOverallScore}/100`} icon={Shield}        trend="up"   className="border-blue-500/20" />
          <KpiCard title="Industry Percentile" value={livePercentile}            icon={Target}        trend="up"   className="border-purple-500/20" />
          <KpiCard title="Days Since Incident" value={liveDaysSince}             icon={CheckCircle2}  trend="up"   className="border-green-500/20" />
          <KpiCard title="Critical Gaps"       value={liveCriticalGaps}          icon={AlertTriangle} trend="down" className="border-red-500/20" />
        </div>
      </div>

      {/* Component scores */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-blue-400" />
            Component Scores
          </CardTitle>
          <CardDescription className="text-xs">
            8 security domains = weighted contribution to overall score. Lowest 3 highlighted.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {liveComponents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            liveComponents.map((c) => (
            <div key={c.name} className={cn("space-y-1.5 rounded-lg p-2", c.low && "bg-red-500/5 border border-red-500/15")}>
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className={cn("font-medium", c.low ? "text-red-400" : "text-foreground")}>{c.name}</span>
                  <Badge className="text-[10px] border border-border text-muted-foreground bg-transparent">
                    Weight {c.weight}
                  </Badge>
                  {c.low && <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Low</Badge>}
                </div>
                <span className={cn("font-bold tabular-nums", scoreColor(c.score))}>{c.score}</span>
              </div>
              <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${c.score}%` }}
                  transition={{ duration: 0.8, ease: "easeOut" }}
                  )))}
                />
              </div>
            </div>
          )))}
        </CardContent>
      </Card>

      {/* Benchmark + History */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Benchmark */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-purple-400" />
              Industry Benchmark Comparison
            </CardTitle>
            <CardDescription className="text-xs">Your score vs. sector averages</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Your score bar */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-blue-400">Your Organization</span>
                <span className="font-bold tabular-nums">{liveOverallScore}</span>
              </div>
              <div className="relative h-3 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${liveOverallScore}%` }}
                  transition={{ duration: 0.8 }}
                  className="h-full rounded-full bg-blue-500"
                />
              </div>
            </div>
            {BENCHMARKS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              BENCHMARKS.map((b) => {
              const diff = liveOverallScore - b.avg;
              return (
                <div key={b.sector} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className={cn("font-medium", b.text)}>{b.sector} Avg</span>
                      <Badge className={cn(
                        "text-[10px] border",
                        diff >= 0
                          ? "border-green-500/30 text-green-400 bg-green-500/10"
                          : "border-red-500/30 text-red-400 bg-red-500/10"
                      )}>
                        {diff >= 0 ? `+${diff}` : diff} vs you
                      </Badge>
                    </div>
                    <span className="font-bold tabular-nums">{b.avg}</span>
                  </div>
                  <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${b.avg}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full", b.color)}
                    />
                  </div>
                </div>
              );
            })
            )}
          </CardContent>
        </Card>

        {/* 12-month history */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-green-400" />
              Score History (12 months)
            </CardTitle>
            <CardDescription className="text-xs">Monthly posture score trend</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="relative h-36">
              {/* Grid lines */}
              {[60, 70, 80].map((v) => (
                <div
                  key={v}
                  className="absolute left-0 right-0 border-t border-muted/20 flex items-center"
                  style={{ bottom: `${((v - chartMin) / chartRange) * 100}%` }}
                >
                  <span className="text-[9px] text-muted-foreground pr-1 -translate-y-2">{v}</span>
                </div>
              )))}
              {/* Bars */}
              <div className="absolute inset-0 flex items-end gap-1 pt-2">
                {HISTORY.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  HISTORY.map((h, i) => (
                  <div key={h.month} className="flex-1 flex flex-col items-center gap-0.5">
                    <motion.div
                      initial={{ height: 0 }}
                      animate={{ height: `${((h.score - chartMin) / chartRange) * 100}%` }}
                      transition={{ duration: 0.6, delay: i * 0.04 }}
                      className={cn(
                        "w-full rounded-t",
                        i === HISTORY.length - 1 ? "bg-blue-500" : "bg-blue-500/40"
                      )}
                      title={`${h.month}: ${h.score}`}
                    />
                    <span className="text-[8px] text-muted-foreground">{h.month.slice(0, 1)}</span>
                  </div>
                )))}
              </div>
            </div>
            <div className="mt-2 flex items-center gap-3 text-[10px] text-muted-foreground">
              <span>May 2025 = Apr 2026</span>
              <span className="text-green-400 font-semibold">+16 pts total improvement</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recommendations */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Target className="h-4 w-4 text-amber-400" />
            Improvement Recommendations
          </CardTitle>
          <CardDescription className="text-xs">Ranked by potential score impact = act on these to increase your posture score</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {RECOMMENDATIONS.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            RECOMMENDATIONS.map((r, i) => (
            <div
              key={r.title}
              className="flex items-start gap-3 p-3 rounded-lg border border-border bg-muted/10 hover:bg-muted/20 transition-colors"
            >
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-amber-500/20 border border-amber-500/30 flex items-center justify-center text-amber-400 text-xs font-bold">
                {i + 1}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-foreground">{r.title}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">{r.area}</p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                {effortBadge(r.effort)}
                <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10 font-bold">
                  +{r.gain} pts
                </Badge>
              </div>
            </div>
          )))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
