/**
 * Security Scorecard Dashboard
 *
 * Overall organizational security grade with domain breakdown and benchmarking.
 *   1. Overall grade circle (A/B/C/D/F, large, color-coded)
 *   2. 6 domain score progress bars: Identity, Endpoint, Network, Cloud, Data, Application
 *   3. 30-day score trend chart (div-based bar chart)
 *   4. Peer benchmarking panel — percentile rank vs. industry
 *   5. "Generate Scorecard" button → POST /api/v1/security-scorecard/scorecards
 *
 * API: GET /api/v1/security-scorecard/ (mock until router deployed)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Award,
  BarChart3,
  TrendingUp,
  TrendingDown,
  RefreshCw,
  Users,
  Target,
  Shield,
  Loader2,
  CheckCircle2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

interface DomainScore {
  domain: string;
  score: number;
  grade: string;
}

interface TrendPoint {
  day: string;
  score: number;
}

interface ScorecardData {
  overall_score: number;
  grade: string;
  percentile_rank: number;
  domains: DomainScore[];
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SCORECARD: ScorecardData = {
  overall_score: 87,
  grade: "B",
  percentile_rank: 73,
  domains: [
    { domain: "Identity",    score: 91, grade: "A" },
    { domain: "Endpoint",    score: 84, grade: "B" },
    { domain: "Network",     score: 79, grade: "C" },
    { domain: "Cloud",       score: 88, grade: "B" },
    { domain: "Data",        score: 92, grade: "A" },
    { domain: "Application", score: 83, grade: "B" },
  ],
};

// 30-day trend (weekly buckets, approx)
const TREND_DATA: TrendPoint[] = [
  { day: "Mar 17", score: 79 },
  { day: "Mar 20", score: 81 },
  { day: "Mar 23", score: 80 },
  { day: "Mar 26", score: 83 },
  { day: "Mar 29", score: 82 },
  { day: "Apr 1",  score: 84 },
  { day: "Apr 4",  score: 83 },
  { day: "Apr 7",  score: 85 },
  { day: "Apr 10", score: 86 },
  { day: "Apr 13", score: 85 },
  { day: "Apr 16", score: 87 },
];

const TREND_MIN = 70;
const TREND_MAX = 100;

// Peer benchmarking data
const PEER_DATA = [
  { label: "Top 10%",   threshold: 94, highlight: false },
  { label: "Top 25%",   threshold: 90, highlight: false },
  { label: "Top 50%",   threshold: 83, highlight: false },
  { label: "You",       threshold: 87, highlight: true  },
  { label: "Industry Avg", threshold: 78, highlight: false },
  { label: "Bottom 25%",  threshold: 65, highlight: false },
];

// ── Helpers ────────────────────────────────────────────────────

function gradeColor(grade: string): { text: string; bg: string; border: string; ring: string } {
  switch (grade) {
    case "A":
      return { text: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30",  ring: "border-green-400" };
    case "B":
      return { text: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   ring: "border-blue-400" };
    case "C":
      return { text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", ring: "border-yellow-400" };
    case "D":
      return { text: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/30",  ring: "border-amber-400" };
    case "F":
      return { text: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    ring: "border-red-500" };
    default:
      return { text: "text-muted-foreground", bg: "bg-muted", border: "border-muted", ring: "border-muted" };
  }
}

function domainBarColor(score: number): string {
  if (score >= 90) return "bg-green-500";
  if (score >= 80) return "bg-blue-500";
  if (score >= 70) return "bg-yellow-500";
  return "bg-red-500";
}

function scoreToPercent(score: number): number {
  return ((score - TREND_MIN) / (TREND_MAX - TREND_MIN)) * 100;
}

// ── Grade Circle ───────────────────────────────────────────────

function GradeCircle({ grade, score }: { grade: string; score: number }) {
  const colors = gradeColor(grade);
  return (
    <div className="flex flex-col items-center gap-3">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <div
        className={cn(
          "w-36 h-36 rounded-full border-8 flex flex-col items-center justify-center shadow-lg transition-all",
          colors.ring,
          colors.bg
        )}
      >
        <span className={cn("text-5xl font-black leading-none", colors.text)}>{grade}</span>
        <span className="text-xs text-muted-foreground mt-1 font-medium">{score} / 100</span>
      </div>
      <Badge className={cn("border text-xs px-3 py-0.5", colors.bg, colors.border, colors.text)}>
        {grade === "A"
          ? "Excellent"
          : grade === "B"
          ? "Good"
          : grade === "C"
          ? "Acceptable"
          : grade === "D"
          ? "At Risk"
          : "Critical"}
      </Badge>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────

export default function SecurityScorecardDashboard() {
  const [scorecard, setScorecard] = useState<ScorecardData>(MOCK_SCORECARD);
  const [refreshing, setRefreshing] = useState(false);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    apiFetch(`/api/v1/security-scorecard/?org_id=${ORG_ID}`).then((d) => {
      if (d?.overall_score !== undefined) setScorecard(d);
    }).catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);
  const [generated, setGenerated] = useState(false);
  const [loading, setLoading] = useState(true);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await fetch("/api/v1/security-scorecard/scorecards", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ org_id: "aldeci-demo", period: "Q2 2026" }),
      });
    } catch {
      // Mock — API may not be deployed yet
    }
    setTimeout(() => {
      setGenerating(false);
      setGenerated(true);
      setTimeout(() => setGenerated(false), 3000);
    }, 1200);
  };

  const trendChange = TREND_DATA[TREND_DATA.length - 1].score - TREND_DATA[0].score;
  const trendUp = trendChange >= 0;

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
        title="Security Scorecard"
        description="Organizational security grade, domain scores, and peer benchmarking"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button
              size="sm"
              onClick={handleGenerate}
              disabled={generating}
              className="gap-1.5"
            >
              {generating ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : generated ? (
                <CheckCircle2 className="h-4 w-4 text-green-400" />
              ) : (
                <Award className="h-4 w-4" />
              )}
              {generating ? "Generating…" : generated ? "Generated!" : "Generate Scorecard"}
            </Button>
          </div>
        }
      />

      {/* Top row: Grade + KPIs */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Grade circle */}
        <Card className="flex flex-col items-center justify-center py-8 lg:col-span-1">
          <GradeCircle grade={scorecard.grade} score={scorecard.overall_score} />
        </Card>

        {/* KPIs */}
        <div className="lg:col-span-3 grid grid-cols-1 sm:grid-cols-3 gap-3 content-start">
          <KpiCard
            title="Overall Score"
            value={`${scorecard.overall_score}/100`}
            icon={Shield}
            trend="up"
            className="border-blue-500/20"
          />
          <KpiCard
            title="Percentile Rank"
            value={`${scorecard.percentile_rank}th`}
            icon={Users}
            trend="up"
            className="border-purple-500/20"
          />
          <KpiCard
            title="30-Day Trend"
            value={`${trendUp ? "+" : ""}${trendChange} pts`}
            icon={trendUp ? TrendingUp : TrendingDown}
            trend={trendUp ? "up" : "down"}
            className={trendUp ? "border-green-500/20" : "border-red-500/20"}
          />
        </div>
      </div>

      {/* Domain scores */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Target className="h-4 w-4 text-indigo-400" />
            Domain Score Breakdown
          </CardTitle>
          <CardDescription className="text-xs">Security score across 6 key domains</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-4">
            {scorecard.domains.map((d) => {
              const colors = gradeColor(d.grade);
              return (
                <div key={d.domain} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium">{d.domain}</span>
                    <div className="flex items-center gap-2">
                      <Badge
                        className={cn(
                          "text-[10px] px-1.5 py-0 border h-4",
                          colors.bg,
                          colors.border,
                          colors.text
                        )}
                      >
                        {d.grade}
                      </Badge>
                      <span className="text-xs tabular-nums font-bold">{d.score}</span>
                    </div>
                  </div>
                  <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${d.score}%` }}
                      transition={{ duration: 0.6, delay: 0.1 }}
                      className={cn("h-full rounded-full", domainBarColor(d.score))}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Trend chart + Peer benchmarking */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* 30-day trend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Score Trend — Last 30 Days
            </CardTitle>
            <CardDescription className="text-xs">
              {trendUp ? "+" : ""}{trendChange} points over period
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-1.5 h-36">
              {TREND_DATA.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                TREND_DATA.map((pt, i) => {
                const pct = scoreToPercent(pt.score);
                const isLatest = i === TREND_DATA.length - 1;
                return (
                  <div key={pt.day} className="flex-1 flex flex-col items-center gap-0.5">
                    <span className="text-[9px] text-muted-foreground tabular-nums">{pt.score}</span>
                    <div
                      className={cn(
                        "w-full rounded-t transition-all",
                        isLatest ? "bg-blue-400" : "bg-blue-500/50"
                      )}
                      style={{ height: `${Math.max(pct, 4)}%`, minHeight: "4px", maxHeight: "100px" }}
                      title={`${pt.day}: ${pt.score}`}
                    />
                    <span className="text-[8px] text-muted-foreground leading-tight text-center">
                      {pt.day.split(" ")[1]}
                    </span>
                  </div>
                );
              })}
              )}
            </div>
            <div className="flex items-center justify-between text-[10px] text-muted-foreground mt-2">
              <span>{TREND_DATA[0].day}</span>
              <span className="flex items-center gap-1">
                {trendUp
                  ? <TrendingUp className="h-3 w-3 text-green-400" />
                  : <TrendingDown className="h-3 w-3 text-red-400" />}
                <span className={trendUp ? "text-green-400" : "text-red-400"}>
                  {trendUp ? "+" : ""}{trendChange} pts
                </span>
              </span>
              <span>{TREND_DATA[TREND_DATA.length - 1].day}</span>
            </div>
          </CardContent>
        </Card>

        {/* Peer benchmarking */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-purple-400" />
              Peer Benchmarking
            </CardTitle>
            <CardDescription className="text-xs">
              You are in the <span className="text-purple-300 font-medium">{scorecard.percentile_rank}th percentile</span> vs. industry peers
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2.5">
              {PEER_DATA.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                PEER_DATA.map((p) => (
                <div key={p.label} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span
                      className={cn(
                        "text-xs font-medium",
                        p.highlight ? "text-purple-300" : "text-muted-foreground"
                      )}
                    >
                      {p.highlight ? "▶ " : ""}{p.label}
                    </span>
                    <span
                      className={cn(
                        "text-xs tabular-nums font-bold",
                        p.highlight ? "text-purple-300" : "text-foreground"
                      )}
                    >
                      {p.threshold}
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-muted/40 overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all",
                        p.highlight ? "bg-purple-400" : "bg-muted-foreground/40"
                      )}
                      style={{ width: `${p.threshold}%` }}
                    />
                  </div>
                </div>
              ))}
              )}
            </div>
            <div className="mt-4 rounded-md border border-purple-500/20 bg-purple-500/5 px-3 py-2.5">
              <p className="text-[11px] text-purple-300 font-medium">
                You outperform {scorecard.percentile_rank}% of organizations in your industry.
              </p>
              <p className="text-[10px] text-muted-foreground mt-0.5">
                Top 25% threshold: 90 pts &mdash; you need <span className="font-medium text-foreground">+3 pts</span> to reach it.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
