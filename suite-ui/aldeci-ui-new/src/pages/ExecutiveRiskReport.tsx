/**
 * Executive Risk Report
 *
 * Board-level security posture summary for C-suite and board members.
 *   1. Header with Download PDF + Schedule Report buttons
 *   2. Overall Risk Rating — large centered grade card with trend
 *   3. 5 Pillar Scores — SVG circular gauges
 *   4. Top 3 Business Risks — non-technical language with impact
 *   5. Wins This Quarter — green achievement cards
 *   6. Peer Benchmarking — horizontal comparison bars
 *   7. Investment Recommendations — table with cost/risk-reduction/priority
 *   8. 6-Quarter Trend Chart — CSS/div bar chart
 *
 * API: GET /api/v1/executive-report/summary
 * Fallback: mock data on API failure
 */

import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Download,
  Calendar,
  TrendingUp,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Users,
  Database,
  Eye,
  FileCheck,
  RefreshCw,
  DollarSign,
  ArrowUpRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

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

type GradeLetter = "A" | "B" | "C" | "D" | "F";
type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type InvestmentPriority = "critical" | "high" | "medium";

interface PillarScore {
  name: string;
  score: number;
  icon: "identity" | "vuln" | "detection" | "data" | "compliance";
  industryAvg: number;
  topQuartile: number;
}

interface BusinessRisk {
  title: string;
  description: string;
  level: RiskLevel;
  impact: string;
}

interface QuarterlyWin {
  title: string;
  detail: string;
}

interface InvestmentRec {
  initiative: string;
  estimatedCost: string;
  riskReduction: string;
  priority: InvestmentPriority;
}

interface QuarterScore {
  quarter: string;
  score: number;
}

interface ExecutiveReportData {
  current_month: string;
  year: number;
  overall_grade: GradeLetter;
  overall_grade_plus: string;
  overall_score: number;
  previous_grade: string;
  score_change: number;
  summary_sentence: string;
  pillars: PillarScore[];
  business_risks: BusinessRisk[];
  quarterly_wins: QuarterlyWin[];
  investment_recommendations: InvestmentRec[];
  quarterly_trend: QuarterScore[];
  last_updated: string;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_DATA: ExecutiveReportData = {
  current_month: "April",
  year: 2026,
  overall_grade: "B",
  overall_grade_plus: "B+",
  overall_score: 82,
  previous_grade: "C+",
  score_change: 12,
  summary_sentence:
    "Your security posture improved 12 points this quarter driven by MFA rollout and patch cadence improvements.",
  pillars: [
    {
      name: "Identity & Access",
      score: 78,
      icon: "identity",
      industryAvg: 65,
      topQuartile: 88,
    },
    {
      name: "Vulnerability Management",
      score: 64,
      icon: "vuln",
      industryAvg: 58,
      topQuartile: 82,
    },
    {
      name: "Threat Detection",
      score: 71,
      icon: "detection",
      industryAvg: 60,
      topQuartile: 85,
    },
    {
      name: "Data Protection",
      score: 85,
      icon: "data",
      industryAvg: 70,
      topQuartile: 91,
    },
    {
      name: "Compliance",
      score: 89,
      icon: "compliance",
      industryAvg: 74,
      topQuartile: 95,
    },
  ],
  business_risks: [
    {
      title: "Critical Vulnerabilities in Internet-Facing Systems",
      description:
        "23 internet-facing systems have critical vulnerabilities that could allow unauthorized access",
      level: "CRITICAL",
      impact: "$2.4M potential impact",
    },
    {
      title: "Finance Systems Lack Multi-Factor Authentication",
      description:
        "Finance systems lack MFA — credential theft would give direct access to payment infrastructure",
      level: "HIGH",
      impact: "$800K potential impact",
    },
    {
      title: "PCI-DSS Quarterly Scan Overdue",
      description: "PCI-DSS quarterly scan overdue by 12 days — audit finding risk",
      level: "MEDIUM",
      impact: "Compliance exposure",
    },
  ],
  quarterly_wins: [
    {
      title: "MFA Deployed to 94% of Workforce",
      detail: "Up from 61% last quarter — significantly reduces credential-based attack surface",
    },
    {
      title: "Critical CVE Patch Time Cut by 62%",
      detail: "Mean time to patch critical CVEs reduced from 21 days to 8 days",
    },
    {
      title: "Zero Confirmed Data Breaches This Quarter",
      detail: "No confirmed data loss incidents — sustained for 3 consecutive quarters",
    },
  ],
  investment_recommendations: [
    {
      initiative: "Endpoint Detection & Response (EDR) Deployment",
      estimatedCost: "$45K",
      riskReduction: "-18 pts",
      priority: "critical",
    },
    {
      initiative: "Network Segmentation Project",
      estimatedCost: "$120K",
      riskReduction: "-22 pts",
      priority: "high",
    },
    {
      initiative: "Security Awareness Training Program",
      estimatedCost: "$8K",
      riskReduction: "-6 pts",
      priority: "medium",
    },
  ],
  quarterly_trend: [
    { quarter: "Q3 2024", score: 54 },
    { quarter: "Q4 2024", score: 59 },
    { quarter: "Q1 2025", score: 63 },
    { quarter: "Q2 2025", score: 68 },
    { quarter: "Q3 2025", score: 70 },
    { quarter: "Q4 2025 / Q1 2026", score: 82 },
  ],
  last_updated: "2026-04-16T08:00:00Z",
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function gradeColorClass(grade: GradeLetter): string {
  const map: Record<GradeLetter, string> = {
    A: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
    B: "bg-cyan-500/20 text-cyan-400 border-cyan-500/40",
    C: "bg-amber-500/20 text-amber-400 border-amber-500/40",
    D: "bg-orange-500/20 text-orange-400 border-orange-500/40",
    F: "bg-red-500/20 text-red-400 border-red-500/40",
  };
  return map[grade];
}

function riskBadgeClass(level: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    LOW: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  };
  return map[level];
}

function priorityBadgeClass(priority: InvestmentPriority): string {
  const map: Record<InvestmentPriority, string> = {
    critical: "bg-red-500/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-amber-500/20 text-amber-400",
  };
  return map[priority];
}

function pillarIconEl(icon: PillarScore["icon"]) {
  const cls = "w-5 h-5";
  switch (icon) {
    case "identity":
      return <Users className={cls} />;
    case "vuln":
      return <AlertTriangle className={cls} />;
    case "detection":
      return <Eye className={cls} />;
    case "data":
      return <Database className={cls} />;
    case "compliance":
      return <FileCheck className={cls} />;
  }
}

function pillarGaugeColor(score: number): string {
  if (score >= 80) return "#10b981"; // emerald
  if (score >= 65) return "#06b6d4"; // cyan
  if (score >= 50) return "#f59e0b"; // amber
  return "#ef4444"; // red
}

// SVG circular gauge
function CircularGauge({ score, size = 96 }: { score: number; size?: number }) {
  const r = (size - 12) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const filled = (score / 100) * circumference;
  const color = pillarGaugeColor(score);

  return (
    <svg width={size} height={size} className="-rotate-90">
      {/* Track */}
      <circle
        cx={cx}
        cy={cy}
        r={r}
        fill="none"
        stroke="rgba(100,116,139,0.2)"
        strokeWidth={8}
      />
      {/* Fill */}
      <circle
        cx={cx}
        cy={cy}
        r={r}
        fill="none"
        stroke={color}
        strokeWidth={8}
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference - filled}`}
        strokeDashoffset={0}
      />
    </svg>
  );
}

// Horizontal benchmark bar row
function BenchmarkBar({
  label,
  yourScore,
  industryAvg,
  topQuartile,
}: {
  label: string;
  yourScore: number;
  industryAvg: number;
  topQuartile: number;
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs">
        <span className="text-slate-300 font-medium">{label}</span>
        <span className="text-slate-500">{yourScore} / {industryAvg} / {topQuartile}</span>
      </div>
      <div className="relative h-6 bg-slate-900/40 rounded overflow-hidden">
        {/* Top quartile background */}
        <div
          className="absolute top-0 left-0 h-full bg-emerald-500/10 rounded"
          style={{ width: `${topQuartile}%` }}
        />
        {/* Industry avg marker */}
        <div
          className="absolute top-0 h-full w-px bg-slate-400/50"
          style={{ left: `${industryAvg}%` }}
        />
        {/* Your score bar */}
        <div
          className="absolute top-1 bottom-1 left-0 rounded transition-all"
          style={{
            width: `${yourScore}%`,
            backgroundColor: pillarGaugeColor(yourScore),
            opacity: 0.85,
          }}
        />
        {/* Labels overlay */}
        <div className="absolute inset-0 flex items-center px-2 gap-2 pointer-events-none">
          <span className="text-[10px] text-white/80 font-semibold z-10">{yourScore}</span>
        </div>
      </div>
      <div className="flex gap-3 text-[10px] text-slate-500">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-sm bg-cyan-500/80 inline-block" />
          You
        </span>
        <span className="flex items-center gap-1">
          <span className="w-px h-3 bg-slate-400/50 inline-block" />
          Industry avg ({industryAvg})
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-sm bg-emerald-500/40 inline-block" />
          Top quartile ({topQuartile})
        </span>
      </div>
    </div>
  );
}

// CSS bar chart for quarterly trend
function QuarterlyBarChart({ data }: { data: QuarterScore[] }) {
  const max = Math.max(...data.map((d) => d.score));

  return (
    <div className="flex items-end gap-3 h-32 px-2">
      {data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
          <p className="text-lg font-medium">No data available</p>
          <p className="text-sm">Data will appear here once available</p>
        </div>
      ) : (
        data.map((d, i) => {
        const heightPct = (d.score / max) * 100;
        const isLatest = i === data.length - 1;
        return (
          <div key={d.quarter} className="flex-1 flex flex-col items-center gap-1">
            <span className="text-xs font-bold text-slate-300">{d.score}</span>
            <div className="w-full flex items-end" style={{ height: "80px" }}>
              <div
                className={cn(
                  "w-full rounded-t transition-all",
                  isLatest ? "bg-cyan-500/70" : "bg-slate-600/50"
                )}
                style={{ height: `${heightPct}%` }}
                title={`${d.quarter}: ${d.score}`}
              />
            </div>
            <span
              className="text-[9px] text-slate-500 text-center leading-tight"
              style={{ maxWidth: "60px" }}
            >
              {d.quarter}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function ExecutiveRiskReport() {
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [liveSupplemental, setLiveSupplemental] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // Fetch supplemental data from real endpoints
  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/risk-quantification/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/kpis/executive?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-advisor/stats?org_id=${ORG_ID}`),
    ]).then(([riskResult, kpiResult, postureResult]) => {
      const riskStats = riskResult.status   === "fulfilled" ? riskResult.value   : null;
      const kpis      = kpiResult.status    === "fulfilled" ? kpiResult.value    : null;
      const posture   = postureResult.status === "fulfilled" ? postureResult.value : null;
      if (riskStats || kpis || posture) {
        setLiveSupplemental({ riskStats, kpis, posture });
      }
    })
      .finally(() => setLoading(false));
  }, []);

  const { data: report, isLoading } = useQuery({
    queryKey: ["executive-report-summary"],
    queryFn: async () => {
      try {
        // GET /api/v1/reports/executive — returns list sorted newest-first
        const res = await fetch(
          `${API_BASE}/api/v1/reports/executive?org_id=${ORG_ID}&limit=1`,
          { headers: { "X-API-Key": API_KEY } },
        );
        if (!res.ok) throw new Error("API error");
        const list = await res.json();
        // Router returns an array; take the first (most recent) report
        const raw = Array.isArray(list) ? list[0] : list;
        if (!raw) return MOCK_DATA;
        // Map engine fields → UI shape (fall back to mock for any missing fields)
        return {
          ...MOCK_DATA,
          current_month: raw.current_month ?? MOCK_DATA.current_month,
          year: raw.year ?? MOCK_DATA.year,
          overall_grade: raw.overall_grade ?? MOCK_DATA.overall_grade,
          overall_grade_plus: raw.overall_grade_plus ?? raw.overall_grade ?? MOCK_DATA.overall_grade_plus,
          overall_score: raw.overall_score ?? MOCK_DATA.overall_score,
          previous_grade: raw.previous_grade ?? MOCK_DATA.previous_grade,
          score_change: raw.score_change ?? MOCK_DATA.score_change,
          summary_sentence: raw.summary_sentence ?? raw.executive_summary ?? MOCK_DATA.summary_sentence,
          pillars: raw.pillars ?? MOCK_DATA.pillars,
          business_risks: raw.business_risks ?? raw.top_risks ?? MOCK_DATA.business_risks,
          quarterly_wins: raw.quarterly_wins ?? raw.wins ?? MOCK_DATA.quarterly_wins,
          investment_recommendations: raw.investment_recommendations ?? raw.recommendations ?? MOCK_DATA.investment_recommendations,
          quarterly_trend: raw.quarterly_trend ?? raw.trend ?? MOCK_DATA.quarterly_trend,
          last_updated: raw.last_updated ?? raw.generated_at ?? MOCK_DATA.last_updated,
        } as ExecutiveReportData;
      } catch {
        return MOCK_DATA;
      }
    },
    staleTime: 10 * 60 * 1000,
  });

  const handleRefresh = async () => {
    setIsRefreshing(true);
    // Refresh supplemental data too
    Promise.allSettled([
      apiFetch(`/api/v1/risk-quantification/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/kpis/executive?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-advisor/stats?org_id=${ORG_ID}`),
    ]).then(([riskResult, kpiResult, postureResult]) => {
      const riskStats = riskResult.status   === "fulfilled" ? riskResult.value   : null;
      const kpis      = kpiResult.status    === "fulfilled" ? kpiResult.value    : null;
      const posture   = postureResult.status === "fulfilled" ? postureResult.value : null;
      if (riskStats || kpis || posture) {
        setLiveSupplemental({ riskStats, kpis, posture });
      }
    });
    await new Promise((resolve) => setTimeout(resolve, 800));
    setIsRefreshing(false);
  };

  if (isLoading) return <PageSkeleton />;

  const d = report ?? MOCK_DATA;

  // Overlay live data onto the report where available
  const liveScore: number =
    liveSupplemental?.posture?.total_recommendations != null
      ? undefined as unknown as number  // posture/stats doesn't have a score — skip
      : liveSupplemental?.kpis?.overall_score ?? d.overall_score;
  const displayScore = typeof liveScore === "number" && !isNaN(liveScore) ? liveScore : d.overall_score;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="space-y-6 p-6">
      {/* ── Header ── */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="space-y-4"
      >
        <div className="flex items-start justify-between gap-4">
          <PageHeader
            title="Executive Risk Report"
            description={`Board-level security posture summary for ${d.current_month} ${d.year}`}
          />
          <div className="flex items-center gap-2 shrink-0 pt-1">
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
            <div className="relative group">
              <Button variant="outline" size="sm" className="gap-2" disabled>
                <Download className="w-4 h-4" />
                Download PDF
              </Button>
              <span className="absolute -bottom-7 left-1/2 -translate-x-1/2 text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap pointer-events-none z-10">
                Coming Soon
              </span>
            </div>
            <Button variant="outline" size="sm" className="gap-2">
              <Calendar className="w-4 h-4" />
              Schedule Report
            </Button>
          </div>
        </div>
      </motion.div>

      {/* ── Overall Risk Rating ── */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.05 }}
      >
        <Card className={cn("border-2 text-center", gradeColorClass(d.overall_grade))}>
          <CardContent className="pt-8 pb-8 space-y-4">
            {/* Grade circle */}
            <div className="flex justify-center">
              <div
                className={cn(
                  "flex items-center justify-center w-28 h-28 rounded-full border-4 border-current bg-slate-950/60"
                )}
              >
                <span className="text-6xl font-black tracking-tight">{d.overall_grade_plus}</span>
              </div>
            </div>

            {/* Score + trend */}
            <div className="flex items-center justify-center gap-4">
              <span className="text-3xl font-bold text-slate-100">{displayScore}/100</span>
              <div className="flex items-center gap-1 bg-emerald-500/20 text-emerald-400 rounded-full px-3 py-1 text-sm font-semibold">
                <TrendingUp className="w-4 h-4" />
                <span>
                  ▲ Improved from {d.previous_grade} (+{d.score_change} pts)
                </span>
              </div>
            </div>

            <p className="text-slate-300 max-w-xl mx-auto text-base">{d.summary_sentence}</p>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── 5 Pillar Scores ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Security Pillar Scores
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
              {d.pillars.map((pillar, idx) => (
                <motion.div
                  key={pillar.name}
                  initial={{ opacity: 0, y: 16 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 + idx * 0.06 }}
                  className="flex flex-col items-center gap-2 p-4 rounded-lg bg-slate-900/30 border border-slate-800 hover:border-slate-700 transition-colors"
                >
                  <div className="relative">
                    <CircularGauge score={pillar.score} size={88} />
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span
                        className="text-xl font-bold"
                        style={{ color: pillarGaugeColor(pillar.score) }}
                      >
                        {pillar.score}
                      </span>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    {pillarIconEl(pillar.icon)}
                  </div>
                  <span className="text-xs text-slate-300 text-center font-medium leading-tight">
                    {pillar.name}
                  </span>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Top 3 Business Risks ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-orange-400">
              <AlertTriangle className="w-5 h-5" />
              Top Business Risks
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {d.business_risks.map((risk, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.2 + idx * 0.07 }}
                className={cn(
                  "flex items-start justify-between gap-4 p-4 rounded-lg border",
                  risk.level === "CRITICAL"
                    ? "bg-red-500/5 border-red-500/20"
                    : risk.level === "HIGH"
                      ? "bg-orange-500/5 border-orange-500/20"
                      : "bg-amber-500/5 border-amber-500/20"
                )}
              >
                <div className="flex items-start gap-3 min-w-0">
                  <span className="text-lg font-bold text-slate-500 shrink-0 mt-0.5">
                    {idx + 1}
                  </span>
                  <div className="space-y-1 min-w-0">
                    <p className="font-semibold text-slate-200 leading-snug">{risk.title}</p>
                    <p className="text-sm text-slate-400">{risk.description}</p>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  <Badge className={cn("border text-xs font-bold", riskBadgeClass(risk.level))}>
                    {risk.level}
                  </Badge>
                  <span className="text-xs text-slate-400 whitespace-nowrap">{risk.impact}</span>
                </div>
              </motion.div>
            ))}
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Wins This Quarter ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="border-emerald-500/20 bg-emerald-500/5">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
              Wins This Quarter
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {d.quarterly_wins.map((win, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3 + idx * 0.08 }}
                  className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/20 space-y-2"
                >
                  <div className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <p className="font-semibold text-slate-200 text-sm leading-snug">{win.title}</p>
                  </div>
                  <p className="text-xs text-slate-400 pl-6">{win.detail}</p>
                </motion.div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Peer Benchmarking + Trend Chart (side by side on large screens) ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {/* Peer Benchmarking */}
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ArrowUpRight className="w-5 h-5" />
              Peer Benchmarking
            </CardTitle>
            <p className="text-xs text-slate-500 mt-1">
              Your score vs industry average vs top quartile
            </p>
          </CardHeader>
          <CardContent className="space-y-5">
            {d.pillars.map((pillar) => (
              <BenchmarkBar
                key={pillar.name}
                label={pillar.name}
                yourScore={pillar.score}
                industryAvg={pillar.industryAvg}
                topQuartile={pillar.topQuartile}
              />
            ))}
          </CardContent>
        </Card>

        {/* 6-Quarter Trend */}
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Overall Score Trend (6 Quarters)
            </CardTitle>
            <p className="text-xs text-slate-500 mt-1">
              Composite security posture score per quarter
            </p>
          </CardHeader>
          <CardContent className="pt-2">
            <QuarterlyBarChart data={d.quarterly_trend} />
            <Separator className="my-3 border-slate-800" />
            <div className="flex items-center justify-between text-xs text-slate-500">
              <span>Q3 2024 baseline: {d.quarterly_trend[0]?.score}</span>
              <span className="text-emerald-400 font-semibold">
                +{(d.quarterly_trend[d.quarterly_trend.length - 1]?.score ?? 0) -
                  (d.quarterly_trend[0]?.score ?? 0)}{" "}
                pts since baseline
              </span>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── Investment Recommendations ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
      >
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DollarSign className="w-5 h-5" />
              Investment Recommendations
            </CardTitle>
            <p className="text-xs text-slate-500 mt-1">
              Initiatives with highest return on security investment
            </p>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-800 hover:bg-transparent">
                    <TableHead className="text-slate-400">Initiative</TableHead>
                    <TableHead className="text-slate-400 text-right">Est. Cost</TableHead>
                    <TableHead className="text-slate-400 text-right">Risk Reduction</TableHead>
                    <TableHead className="text-slate-400 text-right">Priority</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {d.investment_recommendations.map((rec, idx) => (
                    <TableRow key={idx} className="border-slate-800/50 hover:bg-slate-900/20">
                      <TableCell className="text-sm font-medium text-slate-300">
                        {rec.initiative}
                      </TableCell>
                      <TableCell className="text-right text-slate-300 font-semibold">
                        {rec.estimatedCost}
                      </TableCell>
                      <TableCell className="text-right text-emerald-400 font-semibold">
                        {rec.riskReduction}
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge className={cn("text-xs", priorityBadgeClass(rec.priority))}>
                          {rec.priority.charAt(0).toUpperCase() + rec.priority.slice(1)}
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

      {/* ── Footer ── */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="text-center text-xs text-slate-500 pt-2"
      >
        Report generated: {new Date(d.last_updated).toLocaleString()} · Data is for illustrative purposes pending live API integration
      </motion.div>
    </div>
  );
}
