/**
 * SecurityScorecardDashboard
 *
 * Team, asset, project, and vendor security performance scoring.
 *   1. KPIs: Total Scorecards, Grade A, At Risk (C/D/F), Avg Score
 *   2. Scorecard leaderboard — 12 entities ranked by score
 *   3. Grade distribution grid — A/B/C/D/F
 *   4. Trend sparklines — 3 entities × 6-period score history
 *   5. Benchmark comparison — 8 scorecards vs industry benchmark
 *   6. Dimension breakdown — 8 dimensions for selected scorecard
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { Award, BarChart3, TrendingUp, AlertTriangle, RefreshCw, Users, Target } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ───────────────────────────────────────────────────

const SCORECARDS = [
  { rank: 1,  entity: "DevSec Team",        type: "team",    period: "Q1 2026", score: 94, grade: "A", weakDims: [] },
  { rank: 2,  entity: "Cloud Infra",         type: "asset",   period: "Q1 2026", score: 88, grade: "B", weakDims: ["patch_compliance"] },
  { rank: 3,  entity: "AppSec Team",         type: "team",    period: "Q1 2026", score: 85, grade: "B", weakDims: ["code_security"] },
  { rank: 4,  entity: "Acme Corp (Vendor)",  type: "vendor",  period: "Q1 2026", score: 82, grade: "B", weakDims: ["training", "config_hardening"] },
  { rank: 5,  entity: "Payment Service",     type: "project", period: "Q1 2026", score: 79, grade: "C", weakDims: ["vulnerability_hygiene", "patch_compliance"] },
  { rank: 6,  entity: "NetSec Team",         type: "team",    period: "Q1 2026", score: 77, grade: "C", weakDims: ["threat_awareness"] },
  { rank: 7,  entity: "Auth Microservice",   type: "project", period: "Q1 2026", score: 74, grade: "C", weakDims: ["access_control", "code_security"] },
  { rank: 8,  entity: "Legacy API Gateway",  type: "asset",   period: "Q1 2026", score: 68, grade: "D", weakDims: ["patch_compliance", "config_hardening", "vulnerability_hygiene"] },
  { rank: 9,  entity: "HR Portal",           type: "project", period: "Q1 2026", score: 65, grade: "D", weakDims: ["access_control", "training", "IR"] },
  { rank: 10, entity: "SupplyChain Vendor",  type: "vendor",  period: "Q1 2026", score: 61, grade: "D", weakDims: ["vulnerability_hygiene", "code_security", "config_hardening"] },
  { rank: 11, entity: "OT Network",          type: "asset",   period: "Q1 2026", score: 52, grade: "F", weakDims: ["patch_compliance", "threat_awareness", "config_hardening"] },
  { rank: 12, entity: "Legacy ERP",          type: "asset",   period: "Q1 2026", score: 44, grade: "F", weakDims: ["vulnerability_hygiene", "patch_compliance", "access_control"] },
];

const GRADE_DIST = [
  { grade: "A", count: 8,  color: "bg-green-500/20 border-green-500/30 text-green-400" },
  { grade: "B", count: 11, color: "bg-blue-500/20 border-blue-500/30 text-blue-400" },
  { grade: "C", count: 8,  color: "bg-yellow-500/20 border-yellow-500/30 text-yellow-400" },
  { grade: "D", count: 5,  color: "bg-amber-500/20 border-amber-500/30 text-amber-400" },
  { grade: "F", count: 2,  color: "bg-red-500/20 border-red-500/30 text-red-400" },
];

const TRENDS = [
  {
    entity: "DevSec Team",
    scores: [78, 81, 83, 87, 91, 94],
    periods: ["Nov", "Dec", "Jan", "Feb", "Mar", "Apr"],
    color: "bg-green-500",
  },
  {
    entity: "Legacy API Gateway",
    scores: [84, 80, 76, 72, 70, 68],
    periods: ["Nov", "Dec", "Jan", "Feb", "Mar", "Apr"],
    color: "bg-red-500",
  },
  {
    entity: "AppSec Team",
    scores: [75, 77, 79, 82, 83, 85],
    periods: ["Nov", "Dec", "Jan", "Feb", "Mar", "Apr"],
    color: "bg-blue-500",
  },
];

const BENCHMARKS = [
  { entity: "DevSec Team",       score: 94, benchmarkAvg: 78, vsAvg: +16, percentile: 98 },
  { entity: "Cloud Infra",        score: 88, benchmarkAvg: 82, vsAvg: +6,  percentile: 87 },
  { entity: "AppSec Team",        score: 85, benchmarkAvg: 78, vsAvg: +7,  percentile: 82 },
  { entity: "Acme Corp (Vendor)", score: 82, benchmarkAvg: 71, vsAvg: +11, percentile: 79 },
  { entity: "Payment Service",    score: 79, benchmarkAvg: 85, vsAvg: -6,  percentile: 62 },
  { entity: "Legacy API Gateway", score: 68, benchmarkAvg: 82, vsAvg: -14, percentile: 31 },
  { entity: "OT Network",         score: 52, benchmarkAvg: 69, vsAvg: -17, percentile: 18 },
  { entity: "Legacy ERP",         score: 44, benchmarkAvg: 75, vsAvg: -31, percentile: 7  },
];

const DIMENSIONS = [
  { name: "Vulnerability Hygiene",  score: 91 },
  { name: "Patch Compliance",       score: 87 },
  { name: "Security Training",      score: 95 },
  { name: "Access Control",         score: 92 },
  { name: "Incident Response",      score: 88 },
  { name: "Threat Awareness",       score: 96 },
  { name: "Code Security",          score: 89 },
  { name: "Config Hardening",       score: 94 },
];

// ── Helpers ─────────────────────────────────────────────────────

function EntityTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    team:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    asset:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    project: "border-green-500/30 text-green-400 bg-green-500/10",
    vendor:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function GradeLetter({ grade, size = "sm" }: { grade: string; size?: "sm" | "lg" }) {
  const map: Record<string, string> = {
    A: "text-green-400", B: "text-blue-400", C: "text-yellow-400", D: "text-amber-400", F: "text-red-400",
  };
  return (
    <span className={cn("font-black tabular-nums", map[grade] ?? "text-muted-foreground", size === "lg" ? "text-2xl" : "text-base")}>
      {grade}
    </span>
  );
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-6 text-right", score >= 80 ? "text-green-400" : score >= 60 ? "text-amber-400" : "text-red-400")}>
        {score}
      </span>
    </div>
  );
}

function SparklineBar({ scores, color }: { scores: number[]; color: string }) {
  const max = Math.max(...scores);
  return (
    <div className="flex items-end gap-1 h-12">
      {scores.map((s, i) => (
        <div
          key={i}
          className={cn("flex-1 rounded-t transition-all", color, i === scores.length - 1 ? "opacity-100" : "opacity-60")}
          style={{ height: `${(s / max) * 100}%` }}
          title={`${s}`}
        />
      ))}
    </div>
  );
}

// ── Component ───────────────────────────────────────────────────

export default function SecurityScorecardDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [selectedDimEntity, setSelectedDimEntity] = useState("DevSec Team");

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Security Scorecards"
        description="Team, asset, project, and vendor security performance scoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Scorecards" value={34}     icon={Award}         className="border-blue-500/20" />
        <KpiCard title="Grade A"          value={8}      icon={Target}        trend="up" className="border-green-500/20" />
        <KpiCard title="At Risk (C/D/F)"  value={5}      icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="Avg Score"        value="74.2"   icon={BarChart3}     trend="up" />
      </div>

      {/* Leaderboard */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Award className="h-4 w-4 text-amber-400" />
              Scorecard Leaderboard
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{SCORECARDS.length} entities</Badge>
          </div>
          <CardDescription className="text-xs">Ranked by overall security score — Q1 2026</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-8">#</TableHead>
                  <TableHead className="text-[11px] h-8">Entity</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Period</TableHead>
                  <TableHead className="text-[11px] h-8">Score</TableHead>
                  <TableHead className="text-[11px] h-8 w-10">Grade</TableHead>
                  <TableHead className="text-[11px] h-8">Weak Dimensions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SCORECARDS.map((row) => (
                  <TableRow key={row.rank} className="hover:bg-muted/30">
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{row.rank}</TableCell>
                    <TableCell className="text-xs font-medium py-2.5">{row.entity}</TableCell>
                    <TableCell className="py-2.5"><EntityTypeBadge type={row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.period}</TableCell>
                    <TableCell className="py-2.5 w-36"><ScoreBar score={row.score} /></TableCell>
                    <TableCell className="py-2.5"><GradeLetter grade={row.grade} size="lg" /></TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {row.weakDims.map((d) => (
                          <span key={d} className="text-[10px] rounded bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 text-red-400">
                            {d.replace(/_/g, " ")}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Grade distribution + Trend sparklines */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Grade distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Award className="h-4 w-4 text-purple-400" />
              Grade Distribution
            </CardTitle>
            <CardDescription className="text-xs">All 34 scorecards by letter grade</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-5 gap-2">
              {GRADE_DIST.map((g) => (
                <div key={g.grade} className={cn("rounded-lg border p-3 text-center", g.color)}>
                  <div className="text-2xl font-black">{g.grade}</div>
                  <div className="text-lg font-bold">{g.count}</div>
                  <div className="text-[10px] opacity-70">scorecards</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Trend sparklines */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-blue-400" />
              Score Trends (6 Periods)
            </CardTitle>
            <CardDescription className="text-xs">Nov 2025 — Apr 2026</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {TRENDS.map((t) => (
              <div key={t.entity} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{t.entity}</span>
                  <span className={cn("font-bold tabular-nums",
                    t.scores[t.scores.length - 1] >= 80 ? "text-green-400" : t.scores[t.scores.length - 1] >= 60 ? "text-amber-400" : "text-red-400"
                  )}>{t.scores[t.scores.length - 1]}</span>
                </div>
                <SparklineBar scores={t.scores} color={t.color} />
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  {t.periods.map((p) => <span key={p}>{p}</span>)}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Benchmark comparison + Dimension breakdown */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Benchmark comparison */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-indigo-400" />
              Industry Benchmark Comparison
            </CardTitle>
            <CardDescription className="text-xs">Score vs industry peer average for your sector</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Entity</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Benchmark</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">vs Avg</TableHead>
                  <TableHead className="text-[11px] h-8">Percentile</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {BENCHMARKS.map((row, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs py-2.5 font-medium max-w-[120px] truncate">{row.entity}</TableCell>
                    <TableCell className="text-xs py-2.5 text-right tabular-nums font-bold">{row.score}</TableCell>
                    <TableCell className="text-xs py-2.5 text-right tabular-nums text-muted-foreground">{row.benchmarkAvg}</TableCell>
                    <TableCell className={cn("text-xs py-2.5 text-right tabular-nums font-bold", row.vsAvg >= 0 ? "text-green-400" : "text-red-400")}>
                      {row.vsAvg >= 0 ? "+" : ""}{row.vsAvg}
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border",
                        row.percentile >= 75 ? "border-green-500/30 text-green-400 bg-green-500/10" :
                        row.percentile >= 50 ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                                              "border-red-500/30 text-red-400 bg-red-500/10"
                      )}>{row.percentile}th</Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Dimension breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Users className="h-4 w-4 text-green-400" />
                  Dimension Breakdown
                </CardTitle>
                <CardDescription className="text-xs">Security dimensions for: {selectedDimEntity}</CardDescription>
              </div>
              <select
                className="text-xs rounded-md border border-border bg-background px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                value={selectedDimEntity}
                onChange={(e) => setSelectedDimEntity(e.target.value)}
              >
                {SCORECARDS.map((s) => <option key={s.entity} value={s.entity}>{s.entity}</option>)}
              </select>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {DIMENSIONS.map((d) => (
              <div key={d.name} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{d.name}</span>
                  <span className={cn("font-bold tabular-nums", d.score >= 90 ? "text-green-400" : d.score >= 75 ? "text-amber-400" : "text-red-400")}>{d.score}</span>
                </div>
                <div className="h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${d.score}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", d.score >= 90 ? "bg-green-500" : d.score >= 75 ? "bg-amber-500" : "bg-red-500")}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
