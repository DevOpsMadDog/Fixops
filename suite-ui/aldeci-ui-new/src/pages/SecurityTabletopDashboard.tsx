/**
 * Security Tabletop Dashboard
 *
 * Manages tabletop exercises, findings, and scoring.
 *   1. KPI cards: Total Exercises, Completed, Total Findings, Open Findings
 *   2. Exercises table
 *   3. Findings table
 *
 * API: GET /api/v1/tabletop/{stats,exercises,findings}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Users, RefreshCw, CheckCircle, AlertTriangle, ClipboardList, FileWarning,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
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

// ── Badge helpers ──────────────────────────────────────────────

function ExerciseStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed:   "border-green-500/30 text-green-400 bg-green-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    scheduled:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    cancelled:   "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function ScenarioTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    ransomware:     "border-red-500/30 text-red-400 bg-red-500/10",
    insider_threat: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    supply_chain:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    ddos:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    data_breach:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    cloud_attack:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function FindingStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:       "border-red-500/30 text-red-400 bg-red-500/10",
    resolved:   "border-green-500/30 text-green-400 bg-green-500/10",
    in_review:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function scoreColor(score: number): string {
  if (score === 0) return "text-muted-foreground";
  if (score >= 85) return "text-green-400";
  if (score >= 70) return "text-amber-400";
  return "text-red-400";
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityTabletopDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    exercises: any[] | null;
    findings: any[] | null;
  }>({ stats: null, exercises: null, findings: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/tabletop/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/tabletop/exercises?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/tabletop/findings?org_id=${ORG_ID}`),
    ]).then(([statsRes, exRes, findRes]) => {
      setLiveData({
        stats:     statsRes.status === "fulfilled" ? statsRes.value : null,
        exercises: exRes.status    === "fulfilled" ? exRes.value    : null,
        findings:  findRes.status  === "fulfilled" ? findRes.value  : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? { total_exercises: 0, completed_exercises: 0, total_findings: 0, open_findings: 0 };
  const exercises = liveData.exercises ?? [];
  const findings  = liveData.findings  ?? [];

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
        title="Security Tabletop"
        description="Tabletop exercise management, scenario scoring, and findings tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Exercises"    value={stats.total_exercises}         icon={Users}          trend="up"   />
        <KpiCard title="Completed"          value={stats.completed_exercises} icon={CheckCircle}    trend="up"   className="border-green-500/20" />
        <KpiCard title="Total Findings"     value={stats.total_findings}     icon={ClipboardList}  trend="flat" />
        <KpiCard title="Open Findings"      value={stats.open_findings}      icon={FileWarning}    trend="down" className="border-red-500/20" />
      </div>

      {/* Exercises Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-blue-400" />
              Exercises
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {exercises.length} exercises
            </Badge>
          </div>
          <CardDescription className="text-xs">Tabletop exercise schedule, scenario types, and overall scores</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Scenario</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Scheduled</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exercises.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  exercises.map((ex: any, i: number) => (
                  <TableRow key={ex.title ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px]">{ex.title}</TableCell>
                    <TableCell className="py-2"><ScenarioTypeBadge type={ex.scenario_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2"><ExerciseStatusBadge status={ex.status ?? "scheduled"} /></TableCell>
                    <TableCell className={cn("py-2 text-right font-mono text-[11px] font-semibold", scoreColor(ex.overall_score ?? 0))}>
                      {ex.overall_score > 0 ? `${ex.overall_score}%` : "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{ex.scheduled_at}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Findings Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
              Findings
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {findings.filter((f: any) => f.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Findings and gaps identified during tabletop exercises</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Exercise</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  findings.map((f: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px]">{f.title}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{(f.finding_type ?? "gap").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={f.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2"><FindingStatusBadge status={f.status ?? "open"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{f.exercise_id}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
