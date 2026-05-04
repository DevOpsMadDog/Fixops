// FOLDED into Brain hero 2026-04-27 — preserve for git history
// Tab path: /brain?tab=chaos
/**
 * Security Chaos Dashboard
 *
 * Chaos engineering experiments for security resilience testing.
 *   1. KPI cards: Total Experiments, Active Experiments, Avg Resilience Score, Open Findings
 *   2. Chaos experiments table
 *   3. Observations table
 *
 * API: GET /api/v1/security-chaos/{stats,experiments,observations}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Zap, RefreshCw, FlaskConical, AlertTriangle, Activity, Eye,
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

function ExperimentStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-green-500/30 text-green-400 bg-green-500/10",
    completed: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    planned:   "border-gray-500/30 text-gray-400 bg-gray-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function ResilienceScoreBadge({ score }: { score: number }) {
  if (score === 0) return <span className="text-[11px] text-muted-foreground">—</span>;
  const cls =
    score >= 80 ? "border-green-500/30 text-green-400 bg-green-500/10" :
    score >= 60 ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                  "border-red-500/30 text-red-400 bg-red-500/10";
  return (
    <Badge className={cn("text-[10px] border font-mono", cls)}>{score}</Badge>
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

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityChaosDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    experiments: any[] | null;
    observations: any[] | null;
  }>({ stats: null, experiments: null, observations: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-chaos/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-chaos/experiments?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-chaos/observations?org_id=${ORG_ID}`),
    ]).then(([statsRes, experimentsRes, observationsRes]) => {
      setLiveData({
        stats:        statsRes.status        === "fulfilled" ? statsRes.value        : null,
        experiments:  experimentsRes.status  === "fulfilled" ? experimentsRes.value  : null,
        observations: observationsRes.status === "fulfilled" ? observationsRes.value : null,
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

  const stats        = liveData.stats        ?? { total_experiments: 0, active_experiments: 0, avg_resilience_score: 0, open_findings: 0 };
  const experiments  = liveData.experiments  ?? [];
  const observations = liveData.observations ?? [];

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
        title="Security Chaos Engineering"
        description="Proactive resilience testing through controlled chaos experiments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Experiments"    value={stats.total_experiments}    icon={FlaskConical}         trend="up"   />
        <KpiCard title="Active Experiments"   value={stats.active_experiments}   icon={Activity}      trend="flat" className="border-green-500/20" />
        <KpiCard title="Avg Resilience Score" value={`${stats.avg_resilience_score}`} icon={Zap}      trend="up"   className="border-blue-500/20" />
        <KpiCard title="Open Findings"        value={stats.open_findings}        icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
      </div>

      {/* Experiments Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FlaskConical className="h-4 w-4 text-violet-400" />
              Chaos Experiments
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {experiments.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">Security resilience experiments across target systems</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Experiment Type</TableHead>
                  <TableHead className="text-[11px] h-8">Target System</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Resilience Score</TableHead>
                  <TableHead className="text-[11px] h-8">Started</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {experiments.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  experiments.map((ex: any, i: number) => (
                  <TableRow key={ex.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ex.id}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(ex.experiment_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-[11px] font-mono">{ex.target_system}</TableCell>
                    <TableCell className="py-2"><ExperimentStatusBadge status={ex.status ?? "planned"} /></TableCell>
                    <TableCell className="py-2"><ResilienceScoreBadge score={ex.resilience_score ?? 0} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(ex.started_at)}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Observations Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <Eye className="h-4 w-4" />
              Experiment Observations
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {observations.filter((o: any) => o.severity === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">Security gaps and findings discovered during chaos experiments</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Observation Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Experiment</TableHead>
                  <TableHead className="text-[11px] h-8">Detail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {observations.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  observations.map((ob: any, i: number) => (
                  <TableRow key={ob.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ob.id}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(ob.observation_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={ob.severity ?? "low"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ob.experiment_id}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-xs truncate">{ob.detail}</TableCell>
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
