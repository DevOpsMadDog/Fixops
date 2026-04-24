/**
 * Deep Code Analysis Dashboard
 *
 * DCA engine — deep semantic analysis over repositories.
 * Route: /deep-code-analysis
 * API: GET /api/v1/dca/analyses, /stats; POST /api/v1/dca/analyze
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Code2, RefreshCw, Play, GitBranch, AlertCircle, CheckCircle2, Bug } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Analysis {
  id?: string;
  analysis_id?: string;
  repo?: string;
  branch?: string;
  status?: string;
  findings_count?: number;
  critical_count?: number;
  duration_secs?: number;
  created_at?: string;
}

interface DCAStats {
  total_analyses?: number;
  findings_total?: number;
  critical_findings?: number;
  avg_duration_secs?: number;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function statusBadge(s?: string) {
  const key = (s ?? "").toLowerCase();
  const map: Record<string, string> = {
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    running:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    queued:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return map[key] ?? "border-border";
}

export default function DeepCodeAnalysisDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [repo, setRepo] = useState("");
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [stats, setStats] = useState<DCAStats | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [a, s] = await Promise.allSettled([
        apiFetch<Analysis[] | { analyses?: Analysis[]; items?: Analysis[] }>("/api/v1/dca/analyses"),
        apiFetch<DCAStats>("/api/v1/dca/stats"),
      ]);
      if (a.status === "fulfilled") {
        const v = a.value;
        setAnalyses(Array.isArray(v) ? v : (v.analyses ?? v.items ?? []));
      } else { setAnalyses([]); }
      setStats(s.status === "fulfilled" ? s.value : null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleAnalyze = async () => {
    if (!repo.trim()) return;
    setAnalyzing(true);
    try {
      await apiFetch("/api/v1/dca/analyze", { method: "POST", body: JSON.stringify({ repo: repo.trim() }) });
      setRepo("");
      await load();
    } catch (e) { setErr((e as Error).message); }
    finally { setAnalyzing(false); }
  };

  const totalAnalyses = stats?.total_analyses ?? analyses.length;
  const findingsTotal = stats?.findings_total ?? analyses.reduce((s, a) => s + (a.findings_count ?? 0), 0);
  const criticalFindings = stats?.critical_findings ?? analyses.reduce((s, a) => s + (a.critical_count ?? 0), 0);
  const avgDuration = stats?.avg_duration_secs ?? (analyses.length
    ? Math.round(analyses.reduce((s, a) => s + (a.duration_secs ?? 0), 0) / analyses.length) : 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Deep Code Analysis"
        description="Semantic code analysis — control flow, taint tracking, contextual vulnerability detection"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Analyses" value={totalAnalyses} icon={Code2} />
        <KpiCard title="Findings" value={findingsTotal} icon={Bug} />
        <KpiCard title="Critical" value={criticalFindings} icon={AlertCircle} trend="down" />
        <KpiCard title="Avg Duration (s)" value={avgDuration} icon={CheckCircle2} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Play className="h-4 w-4" /> Analyze Repository</CardTitle>
          <CardDescription className="text-xs">Kick off a deep semantic analysis for a repo (org/name or URL)</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-2">
          <Input value={repo} onChange={e => setRepo(e.target.value)} placeholder="org/repo-name" className="h-9 text-xs" />
          <Button size="sm" onClick={handleAnalyze} disabled={analyzing || !repo.trim()}>
            <Play className={cn("h-4 w-4 mr-2", analyzing && "animate-pulse")} />
            Run Analysis
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitBranch className="h-4 w-4" /> Recent Analyses</CardTitle>
          <CardDescription className="text-xs">History of DCA runs with findings and duration</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading analyses…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : analyses.length === 0 ? (
            <EmptyState icon={Code2} title="No analyses yet" description="Run an analysis on any repository to see results here." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Repo</TableHead>
                    <TableHead className="text-[11px] h-8">Branch</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Findings</TableHead>
                    <TableHead className="text-[11px] h-8">Critical</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Duration</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {analyses.map((a, i) => (
                    <TableRow key={a.id ?? a.analysis_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{a.repo ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{a.branch ?? "main"}</TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", statusBadge(a.status))}>{a.status ?? "pending"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{a.findings_count ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-red-400">{a.critical_count ?? 0}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground text-right">{a.duration_secs ?? 0}s</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
