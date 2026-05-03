/**
 * Pipeline BOM Dashboard
 *
 * Per-build Bill-of-Materials for CI/CD pipelines. Show every run, what
 * components/tools/images it used, and allow export.
 * Route: /pipeline-bom
 * API: GET /api/v1/pbom/stats; GET /api/v1/pbom/run/{id}/export
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Boxes, RefreshCw, Download, PlayCircle, Clock, GitBranch } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Stats {
  total_runs?: number;
  total_components?: number;
  signed_runs?: number;
  latest_run?: string;
  runs?: Run[];
}

interface Run {
  id?: string;
  run_id?: string;
  pipeline?: string;
  branch?: string;
  commit?: string;
  status?: string;
  components_count?: number;
  signed?: boolean;
  duration_ms?: number;
  started_at?: string;
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

function formatTs(ts?: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

function formatDuration(ms?: number) {
  if (!ms) return "—";
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
}

function statusColor(s?: string) {
  const k = (s ?? "").toLowerCase();
  if (k === "success" || k === "passed") return "border-green-500/30 text-green-300 bg-green-500/10";
  if (k === "failed"  || k === "error")  return "border-red-500/30 text-red-300 bg-red-500/10";
  if (k === "running" || k === "pending") return "border-blue-500/30 text-blue-300 bg-blue-500/10";
  return "border-muted/60 text-muted-foreground";
}

export default function PipelineBomDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const s = await apiFetch<Stats>("/api/v1/pbom/stats");
      setStats(s);
      setRuns(s.runs ?? []);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleExport = async (runId: string) => {
    setExporting(runId);
    try {
      const res = await fetch(buildApiUrl(`/api/v1/pbom/run/${runId}/export`), {
        headers: {
          "X-API-Key": getStoredAuthToken(),
          "X-Org-ID": getStoredOrgId(),
        },
      });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pbom-${runId}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) { setErr((e as Error).message); }
    finally { setExporting(null); }
  };

  const totalRuns = stats?.total_runs ?? runs.length;
  const totalComponents = stats?.total_components ?? runs.reduce((s, r) => s + (r.components_count ?? 0), 0);
  const signedRuns = stats?.signed_runs ?? runs.filter(r => r.signed).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Pipeline BOM"
        description="Bill-of-materials for every CI/CD run — components, tools, images, signatures"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Runs" value={totalRuns} icon={PlayCircle} />
        <KpiCard title="Components" value={totalComponents} icon={Boxes} />
        <KpiCard title="Signed Runs" value={signedRuns} icon={GitBranch} trend="up" />
        <KpiCard title="Latest Run" value={formatTs(stats?.latest_run ?? runs[0]?.started_at)} icon={Clock} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><Boxes className="h-4 w-4" /> Pipeline Runs</CardTitle>
          <CardDescription className="text-xs">Export any run to CycloneDX-compatible JSON for auditors</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading runs…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : runs.length === 0 ? (
            <EmptyState icon={PlayCircle} title="No pipeline runs yet" description="Runs will appear here as your CI/CD emits build events." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Pipeline</TableHead>
                    <TableHead className="text-[11px] h-8">Branch</TableHead>
                    <TableHead className="text-[11px] h-8">Commit</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Components</TableHead>
                    <TableHead className="text-[11px] h-8">Duration</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Export</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.map((r, i) => {
                    const rid = r.run_id ?? r.id ?? "";
                    return (
                      <TableRow key={rid || i} className="hover:bg-muted/30">
                        <TableCell className="py-2 text-[11px] font-mono">{r.pipeline ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{r.branch ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] font-mono">{(r.commit ?? "—").slice(0, 8)}</TableCell>
                        <TableCell className="py-2">
                          <Badge className={cn("text-[10px] border capitalize", statusColor(r.status))}>{r.status ?? "—"}</Badge>
                        </TableCell>
                        <TableCell className="py-2 text-[11px] font-mono">{r.components_count ?? 0}</TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground">{formatDuration(r.duration_ms)}</TableCell>
                        <TableCell className="py-2 text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => rid && handleExport(rid)}
                            disabled={!rid || exporting === rid}
                            className="h-7 text-[11px]"
                          >
                            <Download className={cn("h-3 w-3 mr-1", exporting === rid && "animate-bounce")} />
                            Export
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
