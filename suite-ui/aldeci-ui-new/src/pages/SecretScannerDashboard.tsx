// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
// FOLDED into SecretsHub hero (scanner tab) 2026-05-02 — preserve for git history (was orphan-imported)
/**
 * Secret Scanner Dashboard - Live API
 * Route: /secret-scanner
 * API: GET /api/v1/secret-scanner/{scan-jobs,findings,stats}
 *      POST /api/v1/secret-scanner/scan
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search, AlertTriangle, RefreshCw, Play, Key } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...init, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const sevColor: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-500 text-black",
  low: "bg-emerald-500 text-white",
};

export default function SecretScannerDashboard() {
  const [jobs, setJobs] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [targetType, setTargetType] = useState("git_repo");
  const [targetPath, setTargetPath] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [j, f, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/secret-scanner/scan-jobs"),
        apiFetch<any>("/api/v1/secret-scanner/findings"),
        apiFetch<any>("/api/v1/secret-scanner/stats"),
      ]);
      if (j.status === "fulfilled") { const v = j.value as any; setJobs(Array.isArray(v) ? v : (v.jobs ?? v.scan_jobs ?? v.items ?? [])); }
      if (f.status === "fulfilled") { const v = f.value as any; setFindings(Array.isArray(v) ? v : (v.findings ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const triggerScan = async () => {
    if (!targetPath.trim()) return;
    setSubmitting(true);
    try {
      await apiFetch<any>("/api/v1/secret-scanner/scan", { method: "POST", body: JSON.stringify({ target_type: targetType, target_path: targetPath }) });
      setTargetPath("");
      load();
    } catch (e) { setError((e as Error).message); }
    finally { setSubmitting(false); }
  };

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Secret Scanner"
        description="Scan jobs, secret findings, type distribution"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : jobs.length === 0 && findings.length === 0 ? <EmptyState icon={Key} title="No scans yet" description="Trigger your first secret scan below." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Scans" value={stats?.total_scans ?? jobs.length} icon={Search} />
            <KpiCard title="Findings" value={stats?.total_findings ?? findings.length} icon={AlertTriangle} />
            <KpiCard title="Critical" value={stats?.critical ?? findings.filter(f => f.severity === "critical").length} icon={AlertTriangle} />
            <KpiCard title="Remediated" value={stats?.remediated ?? findings.filter(f => f.status === "remediated" || f.status === "fixed").length} icon={Search} />
          </motion.div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold flex items-center gap-2"><Play className="w-4 h-4" /> Trigger Scan</CardTitle></CardHeader>
            <CardContent className="flex gap-2 flex-wrap">
              <select value={targetType} onChange={e => setTargetType(e.target.value)} className="rounded-md border border-border bg-background px-3 py-2 text-sm">
                <option value="git_repo">Git Repo</option>
                <option value="directory">Directory</option>
                <option value="git_diff">Git Diff</option>
                <option value="file">File</option>
              </select>
              <Input value={targetPath} onChange={e => setTargetPath(e.target.value)} placeholder="github.com/org/repo or /path" className="flex-1 min-w-[280px]" />
              <Button onClick={triggerScan} disabled={!targetPath.trim() || submitting} className="gap-2"><Play className="w-4 h-4" /> {submitting ? "Starting..." : "Start Scan"}</Button>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Scan Jobs</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Target</TableHead><TableHead>Type</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Secrets Found</TableHead><TableHead>Duration</TableHead></TableRow></TableHeader>
                <TableBody>{jobs.map(j => (
                  <TableRow key={j.id} className="border-b border-gray-700/50">
                    <TableCell className="text-sm font-mono text-gray-200 max-w-xs truncate">{j.target_path}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{j.target_type}</Badge></TableCell>
                    <TableCell className="text-xs text-gray-400">{j.status}</TableCell>
                    <TableCell className={cn("text-right font-bold", (j.secrets_found ?? 0) > 0 ? "text-red-400" : "text-emerald-400")}>{j.secrets_found ?? 0}</TableCell>
                    <TableCell className="text-xs text-gray-400">{j.duration ?? "—"}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>
          {findings.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Findings</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Type</TableHead><TableHead>File</TableHead><TableHead>Line</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
                <TableBody>{findings.slice(0, 100).map(f => (
                  <TableRow key={f.id} className="border-b border-gray-700/50">
                    <TableCell className="text-xs"><Badge variant="outline">{f.secret_type ?? f.type}</Badge></TableCell>
                    <TableCell className="text-xs font-mono text-gray-300 max-w-xs truncate">{f.file_path ?? f.file}</TableCell>
                    <TableCell className="text-xs text-gray-400">{f.line_number ?? "—"}</TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs font-bold capitalize", sevColor[f.severity] ?? "bg-gray-700 text-white")}>{f.severity}</span></TableCell>
                    <TableCell className="text-xs text-gray-400 capitalize">{f.status}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
