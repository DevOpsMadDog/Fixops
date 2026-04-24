/**
 * IDE Backend Dashboard
 *
 * File tree snapshots for IDE-backed code analysis + diff comparisons.
 * Route: /ide-backend
 * API: GET /api/v1/ide/tree, /snapshots; POST /api/v1/ide/snapshots/diff
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FolderTree, RefreshCw, GitCompare, File, Folder, Clock } from "lucide-react";

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

interface TreeNode {
  path?: string;
  type?: "file" | "dir";
  size?: number;
  sha?: string;
}

interface Snapshot {
  id?: string;
  snapshot_id?: string;
  label?: string;
  repo?: string;
  created_at?: string;
  file_count?: number;
}

interface DiffFile {
  path?: string;
  change?: "added" | "removed" | "modified";
  additions?: number;
  deletions?: number;
}

interface DiffResult {
  from?: string;
  to?: string;
  files_changed?: number;
  files?: DiffFile[];
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

function formatBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function formatTs(ts?: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

function changeBadge(c?: string) {
  if (c === "added")    return "border-green-500/30 text-green-400 bg-green-500/10";
  if (c === "removed")  return "border-red-500/30 text-red-400 bg-red-500/10";
  return "border-blue-500/30 text-blue-400 bg-blue-500/10";
}

export default function IDEBackendDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [diffing, setDiffing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [tree, setTree] = useState<TreeNode[]>([]);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [from, setFrom] = useState<string>("");
  const [to, setTo] = useState<string>("");
  const [diff, setDiff] = useState<DiffResult | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [t, s] = await Promise.allSettled([
        apiFetch<TreeNode[] | { tree?: TreeNode[]; files?: TreeNode[] }>("/api/v1/ide/tree"),
        apiFetch<Snapshot[] | { snapshots?: Snapshot[] }>("/api/v1/ide/snapshots"),
      ]);
      setTree(t.status === "fulfilled" ? (Array.isArray(t.value) ? t.value : t.value.tree ?? t.value.files ?? []) : []);
      const snaps = s.status === "fulfilled" ? (Array.isArray(s.value) ? s.value : s.value.snapshots ?? []) : [];
      setSnapshots(snaps);
      if (!from && snaps[1]?.snapshot_id) setFrom(snaps[1].snapshot_id ?? snaps[1].id ?? "");
      if (!to && snaps[0]?.snapshot_id) setTo(snaps[0].snapshot_id ?? snaps[0].id ?? "");
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleDiff = async () => {
    if (!from || !to) return;
    setDiffing(true);
    setDiff(null);
    try {
      const r = await apiFetch<DiffResult>("/api/v1/ide/snapshots/diff", {
        method: "POST",
        body: JSON.stringify({ from, to }),
      });
      setDiff(r);
    } catch (e) { setErr((e as Error).message); }
    finally { setDiffing(false); }
  };

  const fileCount = tree.filter(n => n.type !== "dir").length;
  const dirCount = tree.filter(n => n.type === "dir").length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="IDE Backend"
        description="File-tree snapshots powering IDE-side code analysis and cross-snapshot diffs"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Files" value={fileCount} icon={File} />
        <KpiCard title="Directories" value={dirCount} icon={Folder} />
        <KpiCard title="Snapshots" value={snapshots.length} icon={Clock} />
        <KpiCard title="Latest" value={formatTs(snapshots[0]?.created_at)} icon={FolderTree} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><GitCompare className="h-4 w-4" /> Snapshot Diff</CardTitle>
          <CardDescription className="text-xs">Compare two snapshots to see file-level changes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <select value={from} onChange={e => setFrom(e.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-xs">
              <option value="">From snapshot…</option>
              {snapshots.map((s, i) => <option key={i} value={s.snapshot_id ?? s.id ?? ""}>{s.label ?? s.snapshot_id ?? s.id}</option>)}
            </select>
            <GitCompare className="h-4 w-4 text-muted-foreground hidden sm:block" />
            <select value={to} onChange={e => setTo(e.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-xs">
              <option value="">To snapshot…</option>
              {snapshots.map((s, i) => <option key={i} value={s.snapshot_id ?? s.id ?? ""}>{s.label ?? s.snapshot_id ?? s.id}</option>)}
            </select>
            <Button size="sm" onClick={handleDiff} disabled={diffing || !from || !to}>
              <GitCompare className={cn("h-4 w-4 mr-2", diffing && "animate-pulse")} />
              Diff
            </Button>
          </div>

          {diff && (diff.files ?? []).length > 0 && (
            <div className="rounded border border-border/50 bg-muted/20 p-3">
              <div className="flex items-center justify-between text-xs mb-2">
                <span className="font-mono text-muted-foreground">{diff.from?.slice(0, 10)} → {diff.to?.slice(0, 10)}</span>
                <Badge className="text-[10px] border border-border">{diff.files_changed ?? diff.files?.length ?? 0} files changed</Badge>
              </div>
              <div className="max-h-64 overflow-y-auto space-y-1 text-[11px]">
                {(diff.files ?? []).map((f, i) => (
                  <div key={i} className="flex items-center justify-between rounded bg-muted/30 px-2 py-1">
                    <span className="font-mono truncate">{f.path}</span>
                    <div className="flex items-center gap-2">
                      <Badge className={cn("text-[10px] border capitalize", changeBadge(f.change))}>{f.change ?? "modified"}</Badge>
                      <span className="text-green-400 font-mono">+{f.additions ?? 0}</span>
                      <span className="text-red-400 font-mono">-{f.deletions ?? 0}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {diff && (diff.files ?? []).length === 0 && (
            <div className="p-3 text-xs text-muted-foreground">No differences between snapshots.</div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><FolderTree className="h-4 w-4" /> File Tree</CardTitle>
          <CardDescription className="text-xs">Current file inventory indexed by the IDE backend</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading tree…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : tree.length === 0 ? (
            <EmptyState icon={FolderTree} title="No indexed files" description="Connect the IDE backend to start indexing project files." />
          ) : (
            <div className="overflow-x-auto max-h-[480px]">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Path</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Size</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">SHA</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tree.slice(0, 500).map((n, i) => (
                    <TableRow key={n.path ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">
                        {n.type === "dir" ? <Folder className="inline h-3 w-3 mr-1" /> : <File className="inline h-3 w-3 mr-1" />}
                        {n.path ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{n.type ?? "file"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{formatBytes(n.size)}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground text-right">{(n.sha ?? "").slice(0, 10) || "—"}</TableCell>
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
