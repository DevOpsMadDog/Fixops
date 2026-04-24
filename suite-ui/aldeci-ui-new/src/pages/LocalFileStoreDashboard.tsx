/**
 * Local File Store Dashboard
 *
 * On-disk blob store for offline / air-gapped deployments. Show quota, inventory,
 * and configuration.
 * Route: /local-file-store
 * API: GET /api/v1/local-file-store/stats, /list, /config
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { HardDrive, RefreshCw, FileText, FolderOpen, Cog, Archive } from "lucide-react";

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
  total_files?: number;
  total_size_bytes?: number;
  used_pct?: number;
  quota_bytes?: number;
  oldest?: string;
  latest?: string;
}

interface FileEntry {
  id?: string;
  path?: string;
  name?: string;
  size_bytes?: number;
  sha256?: string;
  kind?: string;
  created_at?: string;
}

interface Config {
  root_path?: string;
  max_size_bytes?: number;
  encryption?: string;
  retention_days?: number;
  compression?: boolean;
  replicas?: number;
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
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatTs(ts?: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

function usedBar(pct?: number) {
  const v = pct ?? 0;
  if (v >= 90) return "bg-red-500";
  if (v >= 75) return "bg-orange-500";
  if (v >= 50) return "bg-yellow-500";
  return "bg-green-500";
}

export default function LocalFileStoreDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [config, setConfig] = useState<Config | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [s, l, c] = await Promise.allSettled([
        apiFetch<Stats>("/api/v1/local-file-store/stats"),
        apiFetch<FileEntry[] | { files?: FileEntry[]; items?: FileEntry[] }>("/api/v1/local-file-store/list"),
        apiFetch<Config>("/api/v1/local-file-store/config"),
      ]);
      setStats(s.status === "fulfilled" ? s.value : null);
      if (l.status === "fulfilled") {
        const v = l.value;
        setFiles(Array.isArray(v) ? v : (v.files ?? v.items ?? []));
      } else { setFiles([]); }
      setConfig(c.status === "fulfilled" ? c.value : null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const totalFiles = stats?.total_files ?? files.length;
  const totalSize = stats?.total_size_bytes ?? files.reduce((s, f) => s + (f.size_bytes ?? 0), 0);
  const usedPct = stats?.used_pct ?? (config?.max_size_bytes ? (totalSize / config.max_size_bytes) * 100 : 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Local File Store"
        description="On-disk blob store for offline / air-gapped deployments — evidence bundles, reports, attestations"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Files" value={totalFiles} icon={FileText} />
        <KpiCard title="Total Size" value={formatBytes(totalSize)} icon={HardDrive} />
        <KpiCard title="Used" value={`${Math.round(usedPct ?? 0)}%`} icon={Archive} trend={(usedPct ?? 0) >= 80 ? "down" : "flat"} />
        <KpiCard title="Latest" value={formatTs(stats?.latest)} icon={FolderOpen} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Quota bar (2 cols) */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2"><Archive className="h-4 w-4" /> Storage Utilization</CardTitle>
            <CardDescription className="text-xs">
              {formatBytes(totalSize)} of {formatBytes(config?.max_size_bytes ?? stats?.quota_bytes)} used
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="w-full bg-muted rounded-full h-3">
              <div className={cn("h-3 rounded-full transition-all", usedBar(usedPct))} style={{ width: `${Math.min(100, Math.max(0, usedPct ?? 0))}%` }} />
            </div>
            <div className="text-[11px] text-muted-foreground flex justify-between">
              <span>{formatBytes(totalSize)}</span>
              <span>{formatBytes(config?.max_size_bytes ?? stats?.quota_bytes)}</span>
            </div>
          </CardContent>
        </Card>

        {/* Config */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2"><Cog className="h-4 w-4" /> Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            {!config ? (
              <div className="text-xs text-muted-foreground">Loading…</div>
            ) : (
              <dl className="space-y-1.5 text-[11px]">
                <div className="flex justify-between"><dt className="text-muted-foreground">Root</dt><dd className="font-mono truncate max-w-[180px]">{config.root_path ?? "—"}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Quota</dt><dd className="font-mono">{formatBytes(config.max_size_bytes)}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Encryption</dt><dd className="font-mono capitalize">{config.encryption ?? "none"}</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Retention</dt><dd className="font-mono">{config.retention_days ?? "—"}d</dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Compression</dt><dd>
                  {config.compression ? (
                    <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">On</Badge>
                  ) : (
                    <Badge className="text-[10px] border border-muted/60 text-muted-foreground">Off</Badge>
                  )}
                </dd></div>
                <div className="flex justify-between"><dt className="text-muted-foreground">Replicas</dt><dd className="font-mono">{config.replicas ?? 1}</dd></div>
              </dl>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2"><FileText className="h-4 w-4" /> Stored Files</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading files…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : files.length === 0 ? (
            <EmptyState icon={FileText} title="No files" description="Stored blobs will appear here." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Path</TableHead>
                    <TableHead className="text-[11px] h-8">Kind</TableHead>
                    <TableHead className="text-[11px] h-8">Size</TableHead>
                    <TableHead className="text-[11px] h-8">SHA-256</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {files.map((f, i) => (
                    <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono truncate max-w-[280px]">{f.path ?? f.name ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{f.kind ?? "blob"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{formatBytes(f.size_bytes)}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{(f.sha256 ?? "—").slice(0, 12)}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{formatTs(f.created_at)}</TableCell>
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
