/**
 * Air-Gap Bundle Dashboard
 *
 * Offline evidence/update bundle export for air-gapped deployments.
 * Route: /air-gap-bundle
 * API: GET /api/v1/air-gap/bundle/list, /stats; POST /api/v1/air-gap/bundle/export
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Package, RefreshCw, Download, Lock, HardDrive, ShieldCheck } from "lucide-react";

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

interface Bundle {
  id?: string;
  bundle_id?: string;
  name?: string;
  kind?: string;
  created_at?: string;
  size_bytes?: number;
  sha256?: string;
  signature?: string;
  status?: string;
}

interface Stats {
  total_bundles?: number;
  total_size_bytes?: number;
  signed_bundles?: number;
  latest_bundle?: string;
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
  try {
    return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch { return ts; }
}

export default function AirGapBundleDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [b, s] = await Promise.allSettled([
        apiFetch<{ bundles?: Bundle[]; items?: Bundle[] } | Bundle[]>("/api/v1/air-gap/bundle/list"),
        apiFetch<Stats>("/api/v1/air-gap/bundle/stats"),
      ]);
      if (b.status === "fulfilled") {
        const v = b.value as { bundles?: Bundle[]; items?: Bundle[] } | Bundle[];
        const arr = Array.isArray(v) ? v : (v.bundles ?? v.items ?? []);
        setBundles(arr);
      } else {
        setBundles([]);
      }
      if (s.status === "fulfilled") setStats(s.value); else setStats(null);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleExport = async () => {
    setExporting(true);
    try {
      await apiFetch("/api/v1/air-gap/bundle/export", { method: "POST", body: JSON.stringify({ include_signatures: true }) });
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

  const totalBundles = stats?.total_bundles ?? bundles.length;
  const totalSize = stats?.total_size_bytes ?? bundles.reduce((s, b) => s + (b.size_bytes ?? 0), 0);
  const signedCount = stats?.signed_bundles ?? bundles.filter(b => !!b.signature).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Air-Gap Bundle"
        description="Offline evidence and update bundles for air-gapped deployments — sealed, signed, reproducible"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" onClick={handleExport} disabled={exporting}>
              <Download className={cn("h-4 w-4 mr-2", exporting && "animate-bounce")} />
              Export New Bundle
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Bundles" value={totalBundles} icon={Package} />
        <KpiCard title="Total Size" value={formatBytes(totalSize)} icon={HardDrive} />
        <KpiCard title="Signed" value={signedCount} icon={ShieldCheck} trend="up" />
        <KpiCard title="Latest" value={formatTs(stats?.latest_bundle ?? bundles[0]?.created_at)} icon={Lock} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Package className="h-4 w-4" />
            Exported Bundles
          </CardTitle>
          <CardDescription className="text-xs">Offline-ready bundles for air-gap transport; each includes SHA-256 + signature</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading bundles…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : bundles.length === 0 ? (
            <EmptyState icon={Package} title="No bundles yet" description="Export your first bundle to distribute to air-gapped environments." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Kind</TableHead>
                    <TableHead className="text-[11px] h-8">Size</TableHead>
                    <TableHead className="text-[11px] h-8">SHA-256</TableHead>
                    <TableHead className="text-[11px] h-8">Signed</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {bundles.map((b, i) => (
                    <TableRow key={b.id ?? b.bundle_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{b.name ?? b.bundle_id ?? b.id ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] capitalize text-muted-foreground">{b.kind ?? "evidence"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{formatBytes(b.size_bytes)}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{(b.sha256 ?? "").slice(0, 12) || "—"}</TableCell>
                      <TableCell className="py-2">
                        {b.signature ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Signed</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Unsigned</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{formatTs(b.created_at)}</TableCell>
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
