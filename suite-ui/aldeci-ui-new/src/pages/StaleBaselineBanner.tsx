// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Stale Baseline Banner — show when findings drift from baseline
 * Route: /findings/drift
 * API: GET /api/v1/findings/drift
 * Multica id: 052597b6
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, RefreshCw, History } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface DriftItem {
  finding_id?: string;
  rule?: string;
  baseline_severity?: string;
  current_severity?: string;
  delta_days?: number;
  status?: string;
}

interface Resp {
  baseline_id?: string;
  baseline_age_days?: number;
  drift?: DriftItem[];
  drift_count?: number;
  is_stale?: boolean;
  detail?: string;
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 501) return { detail: "Coming soon", drift: [] } as unknown as T;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function StaleBaselineBanner() {
  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const r = await apiFetch<Resp>("/api/v1/findings/drift");
      setData(r);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const items = data?.drift ?? [];
  const isComingSoon = !!data?.detail;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Findings Baseline Drift"
        description="See findings that have drifted from the recorded baseline — and whether the baseline is stale"
        badge={isComingSoon ? "Coming Soon" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {data?.is_stale && (
        <Alert className="border-amber-500/30 bg-amber-500/10">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <span className="ml-2 text-xs">
            Baseline <span className="font-mono">{data.baseline_id}</span> is <strong>stale</strong> — {data.baseline_age_days} days old. Drift = <strong>{data.drift_count ?? items.length}</strong> findings.
          </span>
        </Alert>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
        <KpiCard title="Baseline Age" value={`${data?.baseline_age_days ?? 0}d`} icon={History} trend={(data?.baseline_age_days ?? 0) > 30 ? "down" : "up"} />
        <KpiCard title="Drift Findings" value={data?.drift_count ?? items.length} icon={AlertTriangle} trend={items.length > 0 ? "down" : "up"} />
        <KpiCard title="Status" value={data?.is_stale ? "Stale" : "Fresh"} icon={History} trend={data?.is_stale ? "down" : "up"} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">Drift Detail</CardTitle>
          <CardDescription className="text-xs">Endpoint: <code className="text-[10px]">GET /api/v1/findings/drift</code></CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          : err ? <ErrorState message={err} onRetry={load} />
          : isComingSoon ? <EmptyState icon={History} title="Coming soon" description="Endpoint returns 501." />
          : items.length === 0 ? <EmptyState icon={History} title="No drift detected" description="Findings match the recorded baseline." />
          : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Finding</TableHead>
                    <TableHead className="text-[11px] h-8">Rule</TableHead>
                    <TableHead className="text-[11px] h-8">Baseline</TableHead>
                    <TableHead className="text-[11px] h-8">Current</TableHead>
                    <TableHead className="text-[11px] h-8">Δ Days</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((d, i) => (
                    <TableRow key={d.finding_id ?? i}>
                      <TableCell className="py-2 text-[11px] font-mono">{(d.finding_id ?? "").slice(0, 14) || "—"}</TableCell>
                      <TableCell className="py-2 text-[11px]">{d.rule ?? "—"}</TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px]">{d.baseline_severity ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2"><Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{d.current_severity ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] tabular-nums">{d.delta_days ?? 0}</TableCell>
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
