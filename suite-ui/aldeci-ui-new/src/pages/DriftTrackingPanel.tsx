// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Drift Tracking Panel — finding-state drift over time (Wave 3)
 * Route: /drift-tracking
 * API:   GET /api/v1/findings/drift
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, ArrowUpRight, ArrowDownRight } from "lucide-react";

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

interface DriftItem {
  finding_id?: string;
  title?: string;
  prev_severity?: string;
  curr_severity?: string;
  prev_score?: number;
  curr_score?: number;
  delta?: number;
  reason?: string;
  observed_at?: string;
}
interface DriftResponse {
  drifts?: DriftItem[];
  items?: DriftItem[];
  upgraded?: number;
  downgraded?: number;
  total?: number;
}

async function apiFetch<T>(path: string): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function sevColor(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "border-red-500/30 text-red-400 bg-red-500/10";
    case "high": return "border-orange-500/30 text-orange-400 bg-orange-500/10";
    case "medium": return "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
    case "low": return "border-green-500/30 text-green-400 bg-green-500/10";
    default: return "border-border";
  }
}

export default function DriftTrackingPanel() {
  const [data, setData] = useState<DriftResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setComingSoon(false);
    try {
      const r = await apiFetch<DriftResponse>("/api/v1/findings/drift");
      if (!r) {
        setComingSoon(true);
        setData(null);
      } else {
        setData(r);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const items = data?.drifts ?? data?.items ?? [];
  const upgraded = data?.upgraded ?? items.filter((d) => (d.delta ?? 0) > 0).length;
  const downgraded = data?.downgraded ?? items.filter((d) => (d.delta ?? 0) < 0).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Drift Tracking"
        description="Findings whose severity or score has shifted between re-scans"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Drift Events" value={items.length} icon={Activity} />
        <KpiCard title="Upgraded" value={upgraded} icon={ArrowUpRight} trend="down" />
        <KpiCard title="Downgraded" value={downgraded} icon={ArrowDownRight} trend="up" />
        <KpiCard title="Net Δ" value={(upgraded - downgraded).toString()} icon={Activity} />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4" /> Drift Events
          </CardTitle>
          <CardDescription className="text-xs">Most recent first</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : comingSoon ? (
            <EmptyState icon={Activity} title="Coming soon" description="The findings-drift endpoint is not yet enabled in this build." />
          ) : items.length === 0 ? (
            <EmptyState icon={Activity} title="No drift recorded" description="When findings change severity between scans, they'll show up here." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Finding</TableHead>
                    <TableHead className="text-[11px] h-8">Was</TableHead>
                    <TableHead className="text-[11px] h-8">Now</TableHead>
                    <TableHead className="text-[11px] h-8">Δ Score</TableHead>
                    <TableHead className="text-[11px] h-8">Reason</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Observed</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((d, i) => (
                    <TableRow key={(d.finding_id ?? "d") + i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] max-w-[260px] truncate">
                        {d.title ?? <span className="font-mono text-muted-foreground">{d.finding_id}</span>}
                      </TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", sevColor(d.prev_severity))}>{d.prev_severity ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2"><Badge className={cn("text-[10px] border capitalize", sevColor(d.curr_severity))}>{d.curr_severity ?? "—"}</Badge></TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">
                        <span className={cn(
                          (d.delta ?? 0) > 0 ? "text-red-400" : (d.delta ?? 0) < 0 ? "text-green-400" : "text-muted-foreground"
                        )}>
                          {(d.delta ?? 0) > 0 ? "+" : ""}{d.delta?.toFixed(2) ?? "—"}
                        </span>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[280px] truncate">{d.reason ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{d.observed_at?.slice(0, 10) ?? "—"}</TableCell>
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
