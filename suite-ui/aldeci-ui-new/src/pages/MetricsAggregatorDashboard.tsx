// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Metrics Aggregator Dashboard
 *
 * Cross-domain security metric sources, aggregations, and alert triggers.
 *   1. KPIs: Total Metrics, Sources Active, Aggregations/hr, Alerts Triggered
 *   2. Metric sources table (name, type, last_collected, metric_count, status)
 *
 * Route: /metrics-aggregator
 * API: GET /api/v1/metrics-aggregator/sources
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BarChart3, RefreshCw, Database, Bell, Activity } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Badge helpers ──────────────────────────────────────────────

function SourceTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    siem:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    edr:       "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    cloud:     "border-sky-500/30 text-sky-400 bg-sky-500/10",
    vuln:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    network:   "border-teal-500/30 text-teal-400 bg-teal-500/10",
    identity:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    container: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    dlp:       "border-rose-500/30 text-rose-400 bg-rose-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>{type}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    degraded: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    offline:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function MetricsAggregatorDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sources, setSources] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ total_metrics: 0, sources_active: 0, aggregations_hr: 0, alerts_triggered: 0 });

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [sourcesRes, statsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/metrics-aggregator/all"),
        apiFetch<any>("/api/v1/metrics-aggregator/health"),
      ]);
      if (sourcesRes.status === "fulfilled") {
        const v = sourcesRes.value;
        const arr = Array.isArray(v) ? v : (v?.sources ?? v?.metrics ?? v?.items ?? []);
        setSources(arr);
        setStats((prev: any) => ({ ...prev, total_metrics: Array.isArray(arr) ? arr.length : 0, sources_active: arr.length }));
      } else {
        setError((sourcesRes.reason as Error).message);
      }
      if (statsRes.status === "fulfilled") {
        const v = statsRes.value;
        setStats((prev: any) => ({
          ...prev,
          aggregations_hr: v?.aggregations_per_hour ?? v?.aggregations_hr ?? prev.aggregations_hr,
          alerts_triggered: v?.alerts_triggered ?? v?.alerts ?? prev.alerts_triggered,
        }));
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { load(); };

  if (loading) return <PageSkeleton />;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Metrics Aggregator"
        description="Cross-domain security metric collection, aggregation, and alert correlation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Metrics"      value={(stats.total_metrics ?? 0).toLocaleString()}    icon={BarChart3}  trend="up" />
        <KpiCard title="Sources Active"     value={stats.sources_active ?? 0}                      icon={Database}   trend="flat" className="border-cyan-500/20" />
        <KpiCard title="Aggregations / hr"  value={(stats.aggregations_hr ?? 0).toLocaleString()}  icon={Activity}   trend="up"      className="border-blue-500/20" />
        <KpiCard title="Alerts Triggered"   value={stats.alerts_triggered ?? 0}                    icon={Bell}       trend="up"      className="border-amber-500/20" />
      </div>

      {/* Sources Table */}
      <Card className="border-cyan-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-cyan-400">
            <Database className="h-4 w-4" />
            Metric Sources
          </CardTitle>
          <CardDescription className="text-xs">
            Active telemetry sources feeding the aggregation pipeline
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {sources.length === 0 && !error ? <EmptyState icon={Database} title="No metric sources" description="No telemetry sources are currently feeding the aggregation pipeline for this org." /> : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Source Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Last Collected</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Metrics</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sources.map((src: any, i: number) => (
                  <TableRow key={src.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{src.id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium">{src.name}</TableCell>
                    <TableCell className="py-2"><SourceTypeBadge type={src.type ?? src.source_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{src.last_collected ?? src.last_seen ?? "—"}</TableCell>
                    <TableCell className="py-2 text-right font-mono text-xs tabular-nums">
                      {(src.metric_count ?? src.metrics ?? 0).toLocaleString()}
                    </TableCell>
                    <TableCell className="py-2 text-right"><StatusBadge status={src.status ?? "active"} /></TableCell>
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
