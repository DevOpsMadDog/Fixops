/**
 * Data Pipeline Dashboard
 *
 * Security data pipeline monitoring with ingestion stats and error tracking.
 *   1. KPIs: Total Pipelines, Active, Records Processed, Error Rate %
 *   2. Pipelines table (name, source_type, data_format, status, records_processed, last_run)
 *
 * Route: /data-pipeline
 * API: GET /api/v1/data-pipeline
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { GitMerge, RefreshCw, Zap, Database, BarChart2, AlertCircle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_PIPELINES = [
  { id: "pipe-001", name: "SIEM Event Ingest",        source_type: "siem",         data_format: "CEF",     status: "active",  records_processed: 4820341, last_run: "2026-04-16T09:55:00Z" },
  { id: "pipe-002", name: "EDR Alert Normalizer",     source_type: "edr",          data_format: "JSON",    status: "active",  records_processed: 1293847, last_run: "2026-04-16T09:50:00Z" },
  { id: "pipe-003", name: "Cloud Audit Log Ingester", source_type: "cloud",        data_format: "JSON",    status: "active",  records_processed: 3017293, last_run: "2026-04-16T09:52:00Z" },
  { id: "pipe-004", name: "Threat Feed Aggregator",   source_type: "threat_intel", data_format: "STIX2",   status: "paused",  records_processed: 892401,  last_run: "2026-04-15T22:00:00Z" },
  { id: "pipe-005", name: "Vuln Scanner Results",     source_type: "scanner",      data_format: "XML",     status: "active",  records_processed: 412839,  last_run: "2026-04-16T08:30:00Z" },
  { id: "pipe-006", name: "Network Flow Collector",   source_type: "network",      data_format: "NetFlow", status: "error",   records_processed: 0,       last_run: "2026-04-16T07:10:00Z" },
  { id: "pipe-007", name: "IAM Audit Events",         source_type: "iam",          data_format: "JSON",    status: "active",  records_processed: 2140582, last_run: "2026-04-16T09:48:00Z" },
  { id: "pipe-008", name: "DLP Incident Feed",        source_type: "dlp",          data_format: "CSV",     status: "stopped", records_processed: 58340,   last_run: "2026-04-14T18:00:00Z" },
  { id: "pipe-009", name: "Container Runtime Logs",   source_type: "container",    data_format: "JSON",    status: "active",  records_processed: 987432,  last_run: "2026-04-16T09:53:00Z" },
  { id: "pipe-010", name: "Endpoint Telemetry",       source_type: "endpoint",     data_format: "Protobuf",status: "active",  records_processed: 5634291, last_run: "2026-04-16T09:56:00Z" },
];

const MOCK_STATS = { total_pipelines: 38, active_pipelines: 29, records_processed: 19257370, error_rate: 2.6 };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:  "border-green-500/30 text-green-400 bg-green-500/10",
    paused:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    error:   "border-red-500/30 text-red-400 bg-red-500/10",
    stopped: "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function formatTs(ts: string) {
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

function formatRecords(n: number) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

// ── Component ──────────────────────────────────────────────────

export default function DataPipelineDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [livePipelines, setLivePipelines] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/data-pipeline/pipelines?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/data-pipeline/stats?org_id=${ORG_ID}`),
    ]).then(([pipeRes, statsRes]) => {
      if (pipeRes.status === "fulfilled") setLivePipelines(pipeRes.value?.pipelines ?? pipeRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const pipelines = livePipelines ?? MOCK_PIPELINES;
  const stats     = liveStats     ?? MOCK_STATS;

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
      <PageHeader
        title="Data Pipeline"
        description="Security data ingestion pipeline monitoring — source health, record throughput, and error rate tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Pipelines"    value={stats.total_pipelines}                        icon={GitMerge}   trend="flat" className="border-emerald-500/20" />
        <KpiCard title="Active"             value={stats.active_pipelines}                       icon={Zap}        trend="up"   className="border-teal-500/20" />
        <KpiCard title="Records Processed"  value={formatRecords(stats.records_processed ?? 0)}  icon={Database}   trend="up"   className="border-emerald-500/20" />
        <KpiCard title="Error Rate %"       value={`${stats.error_rate}%`}                       icon={AlertCircle} trend="down" className="border-teal-500/20" />
      </div>

      {/* Pipelines Table */}
      <Card className="border-emerald-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-emerald-400">
              <BarChart2 className="h-4 w-4" />
              Pipeline Registry
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {pipelines.filter((p: any) => p.status === "error").length} errored
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Data ingestion pipelines with source type, format, throughput, and health status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Pipeline Name</TableHead>
                  <TableHead className="text-[11px] h-8">Source Type</TableHead>
                  <TableHead className="text-[11px] h-8">Format</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Records</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Last Run</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pipelines.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  pipelines.map((pipe: any, i: number) => (
                  <TableRow key={pipe.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-emerald-300 max-w-[200px] truncate">
                      {pipe.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(pipe.source_type ?? "—").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-teal-300">
                      {pipe.data_format ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={pipe.status ?? "stopped"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-teal-300">
                      {formatRecords(pipe.records_processed ?? 0)}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {pipe.last_run ? formatTs(pipe.last_run) : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
