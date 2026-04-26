/**
 * Agentless Scan Status (Wave 3)
 * Route: /agentless-scan-status
 * API:   GET /api/v1/cspm/agentless/status (501 → coming-soon treatment)
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, CheckCircle2, XCircle, AlertCircle, Server } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface ScanJob {
  id?: string;
  job_id?: string;
  cloud?: string;
  account?: string;
  region?: string;
  status?: "queued" | "running" | "succeeded" | "failed" | string;
  progress?: number;
  resources_total?: number;
  resources_done?: number;
  started_at?: string;
  finished_at?: string;
  error?: string;
}
interface StatusResponse {
  enabled?: boolean;
  active_jobs?: number;
  queued?: number;
  succeeded_24h?: number;
  failed_24h?: number;
  jobs?: ScanJob[];
  items?: ScanJob[];
}

async function apiFetch<T>(path: string): Promise<{ data: T | null; status: number }> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (res.status === 404 || res.status === 501) return { data: null, status: res.status };
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return { data: (await res.json()) as T, status: res.status };
}

function statusIcon(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "succeeded":
    case "completed":
    case "ok": return <CheckCircle2 className="h-3 w-3 text-green-400" />;
    case "failed":
    case "error": return <XCircle className="h-3 w-3 text-red-400" />;
    case "running":
    case "in_progress": return <Activity className="h-3 w-3 text-blue-400 animate-pulse" />;
    default: return <AlertCircle className="h-3 w-3 text-yellow-400" />;
  }
}

export default function AgentlessScanStatus() {
  const [data, setData] = useState<StatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [notImplemented, setNotImplemented] = useState(false);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    setNotImplemented(false);
    try {
      const r = await apiFetch<StatusResponse>("/api/v1/cspm/agentless/status");
      if (!r.data) {
        setNotImplemented(true);
        setData(null);
      } else {
        setData(r.data);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const jobs = data?.jobs ?? data?.items ?? [];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Agentless Scan Status"
        description="Live status of in-flight and recent agentless cloud scan jobs"
        badge={data?.enabled === false ? "Disabled" : undefined}
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Jobs" value={data?.active_jobs ?? jobs.filter((j) => j.status === "running").length} icon={Activity} />
        <KpiCard title="Queued" value={data?.queued ?? jobs.filter((j) => j.status === "queued").length} icon={Server} />
        <KpiCard title="Succeeded (24h)" value={data?.succeeded_24h ?? 0} icon={CheckCircle2} trend="up" />
        <KpiCard title="Failed (24h)" value={data?.failed_24h ?? 0} icon={XCircle} trend="down" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4" /> Scan Jobs
          </CardTitle>
          <CardDescription className="text-xs">Currently active and recently completed</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading…</div>
          ) : err ? (
            <ErrorState message={err} onRetry={load} />
          ) : notImplemented ? (
            <EmptyState
              icon={Activity}
              title="Coming soon"
              description="The agentless-scan status endpoint is not yet enabled in this build (HTTP 501)."
            />
          ) : jobs.length === 0 ? (
            <EmptyState icon={Activity} title="No scan jobs" description="Trigger an agentless snapshot scan to populate this list." />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Job</TableHead>
                    <TableHead className="text-[11px] h-8">Cloud</TableHead>
                    <TableHead className="text-[11px] h-8">Account / Region</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Progress</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Started</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {jobs.map((j, i) => (
                    <TableRow key={(j.id ?? j.job_id ?? "j") + i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-mono">{(j.job_id ?? j.id ?? "—").slice(0, 8)}</TableCell>
                      <TableCell className="py-2 text-[11px] uppercase text-muted-foreground">{j.cloud ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] font-mono">{j.account ?? "—"} / {j.region ?? "—"}</TableCell>
                      <TableCell className="py-2"><div className="flex items-center gap-1.5">{statusIcon(j.status)}<span className="text-[11px] capitalize">{j.status ?? "—"}</span></div></TableCell>
                      <TableCell className="py-2">
                        <div className="flex items-center gap-2">
                          <Progress value={j.progress ?? (j.resources_total ? ((j.resources_done ?? 0) / j.resources_total) * 100 : 0)} className="h-1 w-24" />
                          <span className="text-[10px] font-mono text-muted-foreground w-10 text-right">{j.resources_done ?? 0}/{j.resources_total ?? "?"}</span>
                        </div>
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{j.started_at?.replace("T", " ").slice(0, 16) ?? "—"}</TableCell>
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
