// FOLDED into AssetInventoryHub at /discover/assets/inventory?tab=snapshot (Phase 3, 2026-05-02)
/**
 * Agentless Snapshot Dashboard
 *
 * Agentless workload snapshots — scans running VMs/containers without installing agents.
 * Route: /agentless-snapshot
 * API: GET /api/v1/agentless-snapshot/snapshots, /findings, /stats
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Camera, RefreshCw, Bug, Server, HardDrive, ShieldAlert } from "lucide-react";

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

interface Snapshot {
  id?: string;
  snapshot_id?: string;
  resource_id?: string;
  resource_type?: string;
  cloud?: string;
  status?: string;
  size_bytes?: number;
  created_at?: string;
}

interface Finding {
  id?: string;
  snapshot_id?: string;
  title?: string;
  severity?: string;
  package?: string;
  cve?: string;
}

interface Stats {
  total_snapshots?: number;
  findings_total?: number;
  critical_findings?: number;
  resources_scanned?: number;
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function severityBadge(s?: string) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return map[(s ?? "low").toLowerCase()] ?? "border-border";
}

function formatBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

export default function AgentlessSnapshotDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [sn, fi, st] = await Promise.allSettled([
        apiFetch<Snapshot[] | { snapshots?: Snapshot[] }>("/api/v1/agentless-snapshot/snapshots"),
        apiFetch<Finding[] | { findings?: Finding[] }>("/api/v1/agentless-snapshot/findings"),
        apiFetch<Stats>("/api/v1/agentless-snapshot/stats"),
      ]);
      setSnapshots(sn.status === "fulfilled" ? (Array.isArray(sn.value) ? sn.value : sn.value.snapshots ?? []) : []);
      setFindings(fi.status === "fulfilled" ? (Array.isArray(fi.value) ? fi.value : fi.value.findings ?? []) : []);
      setStats(st.status === "fulfilled" ? st.value : null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const totalSnapshots = stats?.total_snapshots ?? snapshots.length;
  const findingsTotal = stats?.findings_total ?? findings.length;
  const criticalFindings = stats?.critical_findings ?? findings.filter(f => (f.severity ?? "").toLowerCase() === "critical").length;
  const resources = stats?.resources_scanned ?? new Set(snapshots.map(s => s.resource_id)).size;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Agentless Snapshot"
        description="Agentless vulnerability scanning — disk-snapshot-based analysis without installing agents"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Snapshots" value={totalSnapshots} icon={Camera} />
        <KpiCard title="Resources Scanned" value={resources} icon={Server} />
        <KpiCard title="Findings" value={findingsTotal} icon={Bug} />
        <KpiCard title="Critical" value={criticalFindings} icon={ShieldAlert} trend="down" />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2"><HardDrive className="h-4 w-4" /> Snapshots</CardTitle>
            <CardDescription className="text-xs">Point-in-time disk snapshots scanned for vulns</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="p-6 text-sm text-muted-foreground">Loading…</div>
            ) : err ? (
              <ErrorState message={err} onRetry={load} />
            ) : snapshots.length === 0 ? (
              <EmptyState icon={Camera} title="No snapshots" description="Snapshots will appear here when scan jobs run." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Resource</TableHead>
                      <TableHead className="text-[11px] h-8">Cloud</TableHead>
                      <TableHead className="text-[11px] h-8">Size</TableHead>
                      <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {snapshots.map((s, i) => (
                      <TableRow key={s.id ?? s.snapshot_id ?? i} className="hover:bg-muted/30">
                        <TableCell className="py-2 text-[11px] font-mono">{s.resource_id ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground uppercase">{s.cloud ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] font-mono">{formatBytes(s.size_bytes)}</TableCell>
                        <TableCell className="py-2 text-right"><Badge className="text-[10px] border border-border capitalize">{s.status ?? "—"}</Badge></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2"><Bug className="h-4 w-4" /> Findings</CardTitle>
            <CardDescription className="text-xs">Vulnerabilities detected inside snapshot disk contents</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="p-6 text-sm text-muted-foreground">Loading…</div>
            ) : findings.length === 0 ? (
              <EmptyState icon={Bug} title="No findings" description="No vulnerabilities detected in snapshots yet." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Finding</TableHead>
                      <TableHead className="text-[11px] h-8">CVE</TableHead>
                      <TableHead className="text-[11px] h-8">Package</TableHead>
                      <TableHead className="text-[11px] h-8 text-right">Severity</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map((f, i) => (
                      <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                        <TableCell className="py-2 text-[11px] max-w-[220px] truncate">{f.title ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{f.cve ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground">{f.package ?? "—"}</TableCell>
                        <TableCell className="py-2 text-right"><Badge className={cn("text-[10px] border capitalize", severityBadge(f.severity))}>{f.severity ?? "low"}</Badge></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
