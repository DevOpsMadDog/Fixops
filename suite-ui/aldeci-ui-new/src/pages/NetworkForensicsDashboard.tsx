/**
 * Network Forensics Dashboard
 *
 * Packet capture management and artifact tracking for network forensics.
 *   1. KPIs: Active Captures, Total Artifacts, Suspicious Captures, Total Captures
 *   2. Captures table (id, interface, filter_bpf, duration_sec, status, started_at)
 *
 * Route: /network-forensics
 * API: GET /api/v1/network-forensics/captures
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Network, RefreshCw, AlertTriangle, Database, Activity } from "lucide-react";

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

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    running:   "border-green-500/30 text-green-400 bg-green-500/10",
    completed: "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function NetworkForensicsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [captures, setCaptures] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ active_captures: 0, total_artifacts: 0, suspicious_captures: 0, total_captures: 0 });

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [capRes, artRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/network-forensics/captures"),
        apiFetch<any>("/api/v1/network-forensics/artifacts"),
      ]);
      let capArr: any[] = [];
      if (capRes.status === "fulfilled") {
        const v = capRes.value;
        capArr = Array.isArray(v) ? v : (v?.captures ?? v?.items ?? []);
        setCaptures(capArr);
      } else {
        setError((capRes.reason as Error).message);
      }
      const artCount = artRes.status === "fulfilled"
        ? (Array.isArray(artRes.value) ? artRes.value.length : (artRes.value?.artifacts?.length ?? artRes.value?.items?.length ?? 0))
        : 0;
      setStats({
        active_captures: capArr.filter((c: any) => c.status === "running").length,
        total_artifacts: artCount,
        suspicious_captures: capArr.filter((c: any) => c.suspicious === true).length,
        total_captures: capArr.length,
      });
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
        title="Network Forensics"
        description="Packet capture management, artifact tracking, and network traffic analysis for forensic investigations"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Captures"    value={stats.active_captures}    icon={Activity}      trend="flat" />
        <KpiCard title="Total Artifacts"    value={stats.total_artifacts}    icon={Database}      trend="flat" className="border-indigo-500/20" />
        <KpiCard title="Suspicious Captures" value={stats.suspicious_captures} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Total Captures"     value={stats.total_captures}     icon={Network}       trend="flat" className="border-purple-500/20" />
      </div>

      {/* Captures Table */}
      <Card className="border-indigo-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-indigo-400">
              <Network className="h-4 w-4" />
              Packet Captures
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              {captures.filter((c: any) => c.status === "running").length} running
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Active and completed packet captures with BPF filters and artifact metadata
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {captures.length === 0 && !error ? <EmptyState icon={Network} title="No packet captures" description="Start a packet capture to populate this view." /> : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Capture ID</TableHead>
                  <TableHead className="text-[11px] h-8">Interface</TableHead>
                  <TableHead className="text-[11px] h-8">BPF Filter</TableHead>
                  <TableHead className="text-[11px] h-8">Duration (s)</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Started At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {captures.map((cap: any, i: number) => (
                  <TableRow key={cap.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] font-semibold text-indigo-300">
                      {(cap.id ?? "").slice(0, 12)}…
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {cap.interface ?? "eth0"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-purple-300 max-w-[200px] truncate">
                      {cap.filter_bpf ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {cap.duration_sec ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={cap.status ?? "completed"} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {cap.started_at ?? "—"}
                    </TableCell>
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
