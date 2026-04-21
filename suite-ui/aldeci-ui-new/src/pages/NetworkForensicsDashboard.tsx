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
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_CAPTURES = [
  { id: "cap-a1b2c3d4", interface: "eth0",   filter_bpf: "tcp port 443",         duration_sec: 3600, status: "completed", started_at: "2026-04-16 08:00:00" },
  { id: "cap-e5f6g7h8", interface: "eth1",   filter_bpf: "host 10.0.0.55",        duration_sec: 1800, status: "running",   started_at: "2026-04-16 09:30:00" },
  { id: "cap-i9j0k1l2", interface: "eth0",   filter_bpf: "udp port 53",           duration_sec: 900,  status: "completed", started_at: "2026-04-16 07:15:00" },
  { id: "cap-m3n4o5p6", interface: "eth2",   filter_bpf: "tcp port 22",           duration_sec: 7200, status: "running",   started_at: "2026-04-16 06:00:00" },
  { id: "cap-q7r8s9t0", interface: "eth0",   filter_bpf: "icmp",                  duration_sec: 600,  status: "failed",    started_at: "2026-04-16 10:00:00" },
  { id: "cap-u1v2w3x4", interface: "eth3",   filter_bpf: "net 192.168.0.0/24",    duration_sec: 5400, status: "completed", started_at: "2026-04-16 05:00:00" },
  { id: "cap-y5z6a7b8", interface: "eth1",   filter_bpf: "tcp port 8080 or 8443", duration_sec: 2700, status: "running",   started_at: "2026-04-16 09:00:00" },
  { id: "cap-c9d0e1f2", interface: "eth0",   filter_bpf: "host 172.16.0.10",      duration_sec: 1200, status: "completed", started_at: "2026-04-16 04:00:00" },
];

const MOCK_STATS = { active_captures: 3, total_artifacts: 214, suspicious_captures: 2, total_captures: 47 };

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
  const [liveCaptures, setLiveCaptures] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/network-forensics/captures?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/network-forensics/stats?org_id=${ORG_ID}`),
    ]).then(([capturesRes, statsRes]) => {
      if (capturesRes.status === "fulfilled") setLiveCaptures(capturesRes.value?.captures ?? capturesRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const captures = liveCaptures ?? MOCK_CAPTURES;
  const stats    = liveStats    ?? MOCK_STATS;


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


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
        </CardContent>
      </Card>
    </motion.div>
  );
}
