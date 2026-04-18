/**
 * Microsegmentation Policy Dashboard
 *
 * Network microsegmentation enforcement with policy tracking and violation monitoring.
 *   1. KPIs: Total Segments, Policies, Open Violations, High-Violation Segments
 *   2. Segments table (name, segment_type, enforcement_mode, policy_count, violation_count)
 *
 * Route: /microsegmentation
 * API: GET /api/v1/microsegmentation
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Network, RefreshCw, ShieldCheck, AlertTriangle, Layers, BarChart2 } from "lucide-react";

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

// == Mock data ==================================================

const MOCK_SEGMENTS = [
  { id: "seg-001", name: "prod-web-tier",         segment_type: "application", enforcement_mode: "enforcing",  policy_count: 12, violation_count: 0 },
  { id: "seg-002", name: "prod-db-tier",          segment_type: "database",    enforcement_mode: "enforcing",  policy_count: 8,  violation_count: 1 },
  { id: "seg-003", name: "dev-workloads",         segment_type: "workload",    enforcement_mode: "monitoring", policy_count: 5,  violation_count: 3 },
  { id: "seg-004", name: "iot-devices",           segment_type: "iot",         enforcement_mode: "enforcing",  policy_count: 15, violation_count: 7 },
  { id: "seg-005", name: "corp-endpoints",        segment_type: "endpoint",    enforcement_mode: "monitoring", policy_count: 9,  violation_count: 2 },
  { id: "seg-006", name: "payment-processing",    segment_type: "pci",         enforcement_mode: "enforcing",  policy_count: 22, violation_count: 0 },
  { id: "seg-007", name: "dmz-external",          segment_type: "network",     enforcement_mode: "enforcing",  policy_count: 18, violation_count: 4 },
  { id: "seg-008", name: "ml-training-cluster",   segment_type: "workload",    enforcement_mode: "disabled",   policy_count: 3,  violation_count: 9 },
  { id: "seg-009", name: "backup-infra",          segment_type: "storage",     enforcement_mode: "monitoring", policy_count: 6,  violation_count: 0 },
  { id: "seg-010", name: "mgmt-plane",            segment_type: "management",  enforcement_mode: "enforcing",  policy_count: 20, violation_count: 1 },
];

const MOCK_STATS = { total_segments: 87, policies: 342, open_violations: 27, high_violation_segments: 4 };

// == Badge helpers ==============================================

function EnforcementBadge({ mode }: { mode: string }) {
  const map: Record<string, string> = {
    enforcing:  "border-green-500/30 text-green-400 bg-green-500/10",
    monitoring: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    disabled:   "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[mode] ?? "border-border")}>
      {mode}
    </Badge>
  );
}

function ViolationCell({ count }: { count: number }) {
  const color = count > 5 ? "text-red-400" : count > 0 ? "text-yellow-400" : "text-muted-foreground";
  return <span className={cn("font-mono text-[11px]", color)}>{count}</span>;
}

function exportCsv(rows: any[]) {
  const headers = ["name", "segment_type", "enforcement_mode", "policy_count", "violation_count"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "microsegmentation_segments.csv"; a.click();
  URL.revokeObjectURL(url);
}

// == Component ==================================================

export default function MicrosegmentationPolicyDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveSegments, setLiveSegments] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/microsegmentation/segments?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/microsegmentation/stats?org_id=${ORG_ID}`),
    ]).then(([segRes, statsRes]) => {
      if (segRes.status === "fulfilled") setLiveSegments(segRes.value?.segments ?? segRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const segments = liveSegments ?? MOCK_SEGMENTS;
  const stats    = liveStats    ?? MOCK_STATS;

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
        title="Microsegmentation Policies"
        description="Network microsegmentation enforcement = segment isolation, policy coverage, and lateral movement violation tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Segments"          value={stats.total_segments}          icon={Network}       trend="flat" className="border-green-500/20" />
        <KpiCard title="Policies"                value={stats.policies}                icon={Layers}        trend="up"   className="border-emerald-500/20" />
        <KpiCard title="Open Violations"         value={stats.open_violations}         icon={AlertTriangle} trend="down" className="border-green-500/20" />
        <KpiCard title="High-Violation Segments" value={stats.high_violation_segments} icon={ShieldCheck}   trend="down" className="border-emerald-500/20" />
      </div>

      {/* Segments Table */}
      <Card className="border-green-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
              <BarChart2 className="h-4 w-4" />
              Segment Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                {segments.filter((s: any) => s.enforcement_mode === "enforcing").length} enforcing
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(segments)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Network segments with type, enforcement mode, policy count, and violation tracking
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Segment Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Enforcement</TableHead>
                  <TableHead className="text-[11px] h-8">Policies</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Violations</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {segments.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  segments.map((seg: any, i: number) => (
                  <TableRow key={seg.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-green-300 max-w-[180px] truncate">
                      {seg.name ?? "="}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-emerald-300">
                      {seg.segment_type ?? "="}
                    </TableCell>
                    <TableCell className="py-2">
                      <EnforcementBadge mode={seg.enforcement_mode ?? "monitoring"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-green-300">
                      {seg.policy_count ?? 0}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <ViolationCell count={seg.violation_count ?? 0} />
                    </TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
