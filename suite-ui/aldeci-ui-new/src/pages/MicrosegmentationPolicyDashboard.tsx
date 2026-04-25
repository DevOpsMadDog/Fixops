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

import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

const ORG_ID = "juice-shop-corp";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Badge helpers ──────────────────────────────────────────────

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

// ── Component ──────────────────────────────────────────────────

export default function MicrosegmentationPolicyDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveSegments, setLiveSegments] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/microsegmentation/segments?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/microsegmentation/stats?org_id=${ORG_ID}`),
    ]).then(([segRes, statsRes]) => {
      if (segRes.status === "fulfilled") {
        const v = segRes.value;
        setLiveSegments(Array.isArray(v) ? v : (v?.segments ?? v?.items ?? []));
      } else {
        setLiveSegments([]);
      }
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
      setLoading(false);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const segments = liveSegments ?? [];
  const stats    = liveStats    ?? { total_segments: 0, policies: 0, open_violations: 0, high_violation_segments: 0 };

  if (loading) return <PageSkeleton />;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Microsegmentation Policies"
        description="Network microsegmentation enforcement — segment isolation, policy coverage, and lateral movement violation tracking"
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
          {segments.length === 0 ? (
            <EmptyState icon={Network} title="No segments registered" description="Configure microsegmentation policies to populate the segment registry." />
          ) : (
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
                {segments.map((seg: any, i: number) => (
                  <TableRow key={seg.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-green-300 max-w-[180px] truncate">
                      {seg.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-emerald-300">
                      {seg.segment_type ?? "—"}
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
