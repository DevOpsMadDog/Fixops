/**
 * Network Segmentation Dashboard
 *
 * Network micro-segmentation — segments, flow policies, lateral movement risk.
 *   1. KPIs: Segments, Flow Policies, Segmentation Score, Lateral Movement Risks
 *   2. Segments table (name, type, CIDR, trust level)
 *
 * Route: /network-segmentation
 * API: GET /api/v1/network-segmentation/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Network, GitBranch, ShieldCheck, AlertTriangle, RefreshCw } from "lucide-react";
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

function TrustBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    high:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    medium:     "border-green-500/30 text-green-400 bg-green-500/10",
    low:        "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    untrusted:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function SegTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    application: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    data:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    management:  "border-red-500/30 text-red-400 bg-red-500/10",
    dmz:         "border-orange-500/30 text-orange-400 bg-orange-500/10",
    development: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    cloud:       "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    iot:         "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize font-mono", map[type] ?? "border-slate-500/30 text-slate-400 bg-slate-500/10")}>
      {type}
    </Badge>
  );
}

function SegmentationScoreGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 36;
  const color = score >= 70 ? "rgb(34 197 94)" : score >= 40 ? "rgb(251 191 36)" : "rgb(239 68 68)";
  const label = score >= 70 ? "Good" : score >= 40 ? "Moderate" : "Poor";
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative h-24 w-24">
        <svg viewBox="0 0 88 88" className="h-full w-full -rotate-90">
          <circle cx="44" cy="44" r="36" fill="none" stroke="hsl(var(--muted))" strokeWidth="10" />
          <motion.circle
            cx="44" cy="44" r="36" fill="none"
            stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
            initial={{ strokeDasharray: `0 ${circumference}` }}
            animate={{ strokeDasharray: `${(score / 100) * circumference} ${circumference}` }}
            transition={{ duration: 1.2, ease: "easeOut" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums">{score}</span>
          <span className="text-[10px] text-muted-foreground">/100</span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-sm font-semibold" style={{ color }}>{label}</div>
        <div className="text-[10px] text-muted-foreground">Segmentation Score</div>
      </div>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function NetworkSegmentationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [segments, setSegments] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ segments: 0, flow_policies: 0, segmentation_score: 0, lateral_movement_risks: 0 });

  const loadData = async () => {
    setRefreshing(true);
    setFetchError(null);
    try {
      const [segRes, polRes, scoreRes, lateralRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/network-segmentation/segments"),
        apiFetch<any>("/api/v1/network-segmentation/flow-policies"),
        apiFetch<any>("/api/v1/network-segmentation/score"),
        apiFetch<any>("/api/v1/network-segmentation/lateral-movement-risk"),
      ]);
      let segArr: any[] = [];
      if (segRes.status === "fulfilled") {
        const v = segRes.value;
        segArr = Array.isArray(v) ? v : (v?.segments ?? v?.items ?? []);
        setSegments(segArr);
      } else {
        setFetchError((segRes.reason as Error).message);
      }
      const polCount = polRes.status === "fulfilled"
        ? (Array.isArray(polRes.value) ? polRes.value.length : (polRes.value?.policies?.length ?? polRes.value?.items?.length ?? 0))
        : 0;
      const score = scoreRes.status === "fulfilled" ? (scoreRes.value?.score ?? scoreRes.value?.segmentation_score ?? 0) : 0;
      const lateralRisks = lateralRes.status === "fulfilled"
        ? (lateralRes.value?.risks?.length ?? lateralRes.value?.lateral_movement_risks ?? (Array.isArray(lateralRes.value) ? lateralRes.value.length : 0))
        : 0;
      setStats({ segments: segArr.length, flow_policies: polCount, segmentation_score: score, lateral_movement_risks: lateralRisks });
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : "Failed to load segmentation data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { loadData(); }, []);

  const score        = stats.segmentation_score ?? 0;
  const lateralRisks = stats.lateral_movement_risks ?? 0;

  const handleRefresh = () => { loadData(); };

  if (loading) return <PageSkeleton />;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Network Segmentation"
        description="Micro-segmentation coverage, flow policies, and lateral movement risk"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {fetchError && <ErrorState message={fetchError} onRetry={loadData} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Segments"               value={stats.segments ?? 0}              icon={Network}      trend="flat" />
        <KpiCard title="Flow Policies"          value={stats.flow_policies ?? 0}         icon={GitBranch}    trend="up" />
        <KpiCard title="Segmentation Score"     value={`${score}/100`}                  icon={ShieldCheck}  trend="flat" />
        <KpiCard title="Lateral Movement Risks" value={lateralRisks}                    icon={AlertTriangle} trend="up" className="border-red-500/20" />
      </div>

      {/* Segments table + score gauge */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Table — 2/3 width */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Network className="h-4 w-4 text-blue-400" />
              Network Segments
            </CardTitle>
            <CardDescription className="text-xs">
              Defined segments with CIDR ranges and trust classification
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {segments.length === 0 && !fetchError ? <EmptyState icon={Network} title="No segments defined" description="Define network segments to enable micro-segmentation policies." /> : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 font-mono">CIDR</TableHead>
                    <TableHead className="text-[11px] h-8">Trust Level</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {segments.map((seg: any) => (
                    <TableRow key={seg.id ?? seg.name} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-xs text-foreground">{seg.name}</TableCell>
                      <TableCell className="py-2"><SegTypeBadge type={seg.type ?? "application"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{seg.cidr}</TableCell>
                      <TableCell className="py-2"><TrustBadge level={seg.trust_level ?? "medium"} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            )}
          </CardContent>
        </Card>

        {/* Score gauge — 1/3 width */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-green-400" />
              Segmentation Health
            </CardTitle>
            <CardDescription className="text-xs">
              100 = fully segmented, 0 = flat network
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center pt-4 pb-6">
            <SegmentationScoreGauge score={score} />
            <div className="mt-4 w-full space-y-1.5 text-[11px] text-muted-foreground">
              <div className="flex justify-between">
                <span>Segments</span>
                <span className="font-semibold">{segments.length}</span>
              </div>
              <div className="flex justify-between">
                <span>Flow policies</span>
                <span className="font-semibold">{stats.flow_policies ?? 0}</span>
              </div>
              <div className="flex justify-between">
                <span>Lateral risks</span>
                <span className={cn("font-semibold", lateralRisks > 0 ? "text-red-400" : "text-green-400")}>
                  {lateralRisks}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
