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

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SEGMENTS = [
  { id: "SEG-001", name: "production-web",    type: "application", cidr: "10.1.0.0/24",   trust_level: "medium"    },
  { id: "SEG-002", name: "production-db",     type: "data",        cidr: "10.2.0.0/24",   trust_level: "high"      },
  { id: "SEG-003", name: "management",        type: "management",  cidr: "10.3.0.0/28",   trust_level: "critical"  },
  { id: "SEG-004", name: "dmz-public",        type: "dmz",         cidr: "172.16.0.0/25", trust_level: "untrusted" },
  { id: "SEG-005", name: "dev-environment",   type: "development", cidr: "10.4.0.0/22",   trust_level: "low"       },
  { id: "SEG-006", name: "cloud-workloads",   type: "cloud",       cidr: "10.5.0.0/20",   trust_level: "medium"    },
  { id: "SEG-007", name: "iot-devices",       type: "iot",         cidr: "192.168.0.0/22",trust_level: "untrusted" },
  { id: "SEG-008", name: "backup-storage",    type: "data",        cidr: "10.6.0.0/24",   trust_level: "high"      },
];

const MOCK_STATS = {
  segments: 8,
  flow_policies: 143,
  segmentation_score: 74,
  lateral_movement_risks: 5,
};

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
  const [liveData, setLiveData] = useState<any>(null);

  const [fetchError, setFetchError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = (isRefresh = false) => {
    setFetchError(null);
    if (isRefresh) setRefreshing(true);
    apiFetch(`/api/v1/network-segmentation/stats?org_id=${ORG_ID}`)
      .then((d) => setLiveData(d))
      .catch((err) => {
        setFetchError(err instanceof Error ? err.message : "Failed to load segmentation data");
      })
      .finally(() => { if (isRefresh) setRefreshing(false); });
  };

  useEffect(() => {
    loadData();}, []);

  const stats    = liveData ?? MOCK_STATS;
  const segments = liveData?.segments ?? MOCK_SEGMENTS;

  const score         = stats.segmentation_score ?? 74;
  const lateralRisks  = stats.lateral_movement_risks ?? 5;

  const handleRefresh = () => {
    loadData(true);
  };

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
        title="Network Segmentation"
        description="Micro-segmentation coverage, flow policies, and lateral movement risk"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={() => loadData()} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Segments"               value={stats.segments ?? 8}              icon={Network}      trend="flat" />
        <KpiCard title="Flow Policies"          value={stats.flow_policies ?? 143}       icon={GitBranch}    trend="up" />
        <KpiCard title="Segmentation Score"     value={`${score}/100`}                  icon={ShieldCheck}  trend="neutral" />
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
                  {segments.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    segments.map((seg: any) => (
                    <TableRow key={seg.id} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-xs text-foreground">{seg.name}</TableCell>
                      <TableCell className="py-2"><SegTypeBadge type={seg.type} /></TableCell>
                      <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{seg.cidr}</TableCell>
                      <TableCell className="py-2"><TrustBadge level={seg.trust_level} /></TableCell>
                    </TableRow>
                  ))
                )}
                </TableBody>
              </Table>
            </div>
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
                <span className="font-semibold">{stats.flow_policies ?? 143}</span>
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
