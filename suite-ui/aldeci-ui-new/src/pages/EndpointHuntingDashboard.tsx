/**
 * Endpoint Threat Hunting Dashboard
 *
 * Active hunt campaigns, IOC matches, and endpoint coverage.
 *   1. KPIs: Hunts Active, Endpoints Covered, Threats Found, IOCs Matched
 *   2. Hunt campaigns table (name, query, endpoints_scanned, hits, status)
 *
 * Route: /endpoint-hunting
 * API: GET /api/v1/endpoint-hunting/hunts
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search, RefreshCw, Target, Shield, AlertTriangle, Crosshair } from "lucide-react";

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

const MOCK_HUNTS = [
  { id: "HNT-001", name: "LOLBAS Execution Hunt",          query: "process.name IN ('regsvr32','mshta','wscript')",  endpoints_scanned: 1240, hits: 7,  status: "active" },
  { id: "HNT-002", name: "Lateral Movement via PsExec",    query: "parent.name='psexec.exe' AND remote=true",        endpoints_scanned: 1240, hits: 2,  status: "active" },
  { id: "HNT-003", name: "Credential Dumping Detection",   query: "proc.name='lsass.exe' AND memory_access=true",    endpoints_scanned: 890,  hits: 1,  status: "active" },
  { id: "HNT-004", name: "Cobalt Strike Beacon Hunt",      query: "network.port=4444 AND proc.injected=true",        endpoints_scanned: 1240, hits: 0,  status: "completed" },
  { id: "HNT-005", name: "Ransomware Precursor Activity",  query: "file.ext IN ('.bat','.vbs') AND bulk_rename=true", endpoints_scanned: 620,  hits: 3,  status: "active" },
  { id: "HNT-006", name: "DNS Tunneling IOC Sweep",        query: "dns.query.length > 60 AND ttl < 30",              endpoints_scanned: 1240, hits: 4,  status: "active" },
  { id: "HNT-007", name: "Scheduled Task Persistence",     query: "schtasks.exe AND /create AND user=SYSTEM",        endpoints_scanned: 740,  hits: 6,  status: "active" },
  { id: "HNT-008", name: "Shadow Copy Deletion Hunt",      query: "vssadmin delete shadows",                         endpoints_scanned: 1240, hits: 0,  status: "completed" },
];

const MOCK_STATS = { hunts_active: 6, endpoints_covered: 1240, threats_found: 23, iocs_matched: 47 };

// ── Badge helpers ──────────────────────────────────────────────

function HuntStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    planned:   "border-slate-500/30 text-slate-400 bg-slate-500/10",
    paused:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function HitsBadge({ hits }: { hits: number }) {
  const cls = hits === 0
    ? "border-slate-500/30 text-slate-400 bg-slate-500/10"
    : hits >= 5
    ? "border-red-500/30 text-red-400 bg-red-500/10"
    : "border-amber-500/30 text-amber-400 bg-amber-500/10";
  return <Badge className={cn("text-[10px] border tabular-nums font-mono", cls)}>{hits} hits</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function EndpointHuntingDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveHunts, setLiveHunts]   = useState<any[] | null>(null);
  const [liveStats, setLiveStats]   = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/endpoint-hunting/hunts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/endpoint-hunting/stats?org_id=${ORG_ID}`),
    ]).then(([huntsRes, statsRes]) => {
      if (huntsRes.status === "fulfilled") setLiveHunts(huntsRes.value?.hunts ?? huntsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const hunts = liveHunts ?? MOCK_HUNTS;
  const stats = liveStats  ?? MOCK_STATS;

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
        title="Endpoint Threat Hunting"
        description="Proactive hunt campaigns across managed endpoints — IOC sweeps and behavioral queries"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Hunts Active"       value={stats.hunts_active}      icon={Crosshair}      trend="flat" className="border-orange-500/20" />
        <KpiCard title="Endpoints Covered"  value={stats.endpoints_covered}  icon={Shield}         trend="up" />
        <KpiCard title="Threats Found"      value={stats.threats_found}      icon={AlertTriangle}  trend="up"   className="border-red-500/20" />
        <KpiCard title="IOCs Matched"       value={stats.iocs_matched}       icon={Target}         trend="up"   className="border-amber-500/20" />
      </div>

      {/* Hunt Campaigns Table */}
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
            <Search className="h-4 w-4" />
            Hunt Campaigns
          </CardTitle>
          <CardDescription className="text-xs">
            Active and completed threat hunt campaigns with hit counts
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Hunt Name</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[240px]">Query</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Endpoints</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Hits</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hunts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  hunts.map((hunt: any, i: number) => (
                  <TableRow key={hunt.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{hunt.id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium max-w-[180px] truncate">{hunt.name}</TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[240px] truncate">
                      {hunt.query ?? hunt.hunt_query ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-right font-mono text-xs tabular-nums">
                      {(hunt.endpoints_scanned ?? hunt.endpoints ?? 0).toLocaleString()}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <HitsBadge hits={hunt.hits ?? hunt.findings_count ?? 0} />
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <HuntStatusBadge status={hunt.status ?? "active"} />
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
