// FOLDED into ExternalThreatIntelHub hero (zeroday tab) 2026-05-02 — preserve for git history
/**
 * Zero-Day Intelligence Dashboard
 *
 * Tracks zero-day and N-day vulnerabilities, exploitation status, and threat actors.
 *   1. KPI cards: Total Vulns, Unpatched, Actively Exploited, Critical
 *   2. Vulnerabilities table
 *   3. Threat Actors table
 *
 * API: GET /api/v1/zero-day/{stats,vulns,threat-actors}
 */

import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  AlertTriangle, RefreshCw, ShieldOff, Zap, Bug, Users,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Badge helpers ──────────────────────────────────────────────

function DisclosureBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    "zero-day": "border-red-500/30 text-red-400 bg-red-500/10",
    "n-day":    "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function ExploitStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-red-500/30 text-red-400 bg-red-500/10",
    poc:      "border-orange-500/30 text-orange-400 bg-orange-500/10",
    none:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function PatchStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    patched:   "border-green-500/30 text-green-400 bg-green-500/10",
    partial:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    unpatched: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function ActorTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    "nation-state": "border-purple-500/30 text-purple-400 bg-purple-500/10",
    criminal:       "border-red-500/30 text-red-400 bg-red-500/10",
    espionage:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    hacktivist:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function cvssColor(score: number): string {
  if (score >= 9.0) return "text-red-400";
  if (score >= 7.0) return "text-orange-400";
  if (score >= 4.0) return "text-amber-400";
  return "text-green-400";
}

// ── Component ──────────────────────────────────────────────────

export default function ZeroDayIntelligenceDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    vulns: any[] | null;
    actors: any[] | null;
  }>({ stats: null, vulns: null, actors: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/zero-day/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/zero-day/vulns?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/zero-day/threat-actors?org_id=${ORG_ID}`),
    ]).then(([statsRes, vulnsRes, actorsRes]) => {
      setLiveData({
        stats:  statsRes.status  === "fulfilled" ? statsRes.value  : null,
        vulns:  vulnsRes.status  === "fulfilled" ? vulnsRes.value  : null,
        actors: actorsRes.status === "fulfilled" ? actorsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats  = liveData.stats  ?? null;
  const vulns  = liveData.vulns  ?? [];
  const actors = liveData.actors ?? [];
  const hasAnyData = Boolean(stats) || vulns.length > 0 || actors.length > 0;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Zero-Day Intelligence"
        description="Zero-day and N-day vulnerability tracking, exploitation status, and threat actor attribution"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />
      <EmptyState
        icon={Bug}
        title="No zero-day intelligence yet"
        description="Connect a CVE feed or threat-intel source to populate this view."
        action={
          <Link to="/onboarding" className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500">
            Start onboarding
          </Link>
        }
      />
    </motion.div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Zero-Day Intelligence"
        description="Zero-day and N-day vulnerability tracking, exploitation status, and threat actor attribution"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Vulns"         value={stats?.total_vulns ?? "—"}         icon={Bug}           trend="flat" />
        <KpiCard title="Unpatched"           value={stats?.unpatched_count ?? "—"}    icon={ShieldOff}     trend="down" className="border-orange-500/20" />
        <KpiCard title="Actively Exploited"  value={stats?.actively_exploited ?? "—"} icon={Zap}           trend="down" className="border-red-500/20" />
        <KpiCard title="Critical"            value={stats?.critical_count ?? "—"}     icon={AlertTriangle} trend="down" className="border-red-500/20" />
      </div>

      {/* Vulnerabilities Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Bug className="h-4 w-4 text-red-400" />
              Vulnerabilities
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {vulns.length} records
            </Badge>
          </div>
          <CardDescription className="text-xs">Zero-day and N-day vulnerability inventory with exploitation and patch status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE ID</TableHead>
                  <TableHead className="text-[11px] h-8">Disclosure</TableHead>
                  <TableHead className="text-[11px] h-8">Exploitation</TableHead>
                  <TableHead className="text-[11px] h-8">Patch Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">CVSS</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulns.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={5} className="p-0">
                      <EmptyState
                        icon={Bug}
                        title="No vulnerabilities tracked"
                        description="Vulnerabilities ingested from CVE feeds will appear here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  vulns.map((v: any, i: number) => (
                  <TableRow key={v.cve_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{v.cve_id}</TableCell>
                    <TableCell className="py-2"><DisclosureBadge type={v.disclosure_type ?? "n-day"} /></TableCell>
                    <TableCell className="py-2"><ExploitStatusBadge status={v.exploitation_status ?? "none"} /></TableCell>
                    <TableCell className="py-2"><PatchStatusBadge status={v.patch_status ?? "unpatched"} /></TableCell>
                    <TableCell className={cn("py-2 text-right font-mono text-[11px] font-semibold", cvssColor(v.cvss_score ?? 0))}>
                      {(v.cvss_score ?? 0).toFixed(1)}
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Threat Actors Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <Users className="h-4 w-4" />
              Threat Actor Attribution
            </CardTitle>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {actors.length} actors
            </Badge>
          </div>
          <CardDescription className="text-xs">Threat actors attributed to active zero-day exploitation</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Actor Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Linked CVE</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {actors.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={4} className="p-0">
                      <EmptyState
                        icon={Users}
                        title="No threat actors attributed"
                        description="Threat actor attributions from intel sources will appear here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  actors.map((a: any, i: number) => (
                  <TableRow key={a.actor_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-semibold">{a.actor_name}</TableCell>
                    <TableCell className="py-2"><ActorTypeBadge type={a.actor_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2 text-right font-mono text-[11px] text-amber-400">
                      {a.confidence_score ?? 0}%
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.vulnerability_id}</TableCell>
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
