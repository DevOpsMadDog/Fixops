// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
// FOLDED into DeceptionHub hero (decoys tab) 2026-05-02 — preserve for git history
/**
 * Threat Deception Dashboard
 *
 * Decoy management and attacker interaction tracking for deception-based defense.
 *   1. KPIs: Active Decoys, Total Interactions, Unique Attackers, Active Campaigns
 *   2. Decoys table (name, decoy_type, ip_address, port, interaction_count, active)
 *
 * Route: /threat-deception
 * API: GET /api/v1/threat-deception
 */

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Shield, RefreshCw, Users, Target, Activity } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Badge helpers ──────────────────────────────────────────────

function ActiveBadge({ active }: { active: boolean }) {
  return (
    <Badge className={cn("text-[10px] border capitalize", active
      ? "border-green-500/30 text-green-400 bg-green-500/10"
      : "border-zinc-500/30 text-zinc-400 bg-zinc-500/10"
    )}>
      {active ? "active" : "inactive"}
    </Badge>
  );
}

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    database: "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    ssh:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
    web:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    ftp:      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    file:     "border-violet-500/30 text-violet-400 bg-violet-500/10",
    rdp:      "border-pink-500/30 text-pink-400 bg-pink-500/10",
    api:      "border-fuchsia-500/30 text-fuchsia-400 bg-fuchsia-500/10",
    ldap:     "border-rose-500/30 text-rose-400 bg-rose-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>
      {type}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

interface Decoy {
  id: string;
  name: string;
  decoy_type: string;
  ip_address: string;
  port: number;
  interaction_count: number;
  active: boolean;
}

interface DeceptionStats {
  active_decoys: number;
  total_interactions: number;
  unique_attackers: number;
  active_campaigns: number;
}

export default function ThreatDeceptionDashboard() {
  const { data: decoysData, isLoading: decoysLoading, refetch: refetchDecoys } = useQuery<{ decoys?: Decoy[] } | Decoy[]>({
    queryKey: ["threat-deception-decoys"],
    queryFn: () => apiFetch("/api/v1/threat-deception/decoys?org_id=default"),
  });

  const { data: statsData, isLoading: statsLoading, refetch: refetchStats } = useQuery<DeceptionStats>({
    queryKey: ["threat-deception-stats"],
    queryFn: () => apiFetch("/api/v1/threat-deception/stats?org_id=default"),
  });

  const loading = decoysLoading || statsLoading;

  const handleRefresh = () => {
    refetchDecoys();
    refetchStats();
  };

  const decoys: Decoy[] = Array.isArray(decoysData)
    ? decoysData
    : (decoysData as { decoys?: Decoy[] })?.decoys ?? [];

  const stats: DeceptionStats = statsData ?? { active_decoys: 0, total_interactions: 0, unique_attackers: 0, active_campaigns: 0 };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Threat Deception"
        description="Decoy asset management, honeypot interactions, and attacker behavior analytics for deception-based defense"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={loading}>
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Decoys"       value={stats.active_decoys}       icon={Shield}        trend="flat" className="border-indigo-500/20" />
        <KpiCard title="Total Interactions"  value={stats.total_interactions}  icon={Activity}      trend="up"   className="border-purple-500/20" />
        <KpiCard title="Unique Attackers"    value={stats.unique_attackers}    icon={Users}         trend="up"   className="border-red-500/20" />
        <KpiCard title="Active Campaigns"    value={stats.active_campaigns}    icon={Target}        trend="flat" className="border-fuchsia-500/20" />
      </div>

      {/* Decoys Table */}
      <Card className="border-indigo-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-indigo-400">
              <Shield className="h-4 w-4" />
              Decoy Assets
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              {decoys.filter((d: any) => d.active).length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Honeypots, canary tokens, and deception assets with interaction telemetry
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {decoys.length === 0 ? (
            <EmptyState
              icon={Shield}
              title="No decoy assets"
              description="No honeypots or canary tokens have been deployed yet. Configure deception assets to begin tracking attacker interactions."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Name</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">IP Address</TableHead>
                    <TableHead className="text-[11px] h-8">Port</TableHead>
                    <TableHead className="text-[11px] h-8">Interactions</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {decoys.map((dec: Decoy, i: number) => (
                    <TableRow key={dec.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-semibold text-[11px] text-indigo-300">
                        {dec.name ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <TypeBadge type={dec.decoy_type ?? "unknown"} />
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                        {dec.ip_address ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-purple-300">
                        {dec.port ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">
                        {dec.interaction_count ?? 0}
                      </TableCell>
                      <TableCell className="py-2 text-right">
                        <ActiveBadge active={dec.active ?? false} />
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
