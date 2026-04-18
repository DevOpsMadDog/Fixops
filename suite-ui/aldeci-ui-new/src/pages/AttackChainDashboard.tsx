/**
 * Attack Chain Dashboard
 *
 * Kill chain tracking and lateral movement analysis.
 *   1. KPI cards: Total Chains, Active Chains, Contained Chains, Avg Steps
 *   2. Kill Chain Phase Distribution grid
 *   3. Active Chains table
 *
 * API: GET /api/v1/attack-chains/{stats,chains}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Link2, RefreshCw, Zap, Shield, BarChart3 } from "lucide-react";
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

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

const MOCK_STATS = {
  total_chains: 12,
  active_chains: 4,
  contained_chains: 5,
  avg_steps: 6.3,
};

const KILL_CHAIN_PHASES = [
  { phase: "reconnaissance",       label: "Reconnaissance",         count: 3 },
  { phase: "weaponization",        label: "Weaponization",          count: 2 },
  { phase: "delivery",             label: "Delivery",               count: 4 },
  { phase: "exploitation",         label: "Exploitation",           count: 5 },
  { phase: "installation",         label: "Installation",           count: 3 },
  { phase: "c2",                   label: "C2",                     count: 2 },
  { phase: "actions_on_objectives",label: "Actions on Objectives",  count: 1 },
];

const MOCK_CHAINS = [
  { id: "chain-001", name: "APT29 Lateral Spread",      threat_actor: "APT29",      kill_chain_phase: "exploitation",          status: "active",    confidence: 87, steps: 8,  created_at: "2026-04-14T10:22:00Z" },
  { id: "chain-002", name: "Ransomware Delivery Wave",  threat_actor: "LockBit 3",  kill_chain_phase: "delivery",              status: "contained", confidence: 72, steps: 5,  created_at: "2026-04-13T14:05:00Z" },
  { id: "chain-003", name: "Credential Harvesting Run", threat_actor: "TA505",      kill_chain_phase: "actions_on_objectives", status: "active",    confidence: 91, steps: 11, created_at: "2026-04-15T08:47:00Z" },
  { id: "chain-004", name: "Supply Chain Implant",      threat_actor: "Unknown",    kill_chain_phase: "installation",          status: "eradicated",confidence: 65, steps: 7,  created_at: "2026-04-10T16:30:00Z" },
];

const PHASE_COLORS: Record<string, string> = {
  reconnaissance:       "text-gray-400 bg-gray-500/10 border-gray-500/30",
  weaponization:        "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  delivery:             "text-orange-400 bg-orange-500/10 border-orange-500/30",
  exploitation:         "text-red-400 bg-red-500/10 border-red-500/30",
  installation:         "text-purple-400 bg-purple-500/10 border-purple-500/30",
  c2:                   "text-pink-400 bg-pink-500/10 border-pink-500/30",
  actions_on_objectives:"text-rose-400 bg-rose-500/10 border-rose-500/30",
};

function PhaseBadge({ phase }: { phase: string }) {
  return (
    <Badge className={cn("text-[10px] border font-mono", PHASE_COLORS[phase] ?? "border-border text-muted-foreground")}>
      {phase.replace(/_/g, " ")}
    </Badge>
  );
}

function ChainStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:     "border-red-500/30 text-red-400 bg-red-500/10",
    contained:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    eradicated: "border-green-500/30 text-green-400 bg-green-500/10",
    recovered:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function fmtDate(ts: string): string {
  try { return new Date(ts).toLocaleDateString(); } catch { return ts; }
}

export default function AttackChainDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{ stats: any | null; chains: any[] | null }>({
    stats: null, chains: null,
  });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/attack-chains/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/attack-chains/chains?org_id=${ORG_ID}`),
    ]).then(([statsRes, chainsRes]) => {
      setLiveData({
        stats:  statsRes.status  === "fulfilled" ? statsRes.value  : null,
        chains: chainsRes.status === "fulfilled" ? chainsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats  = liveData.stats  ?? MOCK_STATS;
  const chains = liveData.chains ?? MOCK_CHAINS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Attack Chain Monitor"
        description="Kill chain tracking and lateral movement analysis"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Chains"    value={stats.total_chains}    icon={Link2}    trend="flat" />
        <KpiCard title="Active Chains"   value={stats.active_chains}   icon={Zap}      trend="down" className="border-red-500/20" />
        <KpiCard title="Contained"       value={stats.contained_chains} icon={Shield}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Avg Steps"       value={stats.avg_steps}       icon={BarChart3} trend="flat" className="border-blue-500/20" />
      </div>

      {/* Kill Chain Phase Distribution */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-orange-400" />
            Kill Chain Phase Distribution
          </CardTitle>
          <CardDescription className="text-xs">Active chains by kill chain phase</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
            {KILL_CHAIN_PHASES.map((p) => (
              <div
                key={p.phase}
                className={cn("rounded-lg border p-3 text-center", PHASE_COLORS[p.phase] ?? "border-border")}
              >
                <div className="text-xl font-bold">{p.count}</div>
                <div className="text-[10px] mt-1 leading-tight opacity-80">{p.label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Active Chains Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Zap className="h-4 w-4" />
              Active Attack Chains
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {chains.filter((c: any) => c.status === "active").length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Tracked kill chains with threat actor attribution</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Chain Name</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Actor</TableHead>
                  <TableHead className="text-[11px] h-8">Phase</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Steps</TableHead>
                  <TableHead className="text-[11px] h-8">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {chains.map((c: any, i: number) => (
                  <TableRow key={c.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[12px] font-medium">{c.name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{c.threat_actor}</TableCell>
                    <TableCell className="py-2"><PhaseBadge phase={c.kill_chain_phase ?? "reconnaissance"} /></TableCell>
                    <TableCell className="py-2"><ChainStatusBadge status={c.status ?? "active"} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] font-mono">{c.confidence}%</TableCell>
                    <TableCell className="py-2 text-right text-[11px] font-mono">{c.steps}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtDate(c.created_at)}</TableCell>
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
