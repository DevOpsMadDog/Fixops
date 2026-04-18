/**
 * Digital Twin Dashboard
 *
 * Digital twin security simulation tracking with risk scoring.
 *   1. KPIs: Digital Twins, Total Simulations, Avg Risk Score, Critical Findings
 *   2. Simulations table (twin_id truncated, simulation_type, status, findings_count, risk_score, completed_at)
 *
 * Route: /digital-twin
 * API: GET /api/v1/digital-twin
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cpu, RefreshCw, Activity, AlertTriangle, FlaskConical, BarChart2 } from "lucide-react";

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

const MOCK_SIMULATIONS = [
  { id: "sim-001", twin_id: "twin-prod-network-a1b2c3d4e5f6",     simulation_type: "Lateral Movement",    status: "completed", findings_count: 14, risk_score: 87.3, completed_at: "2026-04-16T08:00:00Z" },
  { id: "sim-002", twin_id: "twin-cloud-infra-9f8e7d6c5b4a",      simulation_type: "Data Exfiltration",   status: "completed", findings_count: 7,  risk_score: 72.1, completed_at: "2026-04-15T22:30:00Z" },
  { id: "sim-003", twin_id: "twin-k8s-cluster-3c4d5e6f7a8b",      simulation_type: "Privilege Escalation",status: "running",   findings_count: 3,  risk_score: 61.4, completed_at: null                   },
  { id: "sim-004", twin_id: "twin-prod-network-a1b2c3d4e5f6",     simulation_type: "Supply Chain Attack", status: "completed", findings_count: 22, risk_score: 93.8, completed_at: "2026-04-14T18:15:00Z" },
  { id: "sim-005", twin_id: "twin-ot-scada-7a8b9c0d1e2f",         simulation_type: "OT Protocol Abuse",   status: "completed", findings_count: 18, risk_score: 95.2, completed_at: "2026-04-13T12:00:00Z" },
  { id: "sim-006", twin_id: "twin-saas-tenant-2b3c4d5e6f7a",      simulation_type: "Credential Stuffing", status: "queued",    findings_count: 0,  risk_score: 0.0,  completed_at: null                   },
  { id: "sim-007", twin_id: "twin-cloud-infra-9f8e7d6c5b4a",      simulation_type: "API Abuse",           status: "completed", findings_count: 9,  risk_score: 68.5, completed_at: "2026-04-12T09:45:00Z" },
  { id: "sim-008", twin_id: "twin-endpoint-fleet-4d5e6f7a8b9c",   simulation_type: "Ransomware Spread",   status: "completed", findings_count: 31, risk_score: 98.1, completed_at: "2026-04-11T20:00:00Z" },
  { id: "sim-009", twin_id: "twin-k8s-cluster-3c4d5e6f7a8b",      simulation_type: "Container Escape",    status: "failed",    findings_count: 0,  risk_score: 0.0,  completed_at: "2026-04-10T14:30:00Z" },
  { id: "sim-010", twin_id: "twin-saas-tenant-2b3c4d5e6f7a",      simulation_type: "Insider Threat",      status: "completed", findings_count: 11, risk_score: 79.6, completed_at: "2026-04-09T11:00:00Z" },
];

const MOCK_STATS = {
  digital_twins: 12,
  total_simulations: 847,
  avg_risk_score: 76.8,
  critical_findings: 89,
};

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    running:   "border-teal-500/30 text-teal-400 bg-teal-500/10",
    queued:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  if (score === 0) return <span className="font-mono text-[11px] text-muted-foreground">—</span>;
  const color = score >= 90 ? "text-red-400" : score >= 70 ? "text-orange-400" : score >= 50 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono text-[11px] font-semibold", color)}>{score.toFixed(1)}</span>;
}

function truncateId(id: string) {
  return id.length > 22 ? `${id.slice(0, 20)}…` : id;
}

function formatTs(ts: string | null) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ── Component ──────────────────────────────────────────────────

export default function DigitalTwinDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveSims, setLiveSims]     = useState<any[] | null>(null);
  const [liveStats, setLiveStats]   = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/digital-twin/simulations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/digital-twin/stats?org_id=${ORG_ID}`),
    ]).then(([simsRes, statsRes]) => {
      if (simsRes.status === "fulfilled")  setLiveSims(simsRes.value?.simulations ?? simsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); 
    setLoading(false);};

  const simulations = liveSims    ?? MOCK_SIMULATIONS;
  const stats       = liveStats   ?? MOCK_STATS;

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
        title="Digital Twin"
        description="Security simulation on digital twins — attack path modeling, risk scoring, and finding discovery across virtual replicas"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Digital Twins"      value={stats.digital_twins}                    icon={Cpu}          trend="up"   className="border-cyan-500/20" />
        <KpiCard title="Total Simulations"  value={stats.total_simulations}                icon={FlaskConical} trend="up"   className="border-teal-500/20" />
        <KpiCard title="Avg Risk Score"     value={`${stats.avg_risk_score}/100`}          icon={Activity}     trend="down" className="border-cyan-500/20" />
        <KpiCard title="Critical Findings"  value={stats.critical_findings}                icon={AlertTriangle} trend="down" className="border-teal-500/20" />
      </div>

      {/* Simulations Table */}
      <Card className="border-cyan-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-cyan-400">
              <BarChart2 className="h-4 w-4" />
              Simulation Registry
            </CardTitle>
            <Badge className="text-[10px] border border-teal-500/30 text-teal-400 bg-teal-500/10">
              {simulations.filter((s: any) => s.status === "running").length} running
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Security simulations on digital twins with attack type, findings count, risk score, and completion status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Twin ID</TableHead>
                  <TableHead className="text-[11px] h-8">Simulation Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Findings</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Completed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {simulations.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  simulations.map((sim: any, i: number) => (
                  <TableRow key={sim.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-cyan-300">
                      {truncateId(sim.twin_id ?? "—")}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-teal-300 font-semibold">
                      {sim.simulation_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={sim.status ?? "queued"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {sim.findings_count ?? 0}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskScore score={sim.risk_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {formatTs(sim.completed_at)}
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
