// FOLDED into Remediate hero 2026-04-27 — preserve for git history
// Tab path: /remediate?tab=risk-register
/**
 * Risk Register Engine Dashboard
 *
 * Enterprise risk register with likelihood/impact scoring and lifecycle tracking.
 *   1. KPIs: Total Risks, Critical Risks, High Risks, Open Risks
 *   2. Risks table (name, risk_category, likelihood, impact, risk_score, risk_level, status)
 *
 * Route: /risk-register-engine
 * API: GET /api/v1/risk-register-engine/risks + /api/v1/risk-register-engine/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ClipboardList, RefreshCw, AlertTriangle, TrendingUp, CheckCircle } from "lucide-react";

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

function RiskLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:       "border-red-500/30 text-red-400 bg-red-500/10",
    mitigating: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    accepted:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    closed:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const label: Record<string, string> = {
    open:       "Open",
    mitigating: "Mitigating",
    accepted:   "Accepted",
    closed:     "Closed",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function RiskRegisterDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [risks, setRisks] = useState<Record<string, unknown>[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});

  const fetchData = () => {
    setLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/risk-register-engine/risks?org_id=default"),
      apiFetch("/api/v1/risk-register-engine/stats?org_id=default"),
    ]).then(([risksRes, statsRes]) => {
      if (risksRes.status === "fulfilled") {
        const v = risksRes.value;
        setRisks(Array.isArray(v) ? v : Array.isArray(v?.risks) ? v.risks : []);
      }
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value ?? {});
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
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
        title="Risk Register"
        description="Enterprise risk register with likelihood/impact scoring, risk lifecycle management, and treatment tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Risks"    value={stats.total_risks ?? 0}    icon={ClipboardList} trend="flat" className="border-orange-500/20" />
        <KpiCard title="Critical Risks" value={stats.critical_risks ?? 0} icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="High Risks"     value={stats.high_risks ?? 0}     icon={TrendingUp}    trend="down" className="border-amber-500/20" />
        <KpiCard title="Open Risks"     value={stats.open_risks ?? 0}     icon={CheckCircle}   trend="down" className="border-yellow-500/20" />
      </div>

      {/* Risks Table */}
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <ClipboardList className="h-4 w-4" />
              Risk Register
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {risks.filter((r) => r.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Enterprise risks with likelihood/impact scoring, risk level classification, and treatment status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {risks.length === 0 ? (
            <EmptyState
              icon={ClipboardList}
              title="No risks registered"
              description="Risk register entries will appear here once the API returns data."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Risk Name</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Likelihood</TableHead>
                    <TableHead className="text-[11px] h-8">Impact</TableHead>
                    <TableHead className="text-[11px] h-8">Score</TableHead>
                    <TableHead className="text-[11px] h-8">Level</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {risks.map((risk, i) => (
                    <TableRow key={(risk.id as string) ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-semibold text-[11px] text-orange-300">
                        {(risk.name as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">
                        {(risk.risk_category as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                        {(risk.likelihood as number) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                        {(risk.impact as number) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] font-semibold text-amber-300">
                        {(risk.risk_score as number) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <RiskLevelBadge level={(risk.risk_level as string) ?? "low"} />
                      </TableCell>
                      <TableCell className="py-2 text-right">
                        <StatusBadge status={(risk.status as string) ?? "open"} />
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
