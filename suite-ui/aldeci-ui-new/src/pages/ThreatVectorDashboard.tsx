/**
 * Threat Vector Dashboard
 *
 * Active threat vector monitoring with risk scoring and mitigation tracking.
 *   1. KPIs: Total Vectors, Active, Critical Vectors, Open Mitigations
 *   2. Vectors table (name, vector_type, severity, risk_score, indicator_count, mitigation_count)
 *
 * Route: /threat-vectors
 * API: GET /api/v1/threat-vectors/vectors + /api/v1/threat-vectors/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Crosshair, RefreshCw, Flame, ShieldAlert, Activity, BarChart2 } from "lucide-react";

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

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function riskColor(score: number) {
  if (score >= 90) return "text-red-400";
  if (score >= 70) return "text-orange-400";
  if (score >= 50) return "text-yellow-400";
  return "text-green-400";
}

function exportCsv(vectors: Record<string, unknown>[]) {
  const headers = ["name", "vector_type", "severity", "risk_score", "indicator_count", "mitigation_count"];
  const rows = vectors.map((v) => headers.map((h) => v[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "threat_vectors.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatVectorDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [vectors, setVectors] = useState<Record<string, unknown>[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});

  const fetchData = () => {
    setLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/threat-vectors/vectors?org_id=default"),
      apiFetch("/api/v1/threat-vectors/stats?org_id=default"),
    ]).then(([vecRes, statsRes]) => {
      if (vecRes.status === "fulfilled") {
        const v = vecRes.value;
        setVectors(Array.isArray(v) ? v : Array.isArray(v?.vectors) ? v.vectors : []);
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
        title="Threat Vectors"
        description="Active threat vector monitoring — risk scoring, indicator tracking, and mitigation status across all attack surfaces"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Vectors"    value={stats.total_vectors ?? 0}    icon={Crosshair}   trend="flat" className="border-red-500/20" />
        <KpiCard title="Active"           value={stats.active_vectors ?? 0}   icon={Activity}    trend="down" className="border-orange-500/20" />
        <KpiCard title="Critical Vectors" value={stats.critical_vectors ?? 0} icon={Flame}       trend="down" className="border-red-500/20" />
        <KpiCard title="Open Mitigations" value={stats.open_mitigations ?? 0} icon={ShieldAlert} trend="up"   className="border-orange-500/20" />
      </div>

      {/* Vectors Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <BarChart2 className="h-4 w-4" />
              Threat Vector Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {vectors.filter((v) => v.severity === "critical").length} critical
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(vectors)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            All active threat vectors with type classification, risk score, IOC count, and mitigation coverage
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {vectors.length === 0 ? (
            <EmptyState
              icon={Crosshair}
              title="No threat vectors found"
              description="Threat vector data will appear here once the API returns results."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Vector Name</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                    <TableHead className="text-[11px] h-8">Indicators</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Mitigations</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {vectors.map((vec, i) => (
                    <TableRow key={(vec.id as string) ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-semibold text-[11px] text-red-300 max-w-[200px] truncate">
                        {(vec.name as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">
                        {(vec.vector_type as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <SeverityBadge severity={(vec.severity as string) ?? "low"} />
                      </TableCell>
                      <TableCell className={cn("py-2 font-mono text-[11px] font-bold", riskColor((vec.risk_score as number) ?? 0))}>
                        {(vec.risk_score as number) ?? 0}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-orange-300">
                        {(vec.indicator_count as number) ?? 0}
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                        {(vec.mitigation_count as number) ?? 0}
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
