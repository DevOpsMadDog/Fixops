/**
 * Threat Vector Dashboard
 *
 * Active threat vector monitoring with risk scoring and mitigation tracking.
 *   1. KPIs: Total Vectors, Active, Critical Vectors, Open Mitigations
 *   2. Vectors table (name, vector_type, severity, risk_score, indicator_count, mitigation_count)
 *
 * Route: /threat-vectors
 * API: GET /api/v1/threat-vectors
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

const MOCK_VECTORS = [
  { id: "vec-001", name: "Phishing Campaign",          vector_type: "Social Engineering", severity: "high",     risk_score: 82, indicator_count: 47,  mitigation_count: 3 },
  { id: "vec-002", name: "Log4Shell Exploitation",     vector_type: "Vulnerability",      severity: "critical", risk_score: 97, indicator_count: 134, mitigation_count: 1 },
  { id: "vec-003", name: "Credential Stuffing",        vector_type: "Brute Force",        severity: "high",     risk_score: 78, indicator_count: 892, mitigation_count: 5 },
  { id: "vec-004", name: "Supply Chain Compromise",    vector_type: "Supply Chain",       severity: "critical", risk_score: 94, indicator_count: 23,  mitigation_count: 2 },
  { id: "vec-005", name: "Ransomware Delivery",        vector_type: "Malware",            severity: "critical", risk_score: 99, indicator_count: 61,  mitigation_count: 0 },
  { id: "vec-006", name: "API Key Leakage",            vector_type: "Data Exposure",      severity: "medium",   risk_score: 63, indicator_count: 18,  mitigation_count: 7 },
  { id: "vec-007", name: "DNS Tunneling",              vector_type: "Exfiltration",       severity: "medium",   risk_score: 57, indicator_count: 9,   mitigation_count: 4 },
  { id: "vec-008", name: "Insider Data Theft",         vector_type: "Insider Threat",     severity: "high",     risk_score: 76, indicator_count: 14,  mitigation_count: 2 },
  { id: "vec-009", name: "Business Email Compromise",  vector_type: "Social Engineering", severity: "high",     risk_score: 81, indicator_count: 33,  mitigation_count: 6 },
  { id: "vec-010", name: "Port Scan Activity",         vector_type: "Reconnaissance",     severity: "low",      risk_score: 34, indicator_count: 441, mitigation_count: 1 },
];

const MOCK_STATS = { total_vectors: 87, active_vectors: 62, critical_vectors: 14, open_mitigations: 39 };

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

function exportCsv(vectors: any[]) {
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
  const [liveVectors, setLiveVectors] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/threat-vectors/vectors?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-vectors/stats?org_id=${ORG_ID}`),
    ]).then(([vecRes, statsRes]) => {
      if (vecRes.status === "fulfilled") setLiveVectors(vecRes.value?.vectors ?? vecRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const vectors = liveVectors ?? MOCK_VECTORS;
  const stats   = liveStats   ?? MOCK_STATS;

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
        <KpiCard title="Total Vectors"      value={stats.total_vectors}      icon={Crosshair}  trend="flat" className="border-red-500/20" />
        <KpiCard title="Active"             value={stats.active_vectors}     icon={Activity}   trend="down" className="border-orange-500/20" />
        <KpiCard title="Critical Vectors"   value={stats.critical_vectors}   icon={Flame}      trend="down" className="border-red-500/20" />
        <KpiCard title="Open Mitigations"   value={stats.open_mitigations}   icon={ShieldAlert} trend="up"  className="border-orange-500/20" />
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
                {vectors.filter((v: any) => v.severity === "critical").length} critical
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
                {vectors.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  vectors.map((vec: any, i: number) => (
                  <TableRow key={vec.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-red-300 max-w-[200px] truncate">
                      {vec.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {vec.vector_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={vec.severity ?? "low"} />
                    </TableCell>
                    <TableCell className={cn("py-2 font-mono text-[11px] font-bold", riskColor(vec.risk_score ?? 0))}>
                      {vec.risk_score ?? 0}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-orange-300">
                      {vec.indicator_count ?? 0}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground text-right">
                      {vec.mitigation_count ?? 0}
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
