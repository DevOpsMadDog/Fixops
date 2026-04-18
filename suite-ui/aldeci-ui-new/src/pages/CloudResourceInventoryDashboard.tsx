/**
 * Cloud Resource Inventory Dashboard
 *
 * Multi-cloud resource inventory with compliance status and security scoring.
 *   1. KPIs: Total Resources, Running, Non-Compliant, Avg Security Score
 *   2. Resources table (resource_name, provider, resource_type, compliance_status, resource_state, security_score)
 *
 * Route: /cloud-inventory
 * API: GET /api/v1/cloud-inventory
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, ShieldCheck, AlertCircle, Server, BarChart2 } from "lucide-react";

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

const MOCK_RESOURCES = [
  { id: "res-001", resource_name: "prod-api-cluster",       provider: "aws",   resource_type: "eks",        compliance_status: "compliant",     resource_state: "running",  security_score: 88 },
  { id: "res-002", resource_name: "analytics-bucket",       provider: "aws",   resource_type: "s3",         compliance_status: "non_compliant",  resource_state: "running",  security_score: 41 },
  { id: "res-003", resource_name: "db-replica-west",        provider: "gcp",   resource_type: "cloudsql",   compliance_status: "compliant",     resource_state: "running",  security_score: 92 },
  { id: "res-004", resource_name: "legacy-vm-01",           provider: "azure", resource_type: "vm",         compliance_status: "non_compliant",  resource_state: "stopped",  security_score: 27 },
  { id: "res-005", resource_name: "cdn-distribution",       provider: "aws",   resource_type: "cloudfront", compliance_status: "compliant",     resource_state: "running",  security_score: 79 },
  { id: "res-006", resource_name: "k8s-dev-namespace",      provider: "gcp",   resource_type: "gke",        compliance_status: "unknown",       resource_state: "running",  security_score: 65 },
  { id: "res-007", resource_name: "sql-prod-primary",       provider: "azure", resource_type: "sql",        compliance_status: "compliant",     resource_state: "running",  security_score: 95 },
  { id: "res-008", resource_name: "lambda-etl-pipeline",    provider: "aws",   resource_type: "lambda",     compliance_status: "non_compliant",  resource_state: "running",  security_score: 53 },
  { id: "res-009", resource_name: "vpn-gateway-eu",         provider: "aws",   resource_type: "vpn",        compliance_status: "compliant",     resource_state: "running",  security_score: 84 },
  { id: "res-010", resource_name: "storage-account-logs",   provider: "azure", resource_type: "storage",    compliance_status: "unknown",       resource_state: "running",  security_score: 61 },
];

const MOCK_STATS = { total_resources: 1847, running: 1612, non_compliant: 214, avg_security_score: 72.4 };

// ── Badge helpers ──────────────────────────────────────────────

function ComplianceBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    compliant:     "border-green-500/30 text-green-400 bg-green-500/10",
    non_compliant: "border-red-500/30 text-red-400 bg-red-500/10",
    unknown:       "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function ProviderBadge({ provider }: { provider: string }) {
  const map: Record<string, string> = {
    aws:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    gcp:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    azure: "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border uppercase", map[provider] ?? "border-border")}>
      {provider}
    </Badge>
  );
}

function ScoreCell({ score }: { score: number }) {
  const color = score >= 80 ? "text-green-400" : score >= 60 ? "text-yellow-400" : "text-red-400";
  return <span className={cn("font-mono text-[11px]", color)}>{score}</span>;
}

function exportCsv(rows: any[]) {
  const headers = ["resource_name", "provider", "resource_type", "compliance_status", "resource_state", "security_score"];
  const lines = [headers.join(","), ...rows.map(r => headers.map(h => `"${r[h] ?? ""}"`).join(","))];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "cloud_resources.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function CloudResourceInventoryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveResources, setLiveResources] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/cloud-inventory/resources?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-inventory/stats?org_id=${ORG_ID}`),
    ]).then(([resRes, statsRes]) => {
      if (resRes.status === "fulfilled") setLiveResources(resRes.value?.resources ?? resRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const resources = liveResources ?? MOCK_RESOURCES;
  const stats     = liveStats     ?? MOCK_STATS;

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
        title="Cloud Resource Inventory"
        description="Multi-cloud asset inventory — resource compliance posture, state, and security scoring across AWS, GCP, Azure"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Resources"    value={stats.total_resources}                          icon={Cloud}       trend="flat" className="border-indigo-500/20" />
        <KpiCard title="Running"            value={stats.running}                                  icon={Server}      trend="up"   className="border-blue-500/20" />
        <KpiCard title="Non-Compliant"      value={stats.non_compliant}                            icon={AlertCircle} trend="down" className="border-indigo-500/20" />
        <KpiCard title="Avg Security Score" value={`${stats.avg_security_score}`}                  icon={ShieldCheck} trend="up"   className="border-blue-500/20" />
      </div>

      {/* Resources Table */}
      <Card className="border-indigo-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-indigo-400">
              <BarChart2 className="h-4 w-4" />
              Resource Inventory
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {resources.filter((r: any) => r.compliance_status === "non_compliant").length} non-compliant
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(resources)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            Cloud resources with provider, type, compliance status, state, and security score
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Resource Name</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Compliance</TableHead>
                  <TableHead className="text-[11px] h-8">State</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {resources.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  resources.map((res: any, i: number) => (
                  <TableRow key={res.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-indigo-300 max-w-[180px] truncate">
                      {res.resource_name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ProviderBadge provider={res.provider ?? "aws"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-blue-300">
                      {res.resource_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ComplianceBadge status={res.compliance_status ?? "unknown"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {res.resource_state ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <ScoreCell score={res.security_score ?? 0} />
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
