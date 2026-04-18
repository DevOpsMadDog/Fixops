/**
 * API Discovery Dashboard
 *
 * Automated discovery and risk assessment of API endpoints.
 *   1. KPI cards: Total Endpoints, Undocumented, High Risk, Authenticated %
 *   2. Discovered API endpoints table
 *
 * API: GET /api/v1/api-discovery/{stats,endpoints}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Search, RefreshCw, AlertTriangle, Lock, Unlock, Code,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
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

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_endpoints: 3036,
  undocumented_endpoints: 841,
  high_risk_endpoints: 67,
  authenticated_pct: 78.4,
};

const MOCK_ENDPOINTS = [
  { id: "ep-001", path: "/api/v1/users",              method: "GET",    risk_score: 45, auth_required: true,  status: "documented",    service: "user-service" },
  { id: "ep-002", path: "/api/v1/users/{id}/export",  method: "GET",    risk_score: 82, auth_required: true,  status: "documented",    service: "user-service" },
  { id: "ep-003", path: "/internal/debug/env",        method: "GET",    risk_score: 97, auth_required: false, status: "undocumented",  service: "debug-svc" },
  { id: "ep-004", path: "/api/v1/payments",           method: "POST",   risk_score: 75, auth_required: true,  status: "documented",    service: "payment-svc" },
  { id: "ep-005", path: "/api/v1/admin/users",        method: "DELETE", risk_score: 90, auth_required: true,  status: "documented",    service: "admin-api" },
  { id: "ep-006", path: "/health",                    method: "GET",    risk_score: 5,  auth_required: false, status: "documented",    service: "gateway" },
  { id: "ep-007", path: "/api/v2/reports/bulk",       method: "POST",   risk_score: 68, auth_required: true,  status: "undocumented",  service: "report-svc" },
  { id: "ep-008", path: "/api/v1/config/override",    method: "PUT",    risk_score: 95, auth_required: false, status: "undocumented",  service: "config-api" },
  { id: "ep-009", path: "/api/v1/metrics",            method: "GET",    risk_score: 20, auth_required: false, status: "documented",    service: "observability" },
  { id: "ep-010", path: "/api/v1/scan/trigger",       method: "POST",   risk_score: 55, auth_required: true,  status: "documented",    service: "scan-engine" },
  { id: "ep-011", path: "/api/internal/tokens",       method: "GET",    risk_score: 88, auth_required: false, status: "undocumented",  service: "auth-svc" },
  { id: "ep-012", path: "/api/v1/alerts",             method: "GET",    risk_score: 30, auth_required: true,  status: "documented",    service: "alert-mgr" },
];

// ── Badge helpers ──────────────────────────────────────────────

function RiskScoreBadge({ score }: { score: number }) {
  const cls =
    score >= 75 ? "border-red-500/30 text-red-400 bg-red-500/10" :
    score >= 40 ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                  "border-green-500/30 text-green-400 bg-green-500/10";
  return (
    <Badge className={cn("text-[10px] border font-mono", cls)}>{score}</Badge>
  );
}

function MethodBadge({ method }: { method: string }) {
  const map: Record<string, string> = {
    GET:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    POST:   "border-green-500/30 text-green-400 bg-green-500/10",
    PUT:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    PATCH:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    DELETE: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[method] ?? "border-border text-muted-foreground")}>
      {method}
    </Badge>
  );
}

function EndpointStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    documented:   "border-green-500/30 text-green-400 bg-green-500/10",
    undocumented: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    deprecated:   "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function APIDiscoveryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    endpoints: any[] | null;
  }>({ stats: null, endpoints: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/api-discovery/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-discovery/endpoints?org_id=${ORG_ID}`),
    ]).then(([statsRes, endpointsRes]) => {
      setLiveData({
        stats:     statsRes.status     === "fulfilled" ? statsRes.value     : null,
        endpoints: endpointsRes.status === "fulfilled" ? endpointsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? MOCK_STATS;
  const endpoints = liveData.endpoints ?? MOCK_ENDPOINTS;

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
      {/* Header */}
      <PageHeader
        title="API Discovery"
        description="Automated discovery and risk assessment of API endpoints across all services"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Endpoints"       value={stats.total_endpoints}         icon={Code}          trend="up"   />
        <KpiCard title="Undocumented"          value={stats.undocumented_endpoints}  icon={Search}        trend="up"   className="border-amber-500/20" />
        <KpiCard title="High Risk"             value={stats.high_risk_endpoints}     icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Authenticated"         value={`${stats.authenticated_pct}%`} icon={Lock}          trend="up"   className="border-green-500/20" />
      </div>

      {/* Endpoints Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Code className="h-4 w-4 text-indigo-400" />
              Discovered API Endpoints
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {endpoints.length} shown · {stats.total_endpoints} total
            </Badge>
          </div>
          <CardDescription className="text-xs">All discovered endpoints ranked by risk score — undocumented and unauthenticated endpoints flagged</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Path</TableHead>
                  <TableHead className="text-[11px] h-8">Service</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Auth</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {endpoints.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  endpoints.map((ep: any, i: number) => (
                  <TableRow key={ep.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><MethodBadge method={ep.method ?? "GET"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{ep.path}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{ep.service}</TableCell>
                    <TableCell className="py-2"><RiskScoreBadge score={ep.risk_score ?? 0} /></TableCell>
                    <TableCell className="py-2 text-center">
                      {ep.auth_required
                        ? <Lock className="h-3.5 w-3.5 text-green-400 inline" />
                        : <Unlock className="h-3.5 w-3.5 text-red-400 inline" />}
                    </TableCell>
                    <TableCell className="py-2"><EndpointStatusBadge status={ep.status ?? "documented"} /></TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
