// FOLDED into APISecurityHub hero (discovery tab) 2026-05-02 — preserve for git history
/**
 * API Discovery Dashboard
 *
 * Automated discovery and risk assessment of API endpoints.
 *   1. KPI cards: Total Endpoints, Undocumented, High Risk, Authenticated %
 *   2. Discovered API endpoints table
 *
 * API: GET /api/v1/api-discovery/stats + /api/v1/api-discovery/endpoints
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search, RefreshCw, AlertTriangle, Lock, Unlock, Code } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

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
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<Record<string, number>>({});
  const [endpoints, setEndpoints] = useState<Record<string, unknown>[]>([]);

  const fetchData = () => {
    setLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/api-discovery/stats?org_id=default"),
      apiFetch("/api/v1/api-discovery/endpoints?org_id=default"),
    ]).then(([statsRes, endpointsRes]) => {
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value ?? {});
      }
      if (endpointsRes.status === "fulfilled") {
        const v = endpointsRes.value;
        setEndpoints(Array.isArray(v) ? v : Array.isArray(v?.endpoints) ? v.endpoints : []);
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
        title="API Discovery"
        description="Automated discovery and risk assessment of API endpoints across all services"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || loading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || loading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Endpoints"  value={stats.total_endpoints ?? 0}        icon={Code}          trend="up"  />
        <KpiCard title="Undocumented"     value={stats.undocumented_endpoints ?? 0} icon={Search}        trend="up"  className="border-amber-500/20" />
        <KpiCard title="High Risk"        value={stats.high_risk_endpoints ?? 0}    icon={AlertTriangle} trend="up"  className="border-red-500/20" />
        <KpiCard title="Authenticated"    value={`${stats.authenticated_pct ?? 0}%`} icon={Lock}         trend="up"  className="border-green-500/20" />
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
              {endpoints.length} shown · {stats.total_endpoints ?? 0} total
            </Badge>
          </div>
          <CardDescription className="text-xs">
            All discovered endpoints ranked by risk score — undocumented and unauthenticated endpoints flagged
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {endpoints.length === 0 ? (
            <EmptyState
              icon={Search}
              title="No endpoints discovered"
              description="API endpoints will appear here once discovery scans complete."
            />
          ) : (
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
                  {endpoints.map((ep, i) => (
                    <TableRow key={(ep.id as string) ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><MethodBadge method={(ep.method as string) ?? "GET"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[11px]">{(ep.path as string) ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{(ep.service as string) ?? "—"}</TableCell>
                      <TableCell className="py-2"><RiskScoreBadge score={(ep.risk_score as number) ?? 0} /></TableCell>
                      <TableCell className="py-2 text-center">
                        {ep.auth_required
                          ? <Lock className="h-3.5 w-3.5 text-green-400 inline" />
                          : <Unlock className="h-3.5 w-3.5 text-red-400 inline" />}
                      </TableCell>
                      <TableCell className="py-2"><EndpointStatusBadge status={(ep.status as string) ?? "documented"} /></TableCell>
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
