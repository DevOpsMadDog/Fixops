/**
 * API Inventory Dashboard
 *
 * API discovery, authentication coverage, and endpoint tracking.
 *   1. KPIs: Total APIs, Active APIs, Total Endpoints, Unauthenticated Endpoints
 *   2. APIs table (api_name, api_type, version, auth_type, api_status, endpoint_count)
 *
 * Route: /api-inventory
 * API: GET /api/v1/api-inventory
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Globe, RefreshCw, Lock, AlertCircle, Activity, Server } from "lucide-react";

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

// == Mock data ==================================================

const MOCK_APIS = [
  { id: "api-001", api_name: "User Auth Service",       api_type: "REST",    version: "v2.3", auth_type: "OAuth2",   api_status: "active",     endpoint_count: 24 },
  { id: "api-002", api_name: "Payment Gateway",         api_type: "REST",    version: "v1.8", auth_type: "API Key",  api_status: "active",     endpoint_count: 18 },
  { id: "api-003", api_name: "Reporting GraphQL API",   api_type: "GraphQL", version: "v3.0", auth_type: "JWT",      api_status: "active",     endpoint_count: 9 },
  { id: "api-004", api_name: "Legacy Orders API",       api_type: "SOAP",    version: "v1.0", auth_type: "None",     api_status: "deprecated", endpoint_count: 37 },
  { id: "api-005", api_name: "Notification Service",    api_type: "REST",    version: "v2.1", auth_type: "API Key",  api_status: "active",     endpoint_count: 12 },
  { id: "api-006", api_name: "Partner Integration API", api_type: "REST",    version: "v1.5", auth_type: "mTLS",     api_status: "active",     endpoint_count: 29 },
  { id: "api-007", api_name: "Internal Metrics API",    api_type: "gRPC",    version: "v1.2", auth_type: "None",     api_status: "beta",       endpoint_count: 8 },
  { id: "api-008", api_name: "Data Export API",         api_type: "REST",    version: "v2.0", auth_type: "OAuth2",   api_status: "active",     endpoint_count: 15 },
  { id: "api-009", api_name: "Webhook Relay",           api_type: "REST",    version: "v1.0", auth_type: "HMAC",     api_status: "active",     endpoint_count: 6 },
  { id: "api-010", api_name: "Archive API",             api_type: "REST",    version: "v0.9", auth_type: "None",     api_status: "retired",    endpoint_count: 21 },
];

const MOCK_STATS = { total_apis: 143, active_apis: 98, total_endpoints: 2847, unauthenticated_endpoints: 67 };

// == Badge helpers ==============================================

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:     "border-green-500/30 text-green-400 bg-green-500/10",
    deprecated: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    retired:    "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
    beta:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function AuthBadge({ auth }: { auth: string }) {
  const isNone = auth === "None";
  return (
    <Badge className={cn("text-[10px] border font-mono", isNone
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : "border-cyan-500/30 text-cyan-400 bg-cyan-500/10")}>
      {auth}
    </Badge>
  );
}

function exportCsv(apis: any[]) {
  const headers = ["api_name", "api_type", "version", "auth_type", "api_status", "endpoint_count"];
  const rows = apis.map((a) => headers.map((h) => a[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "api_inventory.csv"; a.click();
  URL.revokeObjectURL(url);
}

// == Component ==================================================

export default function APIInventoryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveApis, setLiveApis] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/api-inventory/apis?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-inventory/stats?org_id=${ORG_ID}`),
    ]).then(([apisRes, statsRes]) => {
      if (apisRes.status === "fulfilled") setLiveApis(apisRes.value?.apis ?? apisRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const apis  = liveApis  ?? MOCK_APIS;
  const stats = liveStats ?? MOCK_STATS;

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
        title="API Inventory"
        description="Discover and track all APIs across the environment = authentication coverage, version health, and endpoint exposure"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total APIs"               value={stats.total_apis}               icon={Globe}        trend="flat" className="border-cyan-500/20" />
        <KpiCard title="Active APIs"              value={stats.active_apis}              icon={Activity}     trend="up"   className="border-teal-500/20" />
        <KpiCard title="Total Endpoints"          value={stats.total_endpoints}          icon={Server}       trend="flat" className="border-cyan-500/20" />
        <KpiCard title="Unauth Endpoints"         value={stats.unauthenticated_endpoints} icon={AlertCircle} trend="down" className="border-teal-500/20" />
      </div>

      {/* APIs Table */}
      <Card className="border-cyan-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-cyan-400">
              <Lock className="h-4 w-4" />
              API Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {apis.filter((a: any) => a.auth_type === "None").length} unauthenticated
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(apis)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            All discovered APIs with type, version, authentication method, status, and endpoint count
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">API Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Auth</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Endpoints</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apis.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  apis.map((api: any, i: number) => (
                  <TableRow key={api.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-cyan-300 max-w-[200px] truncate">
                      {api.api_name ?? "="}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-teal-300">
                      {api.api_type ?? "="}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {api.version ?? "="}
                    </TableCell>
                    <TableCell className="py-2">
                      <AuthBadge auth={api.auth_type ?? "None"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={api.api_status ?? "active"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-teal-300 text-right">
                      {api.endpoint_count ?? 0}
                    </TableCell>
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
