/**
 * API Abuse Dashboard
 *
 * API endpoint abuse detection and incident tracking.
 *   1. KPI cards: Total Endpoints, Monitored Endpoints, Total Incidents, Critical Incidents
 *   2. Endpoints table
 *   3. Incidents table
 *
 * API: GET /api/v1/api-abuse/{stats,endpoints,incidents}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Globe, RefreshCw, AlertTriangle, ShieldAlert, Eye } from "lucide-react";
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
  total_endpoints: 342,
  monitored_endpoints: 298,
  total_incidents: 47,
  critical_incidents: 8,
};

const MOCK_ENDPOINTS = [
  { path: "/api/v1/auth/token",       method: "POST", service_name: "auth-service",    abuse_score: 82, status: "high_risk"  },
  { path: "/api/v1/users/search",     method: "GET",  service_name: "user-service",    abuse_score: 45, status: "monitored"  },
  { path: "/api/v1/payments/charge",  method: "POST", service_name: "payment-service", abuse_score: 91, status: "blocked"    },
  { path: "/api/v1/reports/export",   method: "GET",  service_name: "report-service",  abuse_score: 23, status: "normal"     },
  { path: "/api/v1/admin/users",      method: "GET",  service_name: "admin-service",   abuse_score: 67, status: "high_risk"  },
  { path: "/api/v1/webhooks/ingest",  method: "POST", service_name: "webhook-service", abuse_score: 12, status: "normal"     },
];

const MOCK_INCIDENTS = [
  { abuse_type: "Credential stuffing",    severity: "critical", source_ip: "185.220.101.45", request_count: 15420, blocked: true,  status: "resolved" },
  { abuse_type: "Scraping",              severity: "high",     source_ip: "91.108.4.100",   request_count: 8300,  blocked: true,  status: "open"     },
  { abuse_type: "Rate limit bypass",     severity: "high",     source_ip: "192.168.10.5",   request_count: 3100,  blocked: false, status: "open"     },
  { abuse_type: "BOLA exploitation",     severity: "critical", source_ip: "104.244.72.12",  request_count: 420,   blocked: true,  status: "open"     },
  { abuse_type: "Enumeration attack",    severity: "medium",   source_ip: "45.33.32.156",   request_count: 1800,  blocked: false, status: "resolved" },
  { abuse_type: "Token replay",          severity: "high",     source_ip: "198.54.117.10",  request_count: 290,   blocked: true,  status: "open"     },
];

// ── Badge helpers ──────────────────────────────────────────────

function EndpointStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    normal:    "border-green-500/30 text-green-400 bg-green-500/10",
    monitored: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    high_risk: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    blocked:   "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function MethodBadge({ method }: { method: string }) {
  const map: Record<string, string> = {
    GET:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    POST:   "border-green-500/30 text-green-400 bg-green-500/10",
    PUT:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    DELETE: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[method] ?? "border-border text-muted-foreground")}>
      {method}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function IncidentStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:     "border-red-500/30 text-red-400 bg-red-500/10",
    resolved: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function APIAbuseDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    endpoints: any[] | null;
    incidents: any[] | null;
  }>({ stats: null, endpoints: null, incidents: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/api-abuse/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-abuse/endpoints?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-abuse/incidents?org_id=${ORG_ID}`),
    ]).then(([statsRes, endpointsRes, incidentsRes]) => {
      setLiveData({
        stats:     statsRes.status     === "fulfilled" ? statsRes.value     : null,
        endpoints: endpointsRes.status === "fulfilled" ? endpointsRes.value : null,
        incidents: incidentsRes.status === "fulfilled" ? incidentsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? MOCK_STATS;
  const endpoints = liveData.endpoints ?? MOCK_ENDPOINTS;
  const incidents = liveData.incidents ?? MOCK_INCIDENTS;

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
        title="API Abuse Detection"
        description="API endpoint abuse monitoring, rate limiting, and incident response"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Endpoints"     value={stats.total_endpoints
    setLoading(false);}     icon={Globe}         trend="flat" />
        <KpiCard title="Monitored"           value={stats.monitored_endpoints} icon={Eye}           trend="up"   className="border-blue-500/20" />
        <KpiCard title="Total Incidents"     value={stats.total_incidents}     icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Critical Incidents"  value={stats.critical_incidents}  icon={ShieldAlert}   trend="down" className="border-red-500/20" />
      </div>

      {/* Endpoints Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              API Endpoints
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {endpoints.length} endpoints
            </Badge>
          </div>
          <CardDescription className="text-xs">Monitored API endpoints with abuse scores and risk status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Path</TableHead>
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Service</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Abuse Score</TableHead>
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
                  endpoints.map((e: any, i: number) => (
                  <TableRow key={e.path ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{e.path}</TableCell>
                    <TableCell className="py-2"><MethodBadge method={e.method ?? "GET"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{e.service_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-right">
                      <span className={e.abuse_score >= 80 ? "text-red-400" : e.abuse_score >= 50 ? "text-amber-400" : "text-green-400"}>
                        {e.abuse_score}
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><EndpointStatusBadge status={e.status ?? "normal"} /></TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Incidents Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Abuse Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {incidents.filter((inc: any) => inc.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Detected API abuse incidents with source intelligence</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Abuse Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Source IP</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Requests</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Blocked</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  incidents.map((inc: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{inc.abuse_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={inc.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{inc.source_ip}</TableCell>
                    <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{inc.request_count?.toLocaleString()}</TableCell>
                    <TableCell className="py-2 text-center text-[11px]">
                      {inc.blocked
                        ? <span className="text-green-400">Yes</span>
                        : <span className="text-red-400">No</span>}
                    </TableCell>
                    <TableCell className="py-2"><IncidentStatusBadge status={inc.status ?? "open"} /></TableCell>
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
