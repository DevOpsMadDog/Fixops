/**
 * API Vulnerability Management (APISecurityPage)
 *
 * OWASP API Top 10 findings and traffic analysis.
 *   1. KPIs: APIs Inventoried, Unauthenticated, Vulnerabilities, Traffic Anomalies
 *   2. OWASP API Top 10 table (10 rows)
 *   3. API findings table (15 rows)
 *   4. Traffic anomaly feed (12 events)
 *   5. API inventory health stat cards (6)
 *
 * Route: /api-sec
 * API stubs: GET /api/v1/api-security/findings, /api/v1/api-security/owasp, /api/v1/api-security/traffic
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, Activity, Lock, RefreshCw, Globe, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const ORG_ID = "default";
function getApiKey() {
  return (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "dev-key";
}
async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, { headers: { "X-API-Key": getApiKey() } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const OWASP_TOP10 = [
  { rank: "API1:2023",  name: "Broken Object Level Authorization", findings: 18, critical: 6, high: 8, medium: 4, trend: "up"   },
  { rank: "API2:2023",  name: "Broken Authentication",             findings: 9,  critical: 4, high: 4, medium: 1, trend: "down" },
  { rank: "API3:2023",  name: "Broken Object Property Auth",       findings: 7,  critical: 2, high: 3, medium: 2, trend: "up"   },
  { rank: "API4:2023",  name: "Unrestricted Resource Consumption", findings: 11, critical: 1, high: 5, medium: 5, trend: "down" },
  { rank: "API5:2023",  name: "Broken Function Level Auth",        findings: 5,  critical: 3, high: 2, medium: 0, trend: "flat" },
  { rank: "API6:2023",  name: "Unrestricted Access to Sensitive",  findings: 8,  critical: 2, high: 4, medium: 2, trend: "up"   },
  { rank: "API7:2023",  name: "Server Side Request Forgery",       findings: 4,  critical: 2, high: 2, medium: 0, trend: "down" },
  { rank: "API8:2023",  name: "Security Misconfiguration",         findings: 14, critical: 0, high: 6, medium: 8, trend: "up"   },
  { rank: "API9:2023",  name: "Improper Inventory Management",     findings: 8,  critical: 0, high: 3, medium: 5, trend: "flat" },
  { rank: "API10:2023", name: "Unsafe Consumption of APIs",        findings: 5,  critical: 1, high: 2, medium: 2, trend: "down" },
];

const API_FINDINGS = [
  { endpoint: "/api/v1/users/{id}",        method: "GET",    vuln: "BOLA",              severity: "Critical", cwe: "CWE-639", status: "open"     },
  { endpoint: "/api/v1/auth/token",        method: "POST",   vuln: "Broken Auth",       severity: "Critical", cwe: "CWE-287", status: "open"     },
  { endpoint: "/api/v1/admin/users",       method: "DELETE", vuln: "BFLA",              severity: "Critical", cwe: "CWE-285", status: "open"     },
  { endpoint: "/api/v1/payments",          method: "POST",   vuln: "Mass Assignment",   severity: "High",     cwe: "CWE-915", status: "open"     },
  { endpoint: "/api/v1/export",            method: "GET",    vuln: "Resource Exposure",  severity: "High",     cwe: "CWE-200", status: "open"     },
  { endpoint: "/api/v1/webhooks",          method: "POST",   vuln: "SSRF",              severity: "High",     cwe: "CWE-918", status: "open"     },
  { endpoint: "/api/v1/search",            method: "GET",    vuln: "Rate Limit Missing", severity: "High",     cwe: "CWE-770", status: "fixed"    },
  { endpoint: "/api/v1/files/upload",      method: "POST",   vuln: "Unrestricted Upload",severity: "High",     cwe: "CWE-434", status: "open"     },
  { endpoint: "/api/v1/logs",              method: "GET",    vuln: "Sensitive Exposure", severity: "Medium",   cwe: "CWE-532", status: "accepted" },
  { endpoint: "/api/v2/reports",           method: "GET",    vuln: "BOLA",              severity: "Medium",   cwe: "CWE-639", status: "open"     },
  { endpoint: "/api/v1/config",            method: "GET",    vuln: "Misc Config",       severity: "Medium",   cwe: "CWE-16",  status: "open"     },
  { endpoint: "/api/v1/debug",             method: "GET",    vuln: "Debug Endpoint",    severity: "Medium",   cwe: "CWE-489", status: "fixed"    },
  { endpoint: "/api/v1/internal/metrics",  method: "GET",    vuln: "No Auth",           severity: "High",     cwe: "CWE-306", status: "open"     },
  { endpoint: "/api/v1/users/bulk",        method: "POST",   vuln: "Mass Assignment",   severity: "High",     cwe: "CWE-915", status: "open"     },
  { endpoint: "/api/v1/session",           method: "DELETE", vuln: "Missing CSRF",      severity: "Medium",   cwe: "CWE-352", status: "open"     },
];

const TRAFFIC_ANOMALIES = [
  { ip: "185.220.101.42", type: "credential_stuffing",   requests: 4821, endpoint: "/api/v1/auth/token",   blocked: true,  ts: "04:12 UTC" },
  { ip: "45.134.26.117",  type: "bot_detected",          requests: 2310, endpoint: "/api/v1/search",       blocked: true,  ts: "04:28 UTC" },
  { ip: "192.168.3.44",   type: "rate_limit_exceeded",   requests: 980,  endpoint: "/api/v1/export",       blocked: false, ts: "05:01 UTC" },
  { ip: "103.21.244.0",   type: "credential_stuffing",   requests: 6140, endpoint: "/api/v1/auth/login",   blocked: true,  ts: "05:33 UTC" },
  { ip: "89.248.167.131", type: "bot_detected",          requests: 3200, endpoint: "/api/v1/users",        blocked: true,  ts: "06:02 UTC" },
  { ip: "10.0.15.88",     type: "rate_limit_exceeded",   requests: 512,  endpoint: "/api/v1/reports",      blocked: false, ts: "06:44 UTC" },
  { ip: "198.235.24.17",  type: "credential_stuffing",   requests: 8900, endpoint: "/api/v1/auth/token",   blocked: true,  ts: "07:15 UTC" },
  { ip: "5.188.62.140",   type: "bot_detected",          requests: 1430, endpoint: "/api/v1/products",     blocked: false, ts: "07:48 UTC" },
  { ip: "172.16.0.201",   type: "rate_limit_exceeded",   requests: 742,  endpoint: "/api/v1/notifications",blocked: false, ts: "08:10 UTC" },
  { ip: "77.247.110.83",  type: "credential_stuffing",   requests: 3390, endpoint: "/api/v1/auth/token",   blocked: true,  ts: "08:32 UTC" },
  { ip: "209.141.32.153", type: "bot_detected",          requests: 5610, endpoint: "/api/v1/search",       blocked: true,  ts: "09:05 UTC" },
  { ip: "185.100.87.73",  type: "rate_limit_exceeded",   requests: 1204, endpoint: "/api/v1/export",       blocked: false, ts: "09:41 UTC" },
];

const INVENTORY_HEALTH = [
  { label: "With Auth",       value: 298, color: "text-green-400", bg: "bg-green-500/10 border-green-500/20" },
  { label: "Unauthenticated", value: 14,  color: "text-red-400",   bg: "bg-red-500/10 border-red-500/20"   },
  { label: "Rate Limited",    value: 241, color: "text-blue-400",  bg: "bg-blue-500/10 border-blue-500/20" },
  { label: "Documented",      value: 189, color: "text-purple-400",bg: "bg-purple-500/10 border-purple-500/20" },
  { label: "Deprecated",      value: 37,  color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
  { label: "In Testing",      value: 54,  color: "text-cyan-400",  bg: "bg-cyan-500/10 border-cyan-500/20" },
];

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function MethodBadge({ method }: { method: string }) {
  const cls =
    method === "GET"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
    method === "POST"   ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    method === "DELETE" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    method === "PUT"    ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                          "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border font-mono", cls)}>{method}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "open"     ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "fixed"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "accepted" ? "border-border text-muted-foreground bg-muted/20" :
                            "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{status}</Badge>;
}

function AnomalyBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    credential_stuffing: "border-red-500/30 text-red-400 bg-red-500/10",
    bot_detected:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
    rate_limit_exceeded: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function TrendBadge({ trend }: { trend: string }) {
  if (trend === "up")   return <span className="text-red-400 text-xs font-bold">↑</span>;
  if (trend === "down") return <span className="text-green-400 text-xs font-bold">↓</span>;
  return <span className="text-muted-foreground text-xs">→</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function APISecurityPage() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api-security-engine/endpoints?org_id=${ORG_ID}`),
      apiFetch(`/api-security-engine/abuse-events?org_id=${ORG_ID}&limit=15`),
    ]).then(([endpointsRes, abuseRes]) => {
      const endpoints = endpointsRes.status === "fulfilled" ? endpointsRes.value : null;
      const abuse = abuseRes.status === "fulfilled" ? abuseRes.value : null;
      if (endpoints || abuse) setLiveData({ endpoints, abuse });
    }).finally(() => setDataLoading(false));
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="API Vulnerability Management"
        description="OWASP API Top 10 findings and traffic analysis"
        actions={
          <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="APIs Inventoried"       value={312}  icon={Globe}         />
        <KpiCard title="Unauthenticated"         value={14}   icon={Lock}          trend="up" className="border-red-500/20" />
        <KpiCard title="Vulnerabilities"         value={89}   icon={AlertTriangle} trend="up" className="border-amber-500/20" />
        <KpiCard title="Traffic Anomalies Today" value={23}   icon={Activity}      trend="up" className="border-yellow-500/20" />
      </div>

      {/* OWASP API Top 10 */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-400" />
            OWASP API Security Top 10 (2023)
          </CardTitle>
          <CardDescription className="text-xs">Finding distribution across the OWASP API risk categories</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Rank</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                  <TableHead className="text-[11px] h-8">Severity Distribution</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Trend</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {OWASP_TOP10.map((row) => (
                  <TableRow key={row.rank} className="hover:bg-muted/30">
                    <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground whitespace-nowrap">{row.rank}</TableCell>
                    <TableCell className="text-xs py-2.5 font-medium max-w-[220px]">{row.name}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums font-bold text-right">{row.findings}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-1 h-4">
                        {row.critical > 0 && (
                          <div
                            className="h-4 rounded bg-red-500/70 flex items-center justify-center text-[9px] text-white font-bold"
                            style={{ width: `${row.critical * 14}px`, minWidth: "18px" }}
                            title={`Critical: ${row.critical}`}
                          >{row.critical}</div>
                        )}
                        {row.high > 0 && (
                          <div
                            className="h-4 rounded bg-amber-500/70 flex items-center justify-center text-[9px] text-white font-bold"
                            style={{ width: `${row.high * 14}px`, minWidth: "18px" }}
                            title={`High: ${row.high}`}
                          >{row.high}</div>
                        )}
                        {row.medium > 0 && (
                          <div
                            className="h-4 rounded bg-yellow-500/50 flex items-center justify-center text-[9px] text-white font-bold"
                            style={{ width: `${row.medium * 14}px`, minWidth: "18px" }}
                            title={`Medium: ${row.medium}`}
                          >{row.medium}</div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5 text-center"><TrendBadge trend={row.trend} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* API Findings table */}
      <Card className="border-red-500/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              API Findings
            </CardTitle>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
              {API_FINDINGS.filter(f => f.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Vulnerability findings per API endpoint</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Vulnerability</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">CWE</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {API_FINDINGS.map((row, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-[10px] font-mono py-2.5 max-w-[200px] truncate text-blue-300">{row.endpoint}</TableCell>
                    <TableCell className="py-2.5"><MethodBadge method={row.method} /></TableCell>
                    <TableCell className="text-xs py-2.5">{row.vuln}</TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={row.severity} /></TableCell>
                    <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground">{row.cwe}</TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Fix</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Traffic anomaly feed + Inventory health */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Traffic anomaly feed */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Traffic Anomaly Feed
            </CardTitle>
            <CardDescription className="text-xs">Real-time API traffic anomalies (today)</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Source IP</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Reqs</TableHead>
                    <TableHead className="text-[11px] h-8">Blocked</TableHead>
                    <TableHead className="text-[11px] h-8">Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {TRAFFIC_ANOMALIES.map((ev, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] font-mono py-2 text-muted-foreground">{ev.ip}</TableCell>
                      <TableCell className="py-2"><AnomalyBadge type={ev.type} /></TableCell>
                      <TableCell className="text-xs py-2 tabular-nums text-right font-bold">{ev.requests.toLocaleString()}</TableCell>
                      <TableCell className="py-2">
                        {ev.blocked
                          ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">blocked</Badge>
                          : <Badge className="text-[10px] border border-border text-muted-foreground">allowed</Badge>
                        }
                      </TableCell>
                      <TableCell className="text-[10px] py-2 tabular-nums text-muted-foreground">{ev.ts}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* API inventory health */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Zap className="h-4 w-4 text-purple-400" />
              API Inventory Health
            </CardTitle>
            <CardDescription className="text-xs">Health breakdown across 312 inventoried APIs</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              {INVENTORY_HEALTH.map((stat) => (
                <div
                  key={stat.label}
                  className={cn(
                    "rounded-lg border p-4 flex flex-col gap-1",
                    stat.bg
                  )}
                >
                  <span className={cn("text-2xl font-bold tabular-nums", stat.color)}>{stat.value}</span>
                  <span className="text-[11px] text-muted-foreground">{stat.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
