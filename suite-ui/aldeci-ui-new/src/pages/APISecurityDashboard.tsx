/**
 * API Security Dashboard
 *
 * API inventory, vulnerability scanning and abuse detection.
 *   1. KPIs: APIs Discovered, Unauthenticated, Vulnerabilities, Requests/min
 *   2. API inventory table (10 rows)
 *   3. OWASP API Top 10 vulnerability breakdown (horizontal bars)
 *   4. Traffic anomaly feed (8 events)
 *   5. Schema validation stats (4 boxes)
 *
 * API stubs: GET /api/v1/api-security/inventory, /api/v1/api-security/vulns, /api/v1/api-security/anomalies
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Globe, ShieldAlert, Activity, Zap, RefreshCw, AlertTriangle, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == Mock data ==================================================

const API_INVENTORY = [
  { endpoint: "/api/v1/auth/login",         method: "POST",   auth: "JWT",     rateLimited: true,  lastScan: "2026-04-16 09:00", vulns: 0, risk: "low"      },
  { endpoint: "/api/v1/users/{id}",         method: "GET",    auth: "JWT",     rateLimited: true,  lastScan: "2026-04-16 09:00", vulns: 1, risk: "medium"   },
  { endpoint: "/api/v1/export/data",        method: "GET",    auth: "API-Key", rateLimited: false, lastScan: "2026-04-16 08:45", vulns: 3, risk: "high"     },
  { endpoint: "/api/v1/admin/users",        method: "DELETE", auth: "None",    rateLimited: false, lastScan: "2026-04-16 08:45", vulns: 5, risk: "critical" },
  { endpoint: "/api/v1/webhooks/receive",   method: "POST",   auth: "API-Key", rateLimited: true,  lastScan: "2026-04-16 08:30", vulns: 2, risk: "medium"   },
  { endpoint: "/api/v1/files/upload",       method: "POST",   auth: "JWT",     rateLimited: true,  lastScan: "2026-04-16 08:30", vulns: 1, risk: "medium"   },
  { endpoint: "/api/v1/search",             method: "GET",    auth: "None",    rateLimited: false, lastScan: "2026-04-16 08:15", vulns: 4, risk: "high"     },
  { endpoint: "/api/v1/reports/generate",   method: "POST",   auth: "JWT",     rateLimited: true,  lastScan: "2026-04-16 08:15", vulns: 0, risk: "low"      },
  { endpoint: "/api/v1/config/update",      method: "PUT",    auth: "API-Key", rateLimited: false, lastScan: "2026-04-16 08:00", vulns: 2, risk: "high"     },
  { endpoint: "/api/v1/metrics",            method: "GET",    auth: "None",    rateLimited: false, lastScan: "2026-04-16 08:00", vulns: 0, risk: "low"      },
];

const OWASP_VULNS = [
  { label: "API1 - Broken Object Level Auth",   count: 18, color: "bg-red-500" },
  { label: "API2 - Broken Authentication",       count: 12, color: "bg-red-500" },
  { label: "API3 - Excessive Data Exposure",     count: 21, color: "bg-amber-500" },
  { label: "API4 - Lack of Resources/Rate Limit",count: 9,  color: "bg-amber-500" },
  { label: "API5 - Broken Function Level Auth",  count: 7,  color: "bg-yellow-500" },
  { label: "API6 - Mass Assignment",             count: 5,  color: "bg-yellow-500" },
  { label: "API7 - Security Misconfiguration",   count: 11, color: "bg-orange-500" },
  { label: "API8 - Injection",                   count: 4,  color: "bg-purple-500" },
  { label: "API9 - Improper Assets Management",  count: 2,  color: "bg-blue-500" },
  { label: "API10 - Insufficient Logging",       count: 0,  color: "bg-muted-foreground" },
];

const ANOMALIES = [
  { ts: "09:41:22", srcIp: "91.108.4.171",   endpoint: "/api/v1/auth/login",   type: "credential_stuffing",  severity: "critical", action: "blocked"   },
  { ts: "09:38:05", srcIp: "185.220.101.47", endpoint: "/api/v1/search",       type: "rate_limit_exceeded",  severity: "high",     action: "throttled" },
  { ts: "09:33:44", srcIp: "45.33.32.156",   endpoint: "/api/v1/export/data",  type: "suspicious_pattern",   severity: "high",     action: "alerted"   },
  { ts: "09:27:11", srcIp: "167.99.212.88",  endpoint: "/api/v1/users/{id}",   type: "bot_detected",         severity: "medium",   action: "captcha"   },
  { ts: "09:21:58", srcIp: "198.51.100.42",  endpoint: "/api/v1/admin/users",  type: "suspicious_pattern",   severity: "critical", action: "blocked"   },
  { ts: "09:15:33", srcIp: "203.0.113.19",   endpoint: "/api/v1/webhooks",     type: "rate_limit_exceeded",  severity: "medium",   action: "throttled" },
  { ts: "09:08:17", srcIp: "104.21.67.83",   endpoint: "/api/v1/config",       type: "suspicious_pattern",   severity: "high",     action: "alerted"   },
  { ts: "09:02:44", srcIp: "77.83.100.51",   endpoint: "/api/v1/auth/login",   type: "credential_stuffing",  severity: "critical", action: "blocked"   },
];

const SCHEMA_STATS = [
  { label: "Requests Validated", count: "1.2M",  color: "bg-blue-500/20 border-blue-500/30 text-blue-400"    },
  { label: "Schema Violations",  count: "3,847", color: "bg-red-500/20 border-red-500/30 text-red-400"       },
  { label: "Blocked Requests",   count: "412",   color: "bg-amber-500/20 border-amber-500/30 text-amber-400" },
  { label: "False Positives",    count: "28",    color: "bg-green-500/20 border-green-500/30 text-green-400" },
];

// == Helpers ====================================================

function MethodBadge({ m }: { m: string }) {
  const cls =
    m === "GET"    ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    m === "POST"   ? "border-green-500/30 text-green-400 bg-green-500/10" :
    m === "PUT"    ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
    m === "DELETE" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                     "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border font-mono", cls)}>{m}</Badge>;
}

function AuthBadge({ a }: { a: string }) {
  const cls =
    a === "None" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    a === "JWT"  ? "border-green-500/30 text-green-400 bg-green-500/10" :
                   "border-blue-500/30 text-blue-400 bg-blue-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{a}</Badge>;
}

function RiskBadge({ r }: { r: string }) {
  const cls =
    r === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    r === "high"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    r === "medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{r}</Badge>;
}

function SeverityBadge({ s }: { s: string }) {
  const cls =
    s === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    s === "high"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                       "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{s}</Badge>;
}

const OWASP_MAX = 25;

// == Component ==================================================

export default function APISecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

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
        title="API Security"
        description="API inventory, vulnerability scanning and abuse detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="APIs Discovered"   value={312}    icon={Globe}       trend="up"   className="border-blue-500/20" />
        <KpiCard title="Unauthenticated"   value={14}     icon={ShieldAlert} trend="down" className="border-red-500/20" />
        <KpiCard title="Vulnerabilities"   value={89}     icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Requests/min"      value="4,823"  icon={Activity}    trend="up"   className="border-green-500/20" />
      </div>

      {/* API inventory */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              API Inventory
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">Scan Now</Button>
          </div>
          <CardDescription className="text-xs">Discovered APIs with auth, rate limiting, and risk assessment</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Auth</TableHead>
                  <TableHead className="text-[11px] h-8">Rate Limited</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scan</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Vulns</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {API_INVENTORY.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  API_INVENTORY.map((row) => (
                  <TableRow key={row.endpoint} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 max-w-[220px] truncate">{row.endpoint}</TableCell>
                    <TableCell className="py-2.5"><MethodBadge m={row.method} /></TableCell>
                    <TableCell className="py-2.5"><AuthBadge a={row.auth} /></TableCell>
                    <TableCell className="py-2.5">
                      {row.rateLimited
                        ? <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                        : <span className="text-[10px] text-red-400 font-semibold">No</span>
                      }
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{row.lastScan}</TableCell>
                    <TableCell className={cn(
                      "text-xs tabular-nums py-2.5 font-bold text-center",
                      row.vulns === 0 ? "text-green-400" : row.vulns >= 4 ? "text-red-400" : "text-amber-400"
                    )}>
                      {row.vulns}
                    </TableCell>
                    <TableCell className="py-2.5"><RiskBadge r={row.risk} /></TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* OWASP breakdown + Anomaly feed */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* OWASP API Top 10 */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" />
              OWASP API Top 10 Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Vulnerability count by OWASP API Security category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {OWASP_VULNS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              OWASP_VULNS.map((v) => (
              <div key={v.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground truncate max-w-[240px]">{v.label}</span>
                  <span className="font-bold tabular-nums ml-2 shrink-0">{v.count}</span>
                </div>
                <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: v.count > 0 ? `${(v.count / OWASP_MAX) * 100}%` : "0%" }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", v.color)}
                  />
                </div>
              </div>
            )))}
          </CardContent>
        </Card>

        {/* Traffic anomaly feed */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-amber-400" />
              Traffic Anomaly Feed
            </CardTitle>
            <CardDescription className="text-xs">Recent detected anomalies and actions taken</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {ANOMALIES.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              ANOMALIES.map((ev, i) => (
              <div key={i} className="flex flex-col gap-1 p-2 rounded-lg bg-muted/20 border border-border/50">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono text-muted-foreground">{ev.ts}</span>
                  <div className="flex items-center gap-1.5">
                    <SeverityBadge s={ev.severity} />
                    <Badge className="text-[9px] border border-border text-muted-foreground capitalize">{ev.action}</Badge>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-blue-400 shrink-0">{ev.srcIp}</span>
                  <span className="text-[10px] text-muted-foreground">=</span>
                  <span className="text-[10px] font-mono truncate">{ev.endpoint}</span>
                </div>
                <span className="text-[10px] text-muted-foreground font-medium">{ev.type.replace(/_/g, " ")}</span>
              </div>
            )))}
          </CardContent>
        </Card>
      </div>

      {/* Schema validation stats */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Zap className="h-4 w-4 text-cyan-400" />
            Schema Validation Statistics
          </CardTitle>
          <CardDescription className="text-xs">OpenAPI schema enforcement = last 24 hours</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {SCHEMA_STATS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              SCHEMA_STATS.map((s) => (
              <div key={s.label} className={cn("rounded-lg border p-4 text-center", s.color)}>
                <div className="text-2xl font-bold tabular-nums">{s.count}</div>
                <div className="text-[10px] font-medium mt-1">{s.label}</div>
              </div>
            )))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
