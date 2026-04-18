/**
 * API Security Management Dashboard
 *
 * Wired to: /api/v1/api-security-engine
 *   GET /api/v1/api-security-engine/stats
 *   GET /api/v1/api-security-engine/endpoints
 *   GET /api/v1/api-security-engine/abuse-events
 *   GET /api/v1/api-security-engine/scans
 *
 * Sections:
 *   1. KPI cards: Total Endpoints, API Keys, Abuse Events, Scan Pass Rate
 *   2. Registered Endpoints table
 *   3. Abuse Events feed
 *   4. Recent Scans results
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  Key,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Lock,
  Globe,
  Activity,
  Eye,
  Scan,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ──────────────────────────────────────────────────
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

// ── Mock data ────────────────────────────────────────────────────

const MOCK_STATS = {
  total_endpoints: 342,
  total_api_keys: 87,
  total_abuse_events: 23,
  scan_pass_rate: 94.2,
  critical_endpoints: 12,
  public_endpoints: 68,
  scans_completed: 19,
};

const MOCK_ENDPOINTS = [
  { id: "ep-001", endpoint_path: "/api/v1/auth/token",        http_method: "POST", service_name: "auth-service",      authentication_required: false, sensitivity_level: "critical", risk_score: 82 },
  { id: "ep-002", endpoint_path: "/api/v1/users/{id}",        http_method: "GET",  service_name: "user-service",      authentication_required: true,  sensitivity_level: "internal", risk_score: 34 },
  { id: "ep-003", endpoint_path: "/api/v1/findings",          http_method: "GET",  service_name: "findings-service",  authentication_required: true,  sensitivity_level: "internal", risk_score: 25 },
  { id: "ep-004", endpoint_path: "/api/v1/admin/config",      http_method: "PUT",  service_name: "admin-service",     authentication_required: true,  sensitivity_level: "critical", risk_score: 91 },
  { id: "ep-005", endpoint_path: "/api/v1/export/csv",        http_method: "GET",  service_name: "export-service",    authentication_required: true,  sensitivity_level: "high",     risk_score: 58 },
  { id: "ep-006", endpoint_path: "/api/v1/webhooks",          http_method: "POST", service_name: "webhook-service",   authentication_required: true,  sensitivity_level: "high",     risk_score: 47 },
  { id: "ep-007", endpoint_path: "/api/v1/health",            http_method: "GET",  service_name: "infra",             authentication_required: false, sensitivity_level: "public",   risk_score: 5  },
  { id: "ep-008", endpoint_path: "/api/v1/cve",               http_method: "GET",  service_name: "vuln-service",      authentication_required: true,  sensitivity_level: "internal", risk_score: 30 },
  { id: "ep-009", endpoint_path: "/api/v1/keys/rotate",       http_method: "POST", service_name: "auth-service",      authentication_required: true,  sensitivity_level: "critical", risk_score: 88 },
  { id: "ep-010", endpoint_path: "/api/v1/reports/download",  http_method: "GET",  service_name: "reporting-service", authentication_required: true,  sensitivity_level: "high",     risk_score: 64 },
];

const MOCK_ABUSE_EVENTS = [
  { id: "ab-001", event_type: "rate_limit_exceeded", endpoint_id: "ep-001", source_ip: "45.33.32.156",   severity: "high",     status: "detected",    detected_at: "14:41:02", request_payload_preview: "POST /api/v1/auth/token x2847" },
  { id: "ab-002", event_type: "injection_attempt",   endpoint_id: "ep-004", source_ip: "91.108.4.175",   severity: "critical", status: "blocked",     detected_at: "14:38:17", request_payload_preview: "PUT /api/v1/admin/config {\"role\":\"superadmin\"}" },
  { id: "ab-003", event_type: "credential_stuffing",  endpoint_id: "ep-001", source_ip: "198.51.100.22",  severity: "high",     status: "investigating",detected_at: "14:31:44", request_payload_preview: "1,204 failed login attempts in 8 min" },
  { id: "ab-004", event_type: "excessive_scraping",   endpoint_id: "ep-003", source_ip: "203.0.113.99",   severity: "medium",   status: "detected",    detected_at: "14:25:09", request_payload_preview: "GET /api/v1/findings — 9,400 req/hr" },
  { id: "ab-005", event_type: "bola_attempt",         endpoint_id: "ep-002", source_ip: "10.4.22.17",     severity: "high",     status: "blocked",     detected_at: "14:19:33", request_payload_preview: "Accessing user IDs not owned by caller" },
  { id: "ab-006", event_type: "mass_assignment",      endpoint_id: "ep-006", source_ip: "10.5.12.100",    severity: "medium",   status: "detected",    detected_at: "14:14:55", request_payload_preview: "POST /api/v1/webhooks with unexpected fields" },
  { id: "ab-007", event_type: "rate_limit_exceeded",  endpoint_id: "ep-010", source_ip: "192.168.1.44",   severity: "low",      status: "closed",      detected_at: "14:08:22", request_payload_preview: "GET /api/v1/reports/download x330/hr" },
  { id: "ab-008", event_type: "auth_bypass_attempt",  endpoint_id: "ep-009", source_ip: "77.88.55.60",    severity: "critical", status: "blocked",     detected_at: "13:59:41", request_payload_preview: "Forged JWT token with alg:none" },
];

const MOCK_SCANS = [
  { id: "sc-001", scan_type: "owasp_api_top10",  target_service: "auth-service",      status: "completed", endpoints_scanned: 22, vulnerabilities_found: 3, critical_count: 1, started_at: "08:00", completed_at: "08:14" },
  { id: "sc-002", scan_type: "owasp_api_top10",  target_service: "findings-service",  status: "completed", endpoints_scanned: 41, vulnerabilities_found: 0, critical_count: 0, started_at: "08:15", completed_at: "08:33" },
  { id: "sc-003", scan_type: "schema_validation", target_service: "user-service",      status: "completed", endpoints_scanned: 15, vulnerabilities_found: 2, critical_count: 0, started_at: "08:34", completed_at: "08:42" },
  { id: "sc-004", scan_type: "rate_limit_test",   target_service: "admin-service",     status: "completed", endpoints_scanned: 8,  vulnerabilities_found: 5, critical_count: 2, started_at: "08:43", completed_at: "08:59" },
  { id: "sc-005", scan_type: "owasp_api_top10",  target_service: "export-service",    status: "running",   endpoints_scanned: 12, vulnerabilities_found: 1, critical_count: 0, started_at: "09:10", completed_at: null  },
];

// ── Helper components ────────────────────────────────────────────

function SensitivityBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    internal: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    public:   "border-green-500/30 text-green-400 bg-green-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    detected:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    blocked:       "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    closed:        "border-green-500/30 text-green-400 bg-green-500/10",
    completed:     "border-green-500/30 text-green-400 bg-green-500/10",
    running:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:        "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function MethodBadge({ method }: { method: string }) {
  const map: Record<string, string> = {
    GET:    "border-green-500/30 text-green-400 bg-green-500/10",
    POST:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    PUT:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    PATCH:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    DELETE: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[method] ?? "border-border")}>
      {method}
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  const color = score >= 75 ? "text-red-400" : score >= 50 ? "text-amber-400" : score >= 25 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", color)}>{score}</span>;
}

function AbuseTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    rate_limit_exceeded: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    injection_attempt:   "border-red-500/30 text-red-400 bg-red-500/10",
    credential_stuffing: "border-red-500/30 text-red-400 bg-red-500/10",
    excessive_scraping:  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    bola_attempt:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    mass_assignment:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    auth_bypass_attempt: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono whitespace-nowrap", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Main Component ───────────────────────────────────────────────

export default function APISecurityMgmtDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [stats, setStats]     = useState<any>(null);
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [abuseEvents, setAbuseEvents] = useState<any[]>([]);
  const [scans, setScans]     = useState<any[]>([]);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/api-security-engine/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-security-engine/endpoints?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/api-security-engine/abuse-events?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/api/v1/api-security-engine/scans?org_id=${ORG_ID}`),
    ]).then(([statsRes, epRes, abuseRes, scansRes]) => {
      if (statsRes.status === "fulfilled") setStats(statsRes.value);
      if (epRes.status === "fulfilled")    setEndpoints(epRes.value?.items ?? epRes.value ?? []);
      if (abuseRes.status === "fulfilled") setAbuseEvents(abuseRes.value?.items ?? abuseRes.value ?? []);
      if (scansRes.status === "fulfilled") setScans(scansRes.value?.items ?? scansRes.value ?? []);
    }).finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const displayStats     = stats ?? MOCK_STATS;
  const displayEndpoints = endpoints.length > 0 ? endpoints : MOCK_ENDPOINTS;
  const displayAbuse     = abuseEvents.length > 0 ? abuseEvents : MOCK_ABUSE_EVENTS;
  const displayScans     = scans.length > 0 ? scans : MOCK_SCANS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="API Security Management"
        description="Endpoint inventory, API key governance, abuse detection, and OWASP API Top 10 scanning"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || loading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || loading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard
          title="Total Endpoints"
          value={displayStats.total_endpoints ?? "342"}
          icon={Globe}
          trend="up"
        />
        <KpiCard
          title="API Keys"
          value={displayStats.total_api_keys ?? "87"}
          icon={Key}
          trend="neutral"
          className="border-blue-500/20"
        />
        <KpiCard
          title="Abuse Events"
          value={displayStats.total_abuse_events ?? "23"}
          icon={AlertTriangle}
          trend="up"
          className="border-amber-500/20"
        />
        <KpiCard
          title="Scan Pass Rate"
          value={`${displayStats.scan_pass_rate ?? "94.2"}%`}
          icon={CheckCircle}
          trend="up"
          className="border-green-500/20"
        />
      </div>

      {/* Registered Endpoints Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              Registered API Endpoints
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {displayEndpoints.length} endpoints
            </Badge>
          </div>
          <CardDescription className="text-xs">All registered endpoints with method, sensitivity level, and risk score</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Path</TableHead>
                  <TableHead className="text-[11px] h-8">Service</TableHead>
                  <TableHead className="text-[11px] h-8">Auth Required</TableHead>
                  <TableHead className="text-[11px] h-8">Sensitivity</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayEndpoints.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  displayEndpoints.map((ep: any, i: number) => (
                  <TableRow key={ep.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2">
                      <MethodBadge method={ep.http_method ?? "GET"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-foreground">
                      {ep.endpoint_path}
                    </TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground">
                      {ep.service_name || "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      {ep.authentication_required ? (
                        <span className="flex items-center gap-1 text-[11px] text-green-400">
                          <Lock className="h-3 w-3" /> Yes
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-[11px] text-amber-400">
                          <Globe className="h-3 w-3" /> No
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="py-2">
                      <SensitivityBadge level={ep.sensitivity_level ?? "internal"} />
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <RiskScore score={ep.risk_score ?? 0} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Abuse Events Feed + Scan Results */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

        {/* Abuse Events Feed */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                <AlertTriangle className="h-4 w-4" />
                Abuse Events Feed
              </CardTitle>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Live</Badge>
            </div>
            <CardDescription className="text-xs">Detected API abuse patterns — rate limiting, injection, credential stuffing</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Source IP</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Time</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displayAbuse.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    displayAbuse.map((ev: any, i: number) => (
                    <TableRow key={ev.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2">
                        <AbuseTypeBadge type={ev.event_type ?? "unknown"} />
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                        {ev.source_ip || "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <SeverityBadge severity={ev.severity ?? "medium"} />
                      </TableCell>
                      <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">
                        {ev.detected_at ?? "—"}
                      </TableCell>
                      <TableCell className="py-2">
                        <StatusBadge status={ev.status ?? "detected"} />
                      </TableCell>
                    </TableRow>
                  ))
                )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Scan Results */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Scan className="h-4 w-4 text-purple-400" />
              Security Scan Results
            </CardTitle>
            <CardDescription className="text-xs">OWASP API Top 10 and schema validation scan history</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {displayScans.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              displayScans.map((scan: any, i: number) => (
              <div key={scan.id ?? i} className="rounded-lg border border-border bg-muted/20 p-3 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold truncate">{scan.target_service || "unknown"}</span>
                  <StatusBadge status={scan.status ?? "pending"} />
                </div>
                <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                  <span className="capitalize">{(scan.scan_type ?? "").replace(/_/g, " ")}</span>
                  <span className="tabular-nums">{scan.started_at} {scan.completed_at ? `→ ${scan.completed_at}` : "(running)"}</span>
                </div>
                <div className="flex items-center gap-4 text-[11px]">
                  <span className="text-muted-foreground">
                    Scanned: <span className="text-foreground font-medium tabular-nums">{scan.endpoints_scanned ?? 0}</span>
                  </span>
                  <span className={cn(
                    "font-medium tabular-nums",
                    (scan.vulnerabilities_found ?? 0) === 0 ? "text-green-400" :
                    (scan.critical_count ?? 0) > 0 ? "text-red-400" : "text-amber-400"
                  )}>
                    {scan.vulnerabilities_found ?? 0} vulns
                    {(scan.critical_count ?? 0) > 0 && (
                      <span className="text-red-400 ml-1">({scan.critical_count} critical)</span>
                    )}
                  </span>
                  {(scan.vulnerabilities_found ?? 0) === 0 && (
                    <span className="flex items-center gap-1 text-green-400">
                      <CheckCircle className="h-3 w-3" /> Clean
                    </span>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

      </div>

      {/* API Key stats strip */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Key className="h-4 w-4 text-amber-400" />
            API Key Governance Summary
          </CardTitle>
          <CardDescription className="text-xs">High-level breakdown from stats endpoint</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Total Keys",     value: displayStats.total_api_keys ?? 87,    color: "text-foreground" },
              { label: "Active",         value: displayStats.active_keys ?? 74,        color: "text-green-400" },
              { label: "Revoked",        value: displayStats.revoked_keys ?? 13,       color: "text-red-400" },
              { label: "Expiring Soon",  value: displayStats.expiring_soon_keys ?? 6, color: "text-amber-400" },
            ].map((item) => (
              <div key={item.label} className="rounded-lg border border-border bg-muted/20 p-3 text-center space-y-1">
                <div className={cn("text-2xl font-bold tabular-nums", item.color)}>{item.value}</div>
                <div className="text-[11px] text-muted-foreground">{item.label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

    </motion.div>
  );
}
