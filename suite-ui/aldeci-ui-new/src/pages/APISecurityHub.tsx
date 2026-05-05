/**
 * APISecurityHub — Unified API Security hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 3 standalone API security dashboards into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10 (API Security cluster).
 *
 *   tab        | source page                | endpoint
 *   -----------|----------------------------|----------------------------------------------
 *   inventory  | APISecurityDashboard       | /api/v1/api-security/{inventory,findings,auth-analysis,rate-limits}
 *   management | APISecurityMgmtDashboard   | /api/v1/api-security-engine/{stats,apis,abuse-events}
 *   discovery  | APIDiscoveryDashboard      | /api/v1/api-discovery/{stats,endpoints}
 *
 * Route: /discover/api-security
 * Persona target: AppSec Engineer (#10), API Owner (#16), Sec Architect (#11)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.10
 *
 * NO MOCKS — all tabs call real backend routes. EmptyState shown when 0 records.
 */

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  ListChecks,
  Search,
  RefreshCw,
  Globe,
  Lock,
  AlertTriangle,
  Activity,
  Zap,
  Key,
  Shield,
  Server,
  Eye,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── shared API helpers ─────────────────────────────────────────────────────

function getApiKey(): string {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
    (import.meta.env.VITE_API_KEY as string) ||
    "dev-key"
  );
}

async function apiFetch<T = unknown>(path: string): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": getApiKey() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── small shared UI helpers ────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const cls =
    sev === "critical"
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : sev === "high"
        ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
        : sev === "medium"
          ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10"
          : "border-border text-muted-foreground";
  return (
    <Badge className={cn("text-[10px] border capitalize", cls)}>{sev}</Badge>
  );
}

function MethodBadge({ method }: { method: string }) {
  const cls =
    method === "GET"
      ? "border-green-500/30 text-green-400 bg-green-500/10"
      : method === "POST"
        ? "border-blue-500/30 text-blue-400 bg-blue-500/10"
        : method === "DELETE"
          ? "border-red-500/30 text-red-400 bg-red-500/10"
          : method === "PUT"
            ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
            : "border-border text-muted-foreground";
  return (
    <Badge className={cn("text-[10px] border font-mono", cls)}>{method}</Badge>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  );
}

// ── KPI mini-card ──────────────────────────────────────────────────────────

function KpiMini({
  title,
  value,
  icon: Icon,
  accent,
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  accent?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-lg border bg-card p-4 flex flex-col gap-1",
        accent ?? "border-border",
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-[11px] text-muted-foreground">{title}</span>
        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
      </div>
      <span className="text-2xl font-bold tabular-nums">{value}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB 1 — INVENTORY & OWASP
// Calls: GET /api/v1/api-security/inventory
//        GET /api/v1/api-security/findings
//        GET /api/v1/api-security/auth-analysis
//        GET /api/v1/api-security/rate-limits
// ═══════════════════════════════════════════════════════════════════════════

interface InventoryData {
  total_scans: number;
  inventory: Array<{
    target_url?: string;
    openapi_version?: string;
    total_endpoints?: number;
    timestamp?: string;
  }>;
}

interface FindingsData {
  total: number;
  by_severity: Record<string, number>;
  findings: Array<{
    id?: string;
    owasp_category?: string;
    severity?: string;
    endpoint?: string;
    method?: string;
    description?: string;
    cwe_id?: string;
    status?: string;
  }>;
}

interface RateLimitData {
  total: number;
  endpoints_without_rate_limit: number;
  results: Array<{ endpoint?: string; rate_limit_detected?: boolean }>;
}

interface AuthData {
  total: number;
  analyses: Array<{
    endpoint?: string;
    auth_type?: string;
    weaknesses?: string[];
  }>;
}

function InventoryTab() {
  const [inv, setInv] = useState<InventoryData | null>(null);
  const [findings, setFindings] = useState<FindingsData | null>(null);
  const [rateLimit, setRateLimit] = useState<RateLimitData | null>(null);
  const [auth, setAuth] = useState<AuthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch<InventoryData>("/api-security/inventory"),
      apiFetch<FindingsData>("/api-security/findings?limit=20"),
      apiFetch<RateLimitData>("/api-security/rate-limits"),
      apiFetch<AuthData>("/api-security/auth-analysis"),
    ]).then(([invR, findR, rlR, authR]) => {
      if (invR.status === "fulfilled") setInv(invR.value);
      if (findR.status === "fulfilled") setFindings(findR.value);
      if (rlR.status === "fulfilled") setRateLimit(rlR.value);
      if (authR.status === "fulfilled") setAuth(authR.value);
      if (
        invR.status === "rejected" &&
        findR.status === "rejected" &&
        rlR.status === "rejected" &&
        authR.status === "rejected"
      ) {
        setError("Failed to load API security data");
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) return <Spinner />;

  if (error && !inv && !findings) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No API security data"
        description="Run a scan to populate inventory and findings. Use POST /api/v1/api-security/scan."
        action={
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Retry
          </Button>
        }
      />
    );
  }

  const totalFindings = findings?.total ?? 0;
  const totalInventoried = inv?.total_scans ?? 0;
  const unauthCount = auth?.analyses.filter(a => (a.weaknesses?.length ?? 0) > 0).length ?? 0;
  const noRateLimitCount = rateLimit?.endpoints_without_rate_limit ?? 0;

  return (
    <div className="flex flex-col gap-4 pt-2">
      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiMini title="Scans in Inventory" value={totalInventoried} icon={Globe} />
        <KpiMini
          title="Auth Weaknesses"
          value={unauthCount}
          icon={Lock}
          accent={unauthCount > 0 ? "border-red-500/20" : undefined}
        />
        <KpiMini
          title="Findings"
          value={totalFindings}
          icon={AlertTriangle}
          accent={totalFindings > 0 ? "border-amber-500/20" : undefined}
        />
        <KpiMini
          title="No Rate Limit"
          value={noRateLimitCount}
          icon={Activity}
          accent={noRateLimitCount > 0 ? "border-yellow-500/20" : undefined}
        />
      </div>

      {/* Findings table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              API Findings
            </CardTitle>
            <div className="flex items-center gap-2">
              {findings?.by_severity && Object.entries(findings.by_severity).map(([sev, count]) => (
                <Badge key={sev} className="text-[10px] border border-border text-muted-foreground">
                  {sev}: {count}
                </Badge>
              ))}
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={load} aria-label="Refresh">
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            OWASP API Top 10 findings from completed scans
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {(findings?.findings.length ?? 0) === 0 ? (
            <EmptyState
              icon={ShieldAlert}
              title="No findings yet"
              description="Run an API scan to surface OWASP API Top 10 vulnerabilities."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                    <TableHead className="text-[11px] h-8">Method</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">CWE</TableHead>
                    <TableHead className="text-[11px] h-8 max-w-xs">Description</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings!.findings.map((f, i) => (
                    <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground whitespace-nowrap">
                        {f.owasp_category ?? "—"}
                      </TableCell>
                      <TableCell className="text-[10px] font-mono py-2.5 text-blue-300 max-w-[180px] truncate">
                        {f.endpoint ?? "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {f.method ? <MethodBadge method={f.method.toUpperCase()} /> : <span className="text-muted-foreground text-[10px]">—</span>}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <SevBadge sev={(f.severity ?? "info").toLowerCase()} />
                      </TableCell>
                      <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground">
                        {f.cwe_id ?? "—"}
                      </TableCell>
                      <TableCell className="text-[10px] py-2.5 max-w-xs truncate text-muted-foreground">
                        {f.description ?? "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Auth analysis + Rate limits */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-purple-400" />
              Authentication Analysis
            </CardTitle>
            <CardDescription className="text-xs">
              {auth?.total ?? 0} endpoints analysed
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {(auth?.analyses.length ?? 0) === 0 ? (
              <EmptyState icon={Lock} title="No auth analyses" description="Scan an API to analyse authentication." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                      <TableHead className="text-[11px] h-8">Auth Type</TableHead>
                      <TableHead className="text-[11px] h-8">Weaknesses</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {auth!.analyses.slice(0, 10).map((a, i) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="text-[10px] font-mono py-2 truncate max-w-[160px] text-blue-300">
                          {a.endpoint ?? "—"}
                        </TableCell>
                        <TableCell className="text-[10px] py-2">{a.auth_type ?? "unknown"}</TableCell>
                        <TableCell className="py-2">
                          {(a.weaknesses?.length ?? 0) === 0 ? (
                            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">clean</Badge>
                          ) : (
                            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                              {a.weaknesses!.length} issue{a.weaknesses!.length !== 1 ? "s" : ""}
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Rate Limit Coverage
            </CardTitle>
            <CardDescription className="text-xs">
              {rateLimit?.total ?? 0} endpoints checked — {noRateLimitCount} without rate limiting
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {(rateLimit?.results.length ?? 0) === 0 ? (
              <EmptyState icon={Activity} title="No rate limit data" description="Enable rate limit checks in your scan configuration." />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                      <TableHead className="text-[11px] h-8 text-center">Rate Limited</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rateLimit!.results.slice(0, 10).map((r, i) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="text-[10px] font-mono py-2 truncate max-w-[220px] text-blue-300">
                          {r.endpoint ?? "—"}
                        </TableCell>
                        <TableCell className="py-2 text-center">
                          {r.rate_limit_detected ? (
                            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">yes</Badge>
                          ) : (
                            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">no</Badge>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB 2 — MANAGEMENT
// Calls: GET /api/v1/api-security-engine/stats
//        GET /api/v1/api-security-engine/apis
//        GET /api/v1/api-security-engine/abuse-events
// ═══════════════════════════════════════════════════════════════════════════

interface EngineStats {
  total_endpoints?: number;
  total_api_keys?: number;
  total_abuse_events?: number;
  total_scans?: number;
  high_risk_endpoints?: number;
  active_keys?: number;
  revoked_keys?: number;
  recent_abuse?: number;
  [key: string]: unknown;
}

interface ApiEndpointItem {
  id?: string;
  endpoint_path?: string;
  http_method?: string;
  service_name?: string;
  sensitivity_level?: string;
  risk_score?: number;
  authentication_required?: boolean;
  is_public?: boolean;
}

interface AbuseEvent {
  id?: string;
  event_type?: string;
  severity?: string;
  source_ip?: string;
  endpoint_id?: string;
  status?: string;
  created_at?: string;
}

function ManagementTab() {
  const [stats, setStats] = useState<EngineStats | null>(null);
  const [apis, setApis] = useState<ApiEndpointItem[]>([]);
  const [abuse, setAbuse] = useState<AbuseEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch<EngineStats>("/api-security-engine/stats"),
      apiFetch<ApiEndpointItem[]>("/api-security-engine/apis?org_id=default"),
      apiFetch<AbuseEvent[]>("/api-security-engine/abuse-events?org_id=default&limit=20"),
    ]).then(([sR, aR, abR]) => {
      if (sR.status === "fulfilled") setStats(sR.value);
      if (aR.status === "fulfilled") setApis(Array.isArray(aR.value) ? aR.value : []);
      if (abR.status === "fulfilled") setAbuse(Array.isArray(abR.value) ? abR.value : []);
      if (sR.status === "rejected" && aR.status === "rejected" && abR.status === "rejected") {
        setError("Failed to load management data");
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) return <Spinner />;

  if (error && !stats && apis.length === 0) {
    return (
      <EmptyState
        icon={ListChecks}
        title="No management data"
        description="Register API endpoints via POST /api/v1/api-security-engine/apis to populate this view."
        action={
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Retry
          </Button>
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-4 pt-2">
      {/* Stats KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiMini title="Registered Endpoints" value={stats?.total_endpoints ?? apis.length} icon={Server} />
        <KpiMini title="API Keys" value={stats?.total_api_keys ?? 0} icon={Key} />
        <KpiMini
          title="Abuse Events"
          value={stats?.total_abuse_events ?? abuse.length}
          icon={AlertTriangle}
          accent={(stats?.total_abuse_events ?? abuse.length) > 0 ? "border-red-500/20" : undefined}
        />
        <KpiMini
          title="High Risk"
          value={stats?.high_risk_endpoints ?? 0}
          icon={ShieldAlert}
          accent={(stats?.high_risk_endpoints ?? 0) > 0 ? "border-amber-500/20" : undefined}
        />
      </div>

      {/* Registered APIs table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Server className="h-4 w-4 text-blue-400" />
              Registered API Endpoints
            </CardTitle>
            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={load} aria-label="Refresh">
              <RefreshCw className="h-3.5 w-3.5" />
            </Button>
          </div>
          <CardDescription className="text-xs">
            {apis.length} endpoint{apis.length !== 1 ? "s" : ""} in the security inventory
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {apis.length === 0 ? (
            <EmptyState
              icon={Server}
              title="No endpoints registered"
              description="Use POST /api/v1/api-security-engine/apis to register API endpoints."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Path</TableHead>
                    <TableHead className="text-[11px] h-8">Method</TableHead>
                    <TableHead className="text-[11px] h-8">Service</TableHead>
                    <TableHead className="text-[11px] h-8">Sensitivity</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Risk</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Auth</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Public</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {apis.slice(0, 20).map((ep, i) => (
                    <TableRow key={ep.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] font-mono py-2.5 truncate max-w-[180px] text-blue-300">
                        {ep.endpoint_path ?? "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {ep.http_method ? <MethodBadge method={ep.http_method.toUpperCase()} /> : <span className="text-muted-foreground text-[10px]">—</span>}
                      </TableCell>
                      <TableCell className="text-[10px] py-2.5 text-muted-foreground">
                        {ep.service_name || "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <SevBadge sev={ep.sensitivity_level ?? "internal"} />
                      </TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums font-bold text-right">
                        {ep.risk_score !== undefined ? ep.risk_score.toFixed(1) : "—"}
                      </TableCell>
                      <TableCell className="py-2.5 text-center">
                        {ep.authentication_required ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">yes</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">no</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5 text-center">
                        {ep.is_public ? (
                          <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">yes</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-border text-muted-foreground">no</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Abuse events */}
      <Card className="border-red-500/10">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            Abuse Events
          </CardTitle>
          <CardDescription className="text-xs">
            {abuse.length} recent abuse event{abuse.length !== 1 ? "s" : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {abuse.length === 0 ? (
            <EmptyState
              icon={AlertTriangle}
              title="No abuse events"
              description="Abuse events are recorded automatically when anomalies are detected."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Source IP</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Timestamp</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {abuse.map((ev, i) => (
                    <TableRow key={ev.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] py-2.5">{ev.event_type ?? "—"}</TableCell>
                      <TableCell className="py-2.5">
                        <SevBadge sev={(ev.severity ?? "medium").toLowerCase()} />
                      </TableCell>
                      <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground">
                        {ev.source_ip || "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <Badge className="text-[10px] border border-border text-muted-foreground capitalize">
                          {ev.status ?? "detected"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-[10px] py-2.5 tabular-nums text-muted-foreground">
                        {ev.created_at ? new Date(ev.created_at).toLocaleString() : "—"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// TAB 3 — DISCOVERY
// Calls: GET /api/v1/api-discovery/stats
//        GET /api/v1/api-discovery/endpoints
// ═══════════════════════════════════════════════════════════════════════════

interface DiscoveryStats {
  total_endpoints?: number;
  shadow_apis?: number;
  documented?: number;
  undocumented?: number;
  total_scans?: number;
  high_risk?: number;
  [key: string]: unknown;
}

interface DiscoveredEndpoint {
  id?: string;
  endpoint_path?: string;
  http_method?: string;
  service_name?: string;
  api_type?: string;
  is_shadow?: boolean;
  is_documented?: boolean;
  risk_level?: string;
  auth_required?: boolean;
}

function DiscoveryTab() {
  const [stats, setStats] = useState<DiscoveryStats | null>(null);
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [shadowOnly, setShadowOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch<DiscoveryStats>("/api-discovery/stats"),
      apiFetch<DiscoveredEndpoint[]>("/api-discovery/endpoints?org_id=default"),
    ]).then(([sR, epR]) => {
      if (sR.status === "fulfilled") setStats(sR.value);
      if (epR.status === "fulfilled") setEndpoints(Array.isArray(epR.value) ? epR.value : []);
      if (sR.status === "rejected" && epR.status === "rejected") {
        setError("Failed to load discovery data");
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const displayed = shadowOnly ? endpoints.filter(e => e.is_shadow) : endpoints;

  if (loading) return <Spinner />;

  if (error && !stats && endpoints.length === 0) {
    return (
      <EmptyState
        icon={Search}
        title="No discovery data"
        description="Start an API discovery scan via POST /api/v1/api-discovery/scans."
        action={
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Retry
          </Button>
        }
      />
    );
  }

  const shadowCount = endpoints.filter(e => e.is_shadow).length;
  const docCount = endpoints.filter(e => e.is_documented).length;
  const highRiskCount = endpoints.filter(e => e.risk_level === "high" || e.risk_level === "critical").length;

  return (
    <div className="flex flex-col gap-4 pt-2">
      {/* Stats KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiMini title="Discovered Endpoints" value={stats?.total_endpoints ?? endpoints.length} icon={Globe} />
        <KpiMini
          title="Shadow APIs"
          value={stats?.shadow_apis ?? shadowCount}
          icon={Eye}
          accent={(stats?.shadow_apis ?? shadowCount) > 0 ? "border-red-500/20" : undefined}
        />
        <KpiMini title="Documented" value={stats?.documented ?? docCount} icon={Shield} />
        <KpiMini
          title="High Risk"
          value={stats?.high_risk ?? highRiskCount}
          icon={AlertTriangle}
          accent={(stats?.high_risk ?? highRiskCount) > 0 ? "border-amber-500/20" : undefined}
        />
      </div>

      {/* Endpoints table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Search className="h-4 w-4 text-indigo-400" />
              Discovered Endpoints
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button
                variant={shadowOnly ? "default" : "outline"}
                size="sm"
                className="h-7 px-2 text-[11px]"
                onClick={() => setShadowOnly(v => !v)}
              >
                Shadow only
                {shadowCount > 0 && (
                  <Badge className="ml-1 text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">
                    {shadowCount}
                  </Badge>
                )}
              </Button>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={load} aria-label="Refresh">
                <RefreshCw className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            {displayed.length} endpoint{displayed.length !== 1 ? "s" : ""} shown
            {shadowOnly ? " (shadow APIs only)" : ""}
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {displayed.length === 0 ? (
            <EmptyState
              icon={Search}
              title={shadowOnly ? "No shadow APIs detected" : "No endpoints discovered"}
              description={
                shadowOnly
                  ? "No undocumented shadow APIs found. That's good news."
                  : "Run an API discovery scan to find endpoints across your services."
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Path</TableHead>
                    <TableHead className="text-[11px] h-8">Method</TableHead>
                    <TableHead className="text-[11px] h-8">Service</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Shadow</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Documented</TableHead>
                    <TableHead className="text-[11px] h-8">Risk</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Auth</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displayed.slice(0, 25).map((ep, i) => (
                    <TableRow key={ep.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] font-mono py-2.5 truncate max-w-[180px] text-blue-300">
                        {ep.endpoint_path ?? "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {ep.http_method ? <MethodBadge method={ep.http_method.toUpperCase()} /> : <span className="text-muted-foreground text-[10px]">—</span>}
                      </TableCell>
                      <TableCell className="text-[10px] py-2.5 text-muted-foreground">
                        {ep.service_name || "—"}
                      </TableCell>
                      <TableCell className="text-[10px] py-2.5 text-muted-foreground capitalize">
                        {ep.api_type ?? "rest"}
                      </TableCell>
                      <TableCell className="py-2.5 text-center">
                        {ep.is_shadow ? (
                          <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">yes</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-border text-muted-foreground">no</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5 text-center">
                        {ep.is_documented ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">yes</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">no</Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <SevBadge sev={ep.risk_level ?? "none"} />
                      </TableCell>
                      <TableCell className="py-2.5 text-center">
                        {ep.auth_required ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">yes</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">no</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// HUB SHELL
// ═══════════════════════════════════════════════════════════════════════════

type TabKey = "inventory" | "management" | "discovery";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "inventory",
    label: "Inventory & OWASP",
    icon: ShieldAlert,
    description:
      "API inventory with OWASP API findings, auth-weakness analysis, and rate-limit coverage.",
  },
  {
    key: "management",
    label: "Management",
    icon: ListChecks,
    description:
      "API security engine — registered endpoints, API key inventory, and real-time abuse events.",
  },
  {
    key: "discovery",
    label: "Discovery",
    icon: Search,
    description:
      "Automated discovery of undocumented and shadow APIs with risk scoring and auth coverage.",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function APISecurityHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "inventory";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="API Security"
        description="Unified API security hero — inventory + OWASP API findings, runtime management with abuse detection, and continuous discovery of shadow endpoints."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="inventory">
          <InventoryTab />
        </TabsContent>
        <TabsContent value="management">
          <ManagementTab />
        </TabsContent>
        <TabsContent value="discovery">
          <DiscoveryTab />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
