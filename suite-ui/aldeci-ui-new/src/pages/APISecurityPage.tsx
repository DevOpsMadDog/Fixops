/**
 * API Vulnerability Management (APISecurityPage)
 *
 * All data fetched from real backend endpoints — zero hardcoded arrays.
 *
 * Endpoints used:
 *   GET /api/v1/api-security-engine/         → summary stats + endpoint list
 *   GET /api/v1/api-security-engine/stats    → KPI numbers
 *   GET /api/v1/api-security-engine/endpoints → endpoint inventory table
 *   GET /api/v1/api-security-engine/abuse-events → abuse / anomaly feed
 *   GET /api/v1/api-discovery/stats          → discovery KPIs (shadow, documented, unauthenticated)
 *   GET /api/v1/api-security/findings        → OWASP findings (empty → honest empty state)
 *
 * Route: /api-sec
 */

import { useState, useEffect, useCallback } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Activity,
  Lock,
  RefreshCw,
  Globe,
  Zap,
  Eye,
  Search,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

interface EngineStats {
  total_endpoints: number;
  public_endpoints: number;
  sensitive_endpoints: number;
  active_api_keys: number;
  abuse_events_24h: number;
  by_event_type: Record<string, number>;
  by_severity: Record<string, number>;
  critical_vulnerabilities: number;
  scan_pass_rate: number;
}

interface ApiEndpoint {
  id: string;
  org_id: string;
  endpoint_path: string;
  http_method: string;
  service_name: string;
  authentication_required: boolean;
  rate_limit_per_minute: number;
  is_public: boolean;
  sensitivity_level: string;
  status: string;
  risk_score: number;
  created_at: string;
}

interface AbuseEvent {
  id: string;
  org_id: string;
  event_type: string;
  source_ip: string;
  endpoint_id: string;
  severity: string;
  status: string;
  request_payload_preview: string;
  detected_at: string;
  created_at: string;
}

interface DiscoveryStats {
  total_endpoints: number;
  shadow_apis: number;
  documented_count: number;
  undocumented_count: number;
  by_service: Record<string, number>;
  by_method: Record<string, number>;
  unauthenticated_endpoints: number;
  total_scans: number;
  recent_changes: number;
}

interface SecurityFinding {
  id?: string;
  owasp_category?: string;
  severity?: string;
  endpoint?: string;
  description?: string;
  status?: string;
}

interface SecurityFindings {
  total: number;
  by_severity: Record<string, number>;
  findings: SecurityFinding[];
}

interface PageData {
  engineStats: EngineStats | null;
  endpoints: ApiEndpoint[];
  abuseEvents: AbuseEvent[];
  discoveryStats: DiscoveryStats | null;
  secFindings: SecurityFindings | null;
}

// ── API helpers ────────────────────────────────────────────────

function getApiKey(): string {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
    import.meta.env.VITE_API_KEY ||
    (getStoredAuthToken() ?? "")
  );
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": getApiKey() },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Sub-components ────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const norm = sev.toLowerCase();
  const cls =
    norm === "critical"
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : norm === "high"
      ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
      : norm === "medium"
      ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10"
      : "border-border text-muted-foreground bg-muted/20";
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

function SensitivityBadge({ level }: { level: string }) {
  const norm = level.toLowerCase();
  const cls =
    norm === "critical"
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : norm === "sensitive"
      ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
      : norm === "internal"
      ? "border-blue-500/30 text-blue-400 bg-blue-500/10"
      : "border-border text-muted-foreground bg-muted/20";
  return (
    <Badge className={cn("text-[10px] border capitalize", cls)}>{level}</Badge>
  );
}

function EventTypeBadge({ type }: { type: string }) {
  const label = type.replace(/_/g, " ");
  const cls =
    type === "auth_bypass" || type === "injection_attempt"
      ? "border-red-500/30 text-red-400 bg-red-500/10"
      : type === "bola_attempt" || type === "sensitive_data_exposure"
      ? "border-amber-500/30 text-amber-400 bg-amber-500/10"
      : "border-blue-500/30 text-blue-400 bg-blue-500/10";
  return (
    <Badge className={cn("text-[10px] border capitalize", cls)}>{label}</Badge>
  );
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.min(100, (score / 10) * 100);
  const color =
    score >= 8
      ? "bg-red-500"
      : score >= 5
      ? "bg-amber-500"
      : score >= 3
      ? "bg-yellow-500"
      : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 rounded-full bg-muted/40 overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] tabular-nums text-muted-foreground">{score.toFixed(1)}</span>
    </div>
  );
}

function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="p-4 space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-3">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} className="h-5 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

function EmptyState({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-3 text-center">
      <div className="rounded-full border border-border p-4 bg-muted/20">
        <Icon className="h-6 w-6 text-muted-foreground" />
      </div>
      <p className="text-sm font-medium">{title}</p>
      <p className="text-xs text-muted-foreground max-w-xs">{description}</p>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────

export default function APISecurityPage() {
  const [data, setData] = useState<PageData>({
    engineStats: null,
    endpoints: [],
    abuseEvents: [],
    discoveryStats: null,
    secFindings: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAll = useCallback(async () => {
    setError(null);
    try {
      const [statsRes, endpointsRes, abuseRes, discoveryRes, findingsRes] =
        await Promise.allSettled([
          apiFetch<EngineStats>("/api-security-engine/stats"),
          apiFetch<ApiEndpoint[]>("/api-security-engine/endpoints?org_id=default"),
          apiFetch<AbuseEvent[]>("/api-security-engine/abuse-events?org_id=default&limit=20"),
          apiFetch<DiscoveryStats>("/api-discovery/stats"),
          apiFetch<SecurityFindings>("/api-security/findings"),
        ]);

      setData({
        engineStats: statsRes.status === "fulfilled" ? statsRes.value : null,
        endpoints: endpointsRes.status === "fulfilled" ? endpointsRes.value : [],
        abuseEvents: abuseRes.status === "fulfilled" ? abuseRes.value : [],
        discoveryStats: discoveryRes.status === "fulfilled" ? discoveryRes.value : null,
        secFindings: findingsRes.status === "fulfilled" ? findingsRes.value : null,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load API security data");
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchAll().finally(() => setLoading(false));
  }, [fetchAll]);

  const handleRefresh = useCallback(() => {
    setRefreshing(true);
    fetchAll().finally(() => setRefreshing(false));
  }, [fetchAll]);

  const { engineStats, endpoints, abuseEvents, discoveryStats, secFindings } = data;

  // Derived KPIs
  const totalEndpoints =
    engineStats?.total_endpoints ?? discoveryStats?.total_endpoints ?? 0;
  const unauthCount =
    discoveryStats?.unauthenticated_endpoints ??
    endpoints.filter((e) => !e.authentication_required).length;
  const totalVulns =
    (engineStats?.by_severity?.critical ?? 0) +
    (engineStats?.by_severity?.high ?? 0) +
    (engineStats?.by_severity?.medium ?? 0);
  const abuseToday = engineStats?.abuse_events_24h ?? 0;

  // Inventory health cards derived from real data
  const inventoryHealth = discoveryStats
    ? [
        {
          label: "Total Discovered",
          value: discoveryStats.total_endpoints,
          color: "text-blue-400",
          bg: "bg-blue-500/10 border-blue-500/20",
        },
        {
          label: "Shadow APIs",
          value: discoveryStats.shadow_apis,
          color: discoveryStats.shadow_apis > 0 ? "text-red-400" : "text-green-400",
          bg:
            discoveryStats.shadow_apis > 0
              ? "bg-red-500/10 border-red-500/20"
              : "bg-green-500/10 border-green-500/20",
        },
        {
          label: "Documented",
          value: discoveryStats.documented_count,
          color: "text-purple-400",
          bg: "bg-purple-500/10 border-purple-500/20",
        },
        {
          label: "Undocumented",
          value: discoveryStats.undocumented_count,
          color: "text-amber-400",
          bg: "bg-amber-500/10 border-amber-500/20",
        },
        {
          label: "Unauthenticated",
          value: discoveryStats.unauthenticated_endpoints,
          color:
            discoveryStats.unauthenticated_endpoints > 0
              ? "text-red-400"
              : "text-green-400",
          bg:
            discoveryStats.unauthenticated_endpoints > 0
              ? "bg-red-500/10 border-red-500/20"
              : "bg-green-500/10 border-green-500/20",
        },
        {
          label: "Recent Changes",
          value: discoveryStats.recent_changes,
          color: "text-cyan-400",
          bg: "bg-cyan-500/10 border-cyan-500/20",
        },
      ]
    : [];

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3">
        <AlertTriangle className="h-8 w-8 text-red-400" />
        <p className="text-sm font-medium text-red-400">Failed to load API security data</p>
        <p className="text-xs text-muted-foreground">{error}</p>
        <Button variant="outline" size="sm" onClick={handleRefresh}>
          <RefreshCw className="h-4 w-4 mr-2" /> Retry
        </Button>
      </div>
    );
  }

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
        description="OWASP API Top 10 findings, endpoint inventory, and abuse event feed"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={refreshing || loading}
          >
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {loading ? (
          <>
            <Skeleton className="h-24 rounded-lg" />
            <Skeleton className="h-24 rounded-lg" />
            <Skeleton className="h-24 rounded-lg" />
            <Skeleton className="h-24 rounded-lg" />
          </>
        ) : (
          <>
            <KpiCard title="APIs Inventoried" value={totalEndpoints} icon={Globe} />
            <KpiCard
              title="Unauthenticated"
              value={unauthCount}
              icon={Lock}
              trend={unauthCount > 0 ? "up" : undefined}
              className={unauthCount > 0 ? "border-red-500/20" : undefined}
            />
            <KpiCard
              title="Vulnerabilities"
              value={totalVulns}
              icon={AlertTriangle}
              trend={totalVulns > 0 ? "up" : undefined}
              className={totalVulns > 0 ? "border-amber-500/20" : undefined}
            />
            <KpiCard
              title="Abuse Events (24h)"
              value={abuseToday}
              icon={Activity}
              trend={abuseToday > 0 ? "up" : undefined}
              className={abuseToday > 0 ? "border-yellow-500/20" : undefined}
            />
          </>
        )}
      </div>

      {/* OWASP findings — real data, honest empty state if none */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-red-400" />
            OWASP API Security Findings
          </CardTitle>
          <CardDescription className="text-xs">
            Active findings mapped to OWASP API Top 10 categories
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <TableSkeleton rows={5} cols={5} />
          ) : !secFindings || secFindings.findings.length === 0 ? (
            <EmptyState
              icon={Shield}
              title="No OWASP findings"
              description="Run an API security scan to populate OWASP API Top 10 findings. Use POST /api/v1/api-security/scan to trigger."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">OWASP Category</TableHead>
                    <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Description</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {secFindings.findings.map((f, i) => (
                    <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground whitespace-nowrap">
                        {f.owasp_category ?? "—"}
                      </TableCell>
                      <TableCell className="text-[10px] font-mono py-2.5 max-w-[200px] truncate text-blue-300">
                        {f.endpoint ?? "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        {f.severity ? <SeverityBadge sev={f.severity} /> : "—"}
                      </TableCell>
                      <TableCell className="text-xs py-2.5 max-w-[240px] truncate">
                        {f.description ?? "—"}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <Badge className="text-[10px] border border-border text-muted-foreground capitalize">
                          {f.status ?? "unknown"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Endpoint inventory */}
      <Card className="border-amber-500/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Eye className="h-4 w-4 text-blue-400" />
              API Endpoint Inventory
            </CardTitle>
            {!loading && (
              <Badge className="text-[10px] border border-border text-muted-foreground">
                {endpoints.length} endpoint{endpoints.length !== 1 ? "s" : ""}
              </Badge>
            )}
          </div>
          <CardDescription className="text-xs">
            All monitored API endpoints with risk scores and sensitivity classification
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <TableSkeleton rows={8} cols={6} />
          ) : endpoints.length === 0 ? (
            <EmptyState
              icon={Search}
              title="No endpoints discovered"
              description="Register endpoints via POST /api/v1/api-security-engine/endpoints or run an API discovery scan."
            />
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Endpoint</TableHead>
                    <TableHead className="text-[11px] h-8">Method</TableHead>
                    <TableHead className="text-[11px] h-8">Service</TableHead>
                    <TableHead className="text-[11px] h-8">Sensitivity</TableHead>
                    <TableHead className="text-[11px] h-8">Auth</TableHead>
                    <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {endpoints.map((ep) => (
                    <TableRow key={ep.id} className="hover:bg-muted/30">
                      <TableCell className="text-[10px] font-mono py-2.5 max-w-[220px] truncate text-blue-300">
                        {ep.endpoint_path}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <MethodBadge method={ep.http_method} />
                      </TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">
                        {ep.service_name}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <SensitivityBadge level={ep.sensitivity_level} />
                      </TableCell>
                      <TableCell className="py-2.5">
                        {ep.authentication_required ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                            required
                          </Badge>
                        ) : (
                          <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                            none
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="py-2.5">
                        <RiskBar score={ep.risk_score} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Abuse event feed + Inventory health */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

        {/* Abuse event feed */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                Abuse Event Feed
              </CardTitle>
              {!loading && abuseEvents.length > 0 && (
                <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                  {abuseEvents.filter((e) => e.severity === "critical").length} critical
                </Badge>
              )}
            </div>
            <CardDescription className="text-xs">
              Detected API abuse attempts — injection, BOLA, auth bypass, rate-limit breaches
            </CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <TableSkeleton rows={5} cols={4} />
            ) : abuseEvents.length === 0 ? (
              <EmptyState
                icon={Activity}
                title="No abuse events detected"
                description="Abuse detection data will appear here as your API endpoints are monitored."
              />
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Source IP</TableHead>
                      <TableHead className="text-[11px] h-8">Type</TableHead>
                      <TableHead className="text-[11px] h-8">Severity</TableHead>
                      <TableHead className="text-[11px] h-8">Detected</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {abuseEvents.map((ev) => (
                      <TableRow key={ev.id} className="hover:bg-muted/30">
                        <TableCell className="text-[10px] font-mono py-2 text-muted-foreground">
                          {ev.source_ip}
                        </TableCell>
                        <TableCell className="py-2">
                          <EventTypeBadge type={ev.event_type} />
                        </TableCell>
                        <TableCell className="py-2">
                          <SeverityBadge sev={ev.severity} />
                        </TableCell>
                        <TableCell className="text-[10px] py-2 text-muted-foreground tabular-nums whitespace-nowrap">
                          {new Date(ev.detected_at).toLocaleString(undefined, {
                            month: "short",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {abuseEvents.length > 0 && (
                  <div className="px-4 py-2 border-t border-border">
                    <p className="text-[10px] text-muted-foreground truncate" title={abuseEvents[0].request_payload_preview}>
                      Latest: {abuseEvents[0].request_payload_preview}
                    </p>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* API inventory health (from discovery stats) */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Zap className="h-4 w-4 text-purple-400" />
              API Inventory Health
            </CardTitle>
            <CardDescription className="text-xs">
              Discovery coverage — shadow APIs, documentation, and authentication status
            </CardDescription>
          </CardHeader>
          <CardContent>
            {loading ? (
              <div className="grid grid-cols-2 gap-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <Skeleton key={i} className="h-20 rounded-lg" />
                ))}
              </div>
            ) : inventoryHealth.length === 0 ? (
              <EmptyState
                icon={Zap}
                title="No discovery data"
                description="Run an API discovery scan to populate inventory health metrics."
              />
            ) : (
              <div className="grid grid-cols-2 gap-3">
                {inventoryHealth.map((stat) => (
                  <div
                    key={stat.label}
                    className={cn(
                      "rounded-lg border p-4 flex flex-col gap-1",
                      stat.bg
                    )}
                  >
                    <span className={cn("text-2xl font-bold tabular-nums", stat.color)}>
                      {stat.value}
                    </span>
                    <span className="text-[11px] text-muted-foreground">{stat.label}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* By-severity summary bar (from engine stats) */}
      {!loading && engineStats && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Vulnerability Severity Summary
            </CardTitle>
            <CardDescription className="text-xs">
              Distribution across all monitored API endpoints — scan pass rate:{" "}
              <span className="font-semibold text-foreground">
                {engineStats.scan_pass_rate.toFixed(1)}%
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              {Object.entries(engineStats.by_severity).length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No severity data — run a security scan to populate.
                </p>
              ) : (
                Object.entries(engineStats.by_severity)
                  .sort(([a], [b]) => {
                    const order = ["critical", "high", "medium", "low", "info"];
                    return order.indexOf(a) - order.indexOf(b);
                  })
                  .map(([sev, count]) => (
                    <div
                      key={sev}
                      className="flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-4 py-3"
                    >
                      <SeverityBadge sev={sev} />
                      <span className="text-lg font-bold tabular-nums">{count}</span>
                    </div>
                  ))
              )}
              {engineStats.by_event_type && Object.keys(engineStats.by_event_type).length > 0 && (
                <div className="w-full mt-2 pt-3 border-t border-border">
                  <p className="text-[11px] text-muted-foreground mb-2">Abuse event types detected:</p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(engineStats.by_event_type).map(([type, count]) => (
                      <div key={type} className="flex items-center gap-1.5">
                        <EventTypeBadge type={type} />
                        <span className="text-xs tabular-nums font-bold">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
