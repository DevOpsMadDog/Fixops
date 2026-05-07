/**
 * CISO Executive Dashboard — board-level security posture landing page
 * Route: /executive
 * Persona: P01 (CISO / exec)
 *
 * APIs wired (no mocks):
 *   GET /api/v1/analytics/dashboard/overview  — findings counts + risk score
 *   GET /api/v1/analytics/dashboard/summary   — severity breakdown
 *   GET /api/v1/risk/top?n=5                  — top 5 risks
 *   GET /api/v1/compliance/status             — framework posture
 *   GET /api/v1/exec-reporting/summary        — MTTR / exec summary
 *   GET /api/v1/exec-reporting/kpis           — KPI list
 */

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  AlertTriangle,
  TrendingDown,
  TrendingUp,
  RefreshCw,
  Clock,
  Target,
  FileBarChart,
  Activity,
  CheckCircle,
  XCircle,
  AlertCircle,
  Gauge,
  BarChart3,
  Lock,
  ChevronRight,
} from "lucide-react";
import { Link } from "react-router-dom";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { HealthCardWidget } from "@/components/HealthCardWidget";
import { CouncilVerdictsCard } from "@/components/exec/CouncilVerdictsCard";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─── Types ───────────────────────────────────────────────────────────────────

interface DashboardOverview {
  org_id?: string;
  total_findings?: number;
  open_findings?: number;
  resolved_findings?: number;
  critical_count?: number;
  high_count?: number;
  risk_score?: number;
  risk_level?: string;
  scanners_active?: number;
  last_scan?: string;
  severity?: Record<string, number>;
}

interface TopRisk {
  id?: string;
  title?: string;
  description?: string;
  score?: number;
  severity?: string;
  asset?: string;
  cve?: string;
}

interface TopRisksResponse {
  top_risks?: TopRisk[];
  items?: TopRisk[];
}

interface ComplianceFramework {
  framework?: string;
  name?: string;
  score?: number;
  passed?: number;
  failed?: number;
  total?: number;
  status?: string;
}

interface ComplianceStatus {
  frameworks?: ComplianceFramework[];
  items?: ComplianceFramework[];
  overall_score?: number;
}

interface ExecKPI {
  name?: string;
  kpi_name?: string;
  value?: string | number;
  unit?: string;
  trend?: string;
}

interface ExecSummary {
  org_id?: string;
  mttr_hours?: number;
  mttd_hours?: number;
  sla_compliance_pct?: number;
  remediation_rate_pct?: number;
  open_incidents?: number;
  critical_incidents?: number;
  risk_score?: number;
  top_risks?: TopRisk[];
}

// ─── API helpers ─────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(buildApiUrl(path), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
    });
    if (res.status === 404 || res.status === 501) return null;
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function riskColor(score?: number) {
  if (score === undefined || score === null) return "text-muted-foreground";
  if (score >= 75) return "text-red-400";
  if (score >= 50) return "text-orange-400";
  if (score >= 25) return "text-yellow-400";
  return "text-green-400";
}

function riskBg(score?: number) {
  if (score === undefined || score === null) return "bg-muted";
  if (score >= 75) return "bg-red-500/15 border-red-500/30";
  if (score >= 50) return "bg-orange-500/15 border-orange-500/30";
  if (score >= 25) return "bg-yellow-500/15 border-yellow-500/30";
  return "bg-green-500/15 border-green-500/30";
}

function severityBadgeClass(sev?: string) {
  const s = (sev ?? "").toLowerCase();
  if (s === "critical") return "bg-red-500/15 text-red-400 border-red-500/30";
  if (s === "high") return "bg-orange-500/15 text-orange-400 border-orange-500/30";
  if (s === "medium") return "bg-yellow-500/15 text-yellow-400 border-yellow-500/30";
  return "bg-blue-500/15 text-blue-400 border-blue-500/30";
}

function complianceColor(score?: number) {
  if (score === undefined) return "text-muted-foreground";
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  return "text-red-400";
}

function fmtHours(h?: number) {
  if (h === undefined || h === null) return "—";
  if (h < 1) return `${Math.round(h * 60)}m`;
  if (h < 24) return `${h.toFixed(1)}h`;
  return `${(h / 24).toFixed(1)}d`;
}

function fmtPct(v?: number) {
  if (v === undefined || v === null) return "—";
  return `${Math.round(v)}%`;
}

// ─── Skeleton strip ───────────────────────────────────────────────────────────

function KpiSkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      {Array.from({ length: 6 }).map((_, i) => (
        <Card key={i} className="p-5">
          <Skeleton className="h-3 w-24 mb-3" />
          <Skeleton className="h-7 w-16 mb-1" />
          <Skeleton className="h-2.5 w-20" />
        </Card>
      ))}
    </div>
  );
}

// ─── Risk gauge ring ─────────────────────────────────────────────────────────

function RiskGauge({ score }: { score?: number }) {
  const pct = Math.min(100, Math.max(0, score ?? 0));
  const r = 40;
  const circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  const label = pct >= 75 ? "CRITICAL" : pct >= 50 ? "HIGH" : pct >= 25 ? "MEDIUM" : "LOW";
  const stroke = pct >= 75 ? "#f87171" : pct >= 50 ? "#fb923c" : pct >= 25 ? "#fbbf24" : "#4ade80";

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={100} height={100} viewBox="0 0 100 100" className="-rotate-90">
        <circle cx={50} cy={50} r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth={10} />
        <circle
          cx={50} cy={50} r={r}
          fill="none"
          stroke={stroke}
          strokeWidth={10}
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.16,1,0.3,1)" }}
        />
      </svg>
      <div className="flex flex-col items-center -mt-[72px] mb-6">
        <span className={cn("text-2xl font-black tabular-nums", riskColor(score))}>
          {score?.toFixed(0) ?? "—"}
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground mt-px">
          {label}
        </span>
      </div>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function CISODashboard() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [topRisks, setTopRisks] = useState<TopRisk[]>([]);
  const [compliance, setCompliance] = useState<ComplianceFramework[]>([]);
  const [execSummary, setExecSummary] = useState<ExecSummary | null>(null);
  const [kpis, setKpis] = useState<ExecKPI[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const load = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);

    const [ov, summary, risks, comp, execSum, kpiList] = await Promise.all([
      apiFetch<DashboardOverview>("/api/v1/analytics/dashboard/overview"),
      apiFetch<DashboardOverview>("/api/v1/analytics/dashboard/summary"),
      apiFetch<TopRisksResponse>("/api/v1/risk/top?n=5"),
      apiFetch<ComplianceStatus>("/api/v1/compliance/status"),
      apiFetch<ExecSummary>("/api/v1/exec-reporting/summary"),
      apiFetch<{ items?: ExecKPI[]; kpis?: ExecKPI[] }>("/api/v1/exec-reporting/kpis"),
    ]);

    // Merge overview + summary (summary has severity breakdown, overview has org context)
    const merged: DashboardOverview = {
      ...(ov ?? {}),
      ...(summary ?? {}),
    };
    setOverview(merged);

    const riskItems = risks?.top_risks ?? risks?.items ?? [];
    setTopRisks(riskItems);

    const compItems = comp?.frameworks ?? comp?.items ?? [];
    setCompliance(compItems);

    setExecSummary(execSum);
    setKpis(kpiList?.items ?? kpiList?.kpis ?? []);

    setLastRefresh(new Date());
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  // ── Derived KPI values ──
  const totalFindings = overview?.total_findings ?? 0;
  const openFindings = overview?.open_findings ?? 0;
  const criticalCount = overview?.severity?.critical ?? overview?.critical_count ?? 0;
  const highCount = overview?.severity?.high ?? overview?.high_count ?? 0;
  const riskScore = overview?.risk_score ?? execSummary?.risk_score;
  const mttr = execSummary?.mttr_hours;
  const mttd = execSummary?.mttd_hours;
  const slaCompliance = execSummary?.sla_compliance_pct;
  const remediationRate = execSummary?.remediation_rate_pct;

  // Derive overall compliance % from framework scores
  const avgCompliance = compliance.length > 0
    ? Math.round(compliance.reduce((acc, f) => acc + (f.score ?? 0), 0) / compliance.length)
    : undefined;

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <div className="flex items-start justify-between">
          <div>
            <Skeleton className="h-7 w-56 mb-2" />
            <Skeleton className="h-4 w-80" />
          </div>
          <Skeleton className="h-8 w-28" />
        </div>
        <KpiSkeleton />
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
      className="flex flex-col gap-6"
    >
      {/* ── Page header + Health widget ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold tracking-tight">CISO Dashboard</h1>
            <Badge className="text-[10px] bg-cyan-500/15 text-cyan-400 border border-cyan-500/25 font-semibold">
              P01
            </Badge>
            <Badge className="text-[10px] bg-violet-500/15 text-violet-400 border border-violet-500/25 font-semibold">
              EXECUTIVE
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Board-level security posture — real-time risk, compliance, and threat intelligence
          </p>
        </div>
        <div className="flex flex-col gap-2 min-w-0">
          <div className="flex items-center gap-2 flex-wrap justify-end">
            <span className="text-[11px] text-muted-foreground">
              <Clock className="inline h-3 w-3 mr-1" />
              {lastRefresh.toLocaleTimeString()}
            </span>
            <Button variant="outline" size="sm" onClick={() => load(true)} disabled={refreshing}>
              <RefreshCw className={cn("h-3.5 w-3.5 mr-1.5", refreshing && "animate-spin")} />
              Refresh
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/comply/reports">
                <FileBarChart className="h-3.5 w-3.5 mr-1.5" />
                Executive Report
              </Link>
            </Button>
          </div>
          <div className="w-full md:min-w-[320px]">
            <HealthCardWidget />
          </div>
        </div>
      </div>

      {/* ── KPI strip — 6 cards ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <KpiCard
          title="Total Findings"
          value={totalFindings}
          icon={AlertTriangle}
          description="All severities"
        />
        <KpiCard
          title="Open Findings"
          value={openFindings}
          icon={AlertCircle}
          trend="down"
          trendLabel={totalFindings > 0 ? `${Math.round((openFindings / totalFindings) * 100)}% of total` : undefined}
        />
        <KpiCard
          title="Critical"
          value={criticalCount}
          icon={XCircle}
          trend="down"
          trendLabel={criticalCount > 0 ? "Needs attention" : "Clean"}
        />
        <KpiCard
          title="High"
          value={highCount}
          icon={AlertTriangle}
          trend="down"
        />
        <KpiCard
          title="MTTR"
          value={mttr !== undefined ? fmtHours(mttr) : "—"}
          icon={Clock}
          description="Mean time to remediate"
        />
        <KpiCard
          title="Compliance"
          value={avgCompliance !== undefined ? `${avgCompliance}%` : "—"}
          icon={ShieldCheck}
          trend={avgCompliance !== undefined ? (avgCompliance >= 80 ? "up" : "down") : undefined}
          trendLabel={avgCompliance !== undefined ? (avgCompliance >= 80 ? "Passing" : "Needs work") : undefined}
        />
      </div>

      {/* ── 4-quadrant grid ── */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">

        {/* Q1 — Risk Posture */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Gauge className="h-4 w-4 text-primary" />
              Risk Posture
            </CardTitle>
            <CardDescription className="text-xs">
              Composite risk score across all findings and assets
            </CardDescription>
          </CardHeader>
          <CardContent>
            {riskScore === undefined && !loading ? (
              <EmptyState
                icon={Gauge}
                title="No risk score yet"
                description="Run a scan or trigger risk recompute to populate this panel."
              />
            ) : (
              <div className="flex items-start gap-6">
                <RiskGauge score={riskScore} />
                <div className="flex-1 space-y-3 pt-1">
                  {/* Severity breakdown bars */}
                  {(["critical", "high", "medium", "low"] as const).map((sev) => {
                    const count = overview?.severity?.[sev] ?? 0;
                    const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="capitalize text-muted-foreground">{sev}</span>
                          <span className="font-mono font-semibold">{count}</span>
                        </div>
                        <Progress
                          value={pct}
                          className={cn("h-1.5", {
                            "[&>div]:bg-red-500": sev === "critical",
                            "[&>div]:bg-orange-400": sev === "high",
                            "[&>div]:bg-yellow-400": sev === "medium",
                            "[&>div]:bg-blue-400": sev === "low",
                          })}
                        />
                      </div>
                    );
                  })}
                  <div className="pt-1 border-t border-border flex items-center justify-between text-xs text-muted-foreground">
                    <span>Remediation Progress</span>
                    <span className="font-mono font-semibold text-green-400">
                      {remediationRate !== undefined ? fmtPct(remediationRate) : (
                        totalFindings > 0 ? fmtPct(((totalFindings - openFindings) / totalFindings) * 100) : "—"
                      )}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Q2 — Top Risks */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Target className="h-4 w-4 text-red-400" />
              Top Risks
            </CardTitle>
            <CardDescription className="text-xs">
              Highest-impact vulnerabilities requiring board attention
            </CardDescription>
          </CardHeader>
          <CardContent>
            {topRisks.length === 0 ? (
              <EmptyState
                icon={Target}
                title="No risk data yet"
                description="Risk scoring runs after the first scan completes."
              />
            ) : (
              <div className="space-y-2">
                {topRisks.slice(0, 5).map((risk, i) => (
                  <div
                    key={risk.id ?? i}
                    className={cn(
                      "flex items-start gap-3 rounded-lg border p-3 transition-colors",
                      riskBg(risk.score)
                    )}
                  >
                    <span className="mt-0.5 text-xs font-bold text-muted-foreground tabular-nums w-4 shrink-0">
                      {i + 1}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-xs font-semibold truncate max-w-[180px]">
                          {risk.title ?? risk.cve ?? "Unknown risk"}
                        </span>
                        {risk.severity && (
                          <Badge className={cn("text-[9px] border", severityBadgeClass(risk.severity))}>
                            {risk.severity.toUpperCase()}
                          </Badge>
                        )}
                      </div>
                      {(risk.asset || risk.description) && (
                        <p className="text-[11px] text-muted-foreground mt-0.5 truncate">
                          {risk.asset ?? risk.description}
                        </p>
                      )}
                    </div>
                    <span className={cn("text-sm font-black tabular-nums shrink-0", riskColor(risk.score))}>
                      {risk.score?.toFixed(0) ?? "—"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Q3 — Compliance Scorecard */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-green-400" />
              Compliance Status
            </CardTitle>
            <CardDescription className="text-xs">
              Framework coverage across SOC 2, PCI, HIPAA, ISO 27001 and more
            </CardDescription>
          </CardHeader>
          <CardContent>
            {compliance.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="No compliance data"
                description="Connect a compliance framework and run evidence collection to populate this panel."
              />
            ) : (
              <div className="space-y-3">
                {compliance.slice(0, 6).map((fw, i) => {
                  const pct = fw.score ?? (
                    fw.total && fw.total > 0
                      ? Math.round(((fw.passed ?? 0) / fw.total) * 100)
                      : undefined
                  );
                  const name = fw.name ?? fw.framework ?? `Framework ${i + 1}`;
                  const passing = pct !== undefined && pct >= 70;
                  return (
                    <div key={fw.framework ?? i} className="space-y-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-1.5 min-w-0">
                          {passing ? (
                            <CheckCircle className="h-3 w-3 text-green-400 shrink-0" />
                          ) : (
                            <AlertCircle className="h-3 w-3 text-orange-400 shrink-0" />
                          )}
                          <span className="text-xs font-medium truncate">{name}</span>
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums shrink-0", complianceColor(pct))}>
                          {pct !== undefined ? `${pct}%` : "—"}
                        </span>
                      </div>
                      <Progress
                        value={pct ?? 0}
                        className={cn("h-1.5", pct !== undefined && pct >= 80
                          ? "[&>div]:bg-green-500"
                          : pct !== undefined && pct >= 60
                            ? "[&>div]:bg-yellow-500"
                            : "[&>div]:bg-red-500"
                        )}
                      />
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Q4 — Exec KPIs / Upcoming */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              Security KPIs
            </CardTitle>
            <CardDescription className="text-xs">
              Operational metrics — MTTD, MTTR, SLA compliance, detection accuracy
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-0 divide-y divide-border">
              {/* Always show exec-summary derived KPIs first */}
              {[
                {
                  label: "MTTD",
                  value: mttd !== undefined ? fmtHours(mttd) : "—",
                  icon: Clock,
                  good: mttd !== undefined && mttd < 24,
                },
                {
                  label: "MTTR",
                  value: mttr !== undefined ? fmtHours(mttr) : "—",
                  icon: Activity,
                  good: mttr !== undefined && mttr < 72,
                },
                {
                  label: "SLA Compliance",
                  value: slaCompliance !== undefined ? fmtPct(slaCompliance) : "—",
                  icon: ShieldCheck,
                  good: slaCompliance !== undefined && slaCompliance >= 90,
                },
                {
                  label: "Remediation Rate",
                  value: remediationRate !== undefined ? fmtPct(remediationRate) : (
                    totalFindings > 0 ? fmtPct(((totalFindings - openFindings) / totalFindings) * 100) : "—"
                  ),
                  icon: TrendingDown,
                  good: remediationRate !== undefined ? remediationRate >= 80 : false,
                },
                {
                  label: "Open Incidents",
                  value: execSummary?.open_incidents ?? "—",
                  icon: AlertTriangle,
                  good: (execSummary?.open_incidents ?? 99) === 0,
                },
                {
                  label: "Active Scanners",
                  value: overview?.scanners_active ?? "—",
                  icon: Lock,
                  good: (overview?.scanners_active ?? 0) > 0,
                },
                // Dynamic KPIs from exec-reporting/kpis endpoint
                ...kpis.slice(0, 4).map((kpi) => ({
                  label: kpi.name ?? kpi.kpi_name ?? "KPI",
                  value: kpi.unit ? `${kpi.value}${kpi.unit}` : (kpi.value ?? "—"),
                  icon: BarChart3,
                  good: undefined as boolean | undefined,
                })),
              ]
                .slice(0, 8)
                .map((item, i) => (
                  <div key={item.label + i} className="flex items-center justify-between py-2.5 gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <item.icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      <span className="text-xs text-muted-foreground truncate">{item.label}</span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-xs font-bold tabular-nums">
                        {typeof item.value === "number" ? item.value.toLocaleString() : item.value}
                      </span>
                      {item.good !== undefined && (
                        item.good ? (
                          <TrendingUp className="h-3 w-3 text-green-400" />
                        ) : (
                          <TrendingDown className="h-3 w-3 text-orange-400" />
                        )
                      )}
                    </div>
                  </div>
                ))}

              {/* Links to drill-down pages */}
              <div className="pt-3 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" asChild className="h-7 text-[11px]">
                  <Link to="/mission-control/risk">
                    Risk Details <ChevronRight className="h-3 w-3 ml-0.5" />
                  </Link>
                </Button>
                <Button variant="outline" size="sm" asChild className="h-7 text-[11px]">
                  <Link to="/comply/coverage">
                    Compliance <ChevronRight className="h-3 w-3 ml-0.5" />
                  </Link>
                </Button>
                <Button variant="outline" size="sm" asChild className="h-7 text-[11px]">
                  <Link to="/discover">
                    All Findings <ChevronRight className="h-3 w-3 ml-0.5" />
                  </Link>
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── LLM Council Verdicts ── */}
      <CouncilVerdictsCard />
    </motion.div>
  );
}
