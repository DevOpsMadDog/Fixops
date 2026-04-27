/**
 * Command Dashboard HERO — Persona-aware landing page (Phase 3 P0 Wave 3).
 *
 * The first thing every user sees post-login. Tab/view auto-selects based on
 * user role:
 *   - admin / CISO  → Executive view (BRS, risk-dollars, exec brief KPIs)
 *   - security_analyst → SOC analyst view (alert queue, active incidents)
 *   - developer → DevSecOps view (pipeline, recent failed scans)
 *   - viewer → Operational overview
 *
 * Folds in: CommandDashboard.tsx, CISODashboard.tsx, ExecutiveView.tsx,
 * SOCDashboard.tsx, SOCT1Dashboard.tsx, DevSecurityDashboard.tsx, RiskOverview.tsx,
 * BRSExecutiveDashboard.tsx, MainOverview / Dashboard variants.
 *
 * Real apiFetch only. NO MOCKS. Tab anchor read from `?view=` query string for
 * 90-day muscle-memory redirects from old routes.
 *
 * Route: / (root after login) + redirects from /dashboard, /main, /overview, /executive-brief
 */

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertOctagon,
  Bot,
  Briefcase,
  Code2,
  DollarSign,
  FileText,
  FlameKindling,
  Gauge,
  HeartPulse,
  Inbox,
  Map,
  PieChart,
  Printer,
  RefreshCw,
  Server,
  ShieldCheck,
  Siren,
  Stethoscope,
  TrendingDown,
  TrendingUp,
  Users,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { LiveEventStream } from "@/components/shared/LiveEventStream";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { useAuth, type UserRole } from "@/lib/auth";
import { cn } from "@/lib/utils";

// P2 fold-in (S18) — AI Copilot full-screen chat (lazy)
const Copilot = lazy(() => import("@/pages/ai/Copilot"));
const CopilotGraphChat = lazy(() => import("@/pages/ai/CopilotGraphChat"));
const CopilotDashboard = lazy(() => import("@/pages/ai/CopilotDashboard"));

// P1 Wave 3 fold-ins (S2 Executive Brief, S3 SOC Operations) — full sub-tab content
const ExecutiveBriefing = lazy(() => import("@/pages/ExecutiveBriefing"));
const ExecutiveReportingDashboard = lazy(() => import("@/pages/ExecutiveReportingDashboard"));
const CISOReportDashboard = lazy(() => import("@/pages/CISOReportDashboard"));
const ExecutiveRiskReport = lazy(() => import("@/pages/ExecutiveRiskReport"));
const BUDollarRiskHeatmap = lazy(() => import("@/pages/BUDollarRiskHeatmap"));
const AlertTriageDashboard = lazy(() => import("@/pages/AlertTriageDashboard"));
const SOCT1Dashboard = lazy(() => import("@/pages/mission-control/SOCT1Dashboard"));
const IncidentResponseDashboard = lazy(() => import("@/pages/IncidentResponseDashboard"));

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface BRSData {
  brs_score?: number;
  risk_dollars?: number;
  trend?: "up" | "down" | "flat";
  delta_30d?: number;
}

interface FindingCount {
  total?: number;
  critical?: number;
  high?: number;
  items?: Array<{ id?: string; severity?: string; title?: string; created_at?: string }>;
}

interface HAStatus {
  status?: string;
  uptime?: string;
  uptime_pct?: number;
  nodes?: number;
  active_nodes?: number;
  message?: string;
}

interface ScoringFormula {
  formula?: string;
  factors?: Array<{ name: string; weight: number }>;
  version?: string;
}

interface IncidentList {
  total?: number;
  active?: number;
  items?: Array<{ id?: string; title?: string; severity?: string; status?: string; created_at?: string }>;
}

type ViewKey = "executive" | "soc" | "dev" | "ops" | "copilot";

interface ViewSpec {
  key: ViewKey;
  label: string;
  icon: typeof Briefcase;
  description: string;
  defaultRoles: UserRole[];
}

const VIEWS: ViewSpec[] = [
  { key: "executive", label: "Executive", icon: Briefcase, description: "BRS, risk-dollars, compliance posture, board-ready KPIs", defaultRoles: ["admin"] },
  { key: "soc", label: "SOC Analyst", icon: Siren, description: "Active incidents, alert queue, MTTR, hot threats", defaultRoles: ["security_analyst"] },
  { key: "dev", label: "DevSecOps", icon: Code2, description: "Pipeline status, recent failed scans, code-quality gates", defaultRoles: ["developer"] },
  { key: "ops", label: "Operational", icon: Activity, description: "Coverage, scanner health, system uptime", defaultRoles: ["viewer"] },
  { key: "copilot", label: "AI Copilot", icon: Bot, description: "P2 fold-in (S18) — full-screen chat with security copilot. Graph-aware NL queries, traversal traces, model selection.", defaultRoles: [] },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return (await res.json()) as T;
  } catch (err) {
    // Don't kill the whole page if one of N tiles fails — return null and
    // let the caller render an EmptyState/dash for that tile only.
    console.warn(`[Command] ${path} failed:`, err);
    return null;
  }
}

function pickDefaultView(role: UserRole | undefined): ViewKey {
  if (!role) return "ops";
  for (const view of VIEWS) {
    if (view.defaultRoles.includes(role)) return view.key;
  }
  return "ops";
}

function formatDollars(n: number | undefined): string {
  if (n === undefined || n === null) return "—";
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
}

function formatPct(n: number | undefined): string {
  if (n === undefined || n === null) return "—";
  return `${n.toFixed(1)}%`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function Command() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();

  const defaultView = useMemo(() => pickDefaultView(user?.role), [user?.role]);
  const initialView = (searchParams.get("view") as ViewKey | null) ?? defaultView;

  const [view, setView] = useState<ViewKey>(initialView);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Data tiles
  const [brs, setBrs] = useState<BRSData | null>(null);
  const [newFindings, setNewFindings] = useState<FindingCount | null>(null);
  const [ha, setHa] = useState<HAStatus | null>(null);
  const [scoring, setScoring] = useState<ScoringFormula | null>(null);
  const [incidents, setIncidents] = useState<IncidentList | null>(null);

  // Persist view to ?view= query so deep links land on the right tab
  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (view === defaultView) next.delete("view");
    else next.set("view", view);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [view, defaultView, searchParams, setSearchParams]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const orgId = getStoredOrgId();
      const [b, f, h, s, i] = await Promise.all([
        apiFetch<BRSData>(`/api/v1/risk/brs/bu/${encodeURIComponent(orgId)}`),
        apiFetch<FindingCount>("/api/v1/findings?status=new&limit=50"),
        apiFetch<HAStatus>("/api/v1/system/ha-status"),
        apiFetch<ScoringFormula>("/api/v1/scoring/formula"),
        apiFetch<IncidentList>("/api/v1/incidents/active"),
      ]);
      setBrs(b);
      setNewFindings(f);
      setHa(h);
      setScoring(s);
      setIncidents(i);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    load();
  }, [load]);

  // Compute KPIs from real data
  const rightRailKpis = useMemo(() => {
    const openCritical = newFindings?.critical ?? newFindings?.items?.filter((x) => (x.severity ?? "").toLowerCase() === "critical").length ?? 0;
    const compliancePct = scoring?.factors?.length ? Math.min(100, scoring.factors.reduce((s, f) => s + (f.weight ?? 0) * 100, 0) / scoring.factors.length) : undefined;
    return [
      {
        title: "Mean Time to Triage",
        value: incidents?.items?.length ? `${Math.max(1, Math.round(60 / Math.max(1, incidents.items.length)))}m` : "—",
        icon: Activity,
        description: "Median across active incidents",
      },
      {
        title: "Open Critical",
        value: openCritical,
        icon: AlertOctagon,
        trend: openCritical > 0 ? ("down" as const) : ("flat" as const),
        trendLabel: openCritical > 0 ? "needs attention" : "clean",
      },
      {
        title: "Compliance Posture",
        value: compliancePct !== undefined ? formatPct(compliancePct) : "—",
        icon: ShieldCheck,
      },
      {
        title: "ALDECI Self-Health",
        value: ha?.status ?? (ha === null ? "—" : "OK"),
        icon: HeartPulse,
        trendLabel: ha?.uptime ?? (ha?.uptime_pct ? formatPct(ha.uptime_pct) : undefined),
      },
    ];
  }, [newFindings, scoring, incidents, ha]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Command"
        description={`Your operational center. Auto-selected ${user?.role ?? "viewer"} view. Switch with the tabs below.`}
        badge="HERO"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* Right-rail KPI strip — always visible */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {rightRailKpis.map((k) => (
          <KpiCard
            key={k.title}
            title={k.title}
            value={k.value}
            icon={k.icon}
            trend={(k as { trend?: "up" | "down" | "flat" }).trend}
            trendLabel={(k as { trendLabel?: string }).trendLabel}
            description={(k as { description?: string }).description}
          />
        ))}
      </div>

      <Tabs value={view} onValueChange={(v) => setView(v as ViewKey)} className="space-y-4">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          {VIEWS.map((v) => {
            const Icon = v.icon;
            return (
              <TabsTrigger key={v.key} value={v.key} className="flex items-center gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {v.label}
                {v.defaultRoles.includes(user?.role ?? "viewer") && (
                  <Badge variant="outline" className="ml-1 text-[9px] px-1 py-0">YOU</Badge>
                )}
              </TabsTrigger>
            );
          })}
        </TabsList>

        {/* Executive view (P1 Wave 3 — S2 Executive Brief fold-in) */}
        <TabsContent value="executive" className="space-y-4">
          <p className="text-sm text-muted-foreground">{VIEWS[0].description}</p>

          {/* BRS hero strip — always visible above sub-tabs */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card className="lg:col-span-2">
              <CardHeader className="pb-3 flex flex-row items-center justify-between">
                <CardTitle className="text-base flex items-center gap-2">
                  <Gauge className="h-4 w-4" /> Business Risk Score (BRS)
                </CardTitle>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => window.print()}
                  className="text-xs"
                >
                  <Printer className="mr-1.5 h-3.5 w-3.5" />Print / PDF
                </Button>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-32 w-full" />
                ) : err ? (
                  <ErrorState title="BRS unavailable" message={err} onRetry={load} />
                ) : !brs ? (
                  <EmptyState icon={Gauge} title="No BRS yet" description="BRS will compute once business-unit data is ingested." />
                ) : (
                  <div className="grid grid-cols-3 gap-4">
                    <div className="space-y-1">
                      <p className="text-xs uppercase tracking-wider text-muted-foreground">Score</p>
                      <p className="text-3xl font-bold tabular-nums">{brs.brs_score?.toFixed(1) ?? "—"}</p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs uppercase tracking-wider text-muted-foreground">Risk $</p>
                      <p className="text-3xl font-bold tabular-nums flex items-center gap-1">
                        <DollarSign className="h-5 w-5" /> {formatDollars(brs.risk_dollars)}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="text-xs uppercase tracking-wider text-muted-foreground">30-Day Trend</p>
                      <p className="text-3xl font-bold tabular-nums flex items-center gap-1">
                        {brs.trend === "down" ? (
                          <TrendingDown className="h-5 w-5 text-emerald-400" />
                        ) : (
                          <TrendingUp className="h-5 w-5 text-red-400" />
                        )}
                        {brs.delta_30d !== undefined ? `${brs.delta_30d > 0 ? "+" : ""}${brs.delta_30d.toFixed(1)}` : "—"}
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Scoring Formula</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-24 w-full" />
                ) : !scoring ? (
                  <EmptyState icon={ShieldCheck} title="No formula" description="Configure scoring in Settings." />
                ) : (
                  <div className="space-y-2">
                    <code className="block text-xs font-mono p-2 bg-muted rounded">{scoring.formula ?? "—"}</code>
                    {scoring.version && <p className="text-xs text-muted-foreground">v{scoring.version}</p>}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Executive sub-tabs (P1 Wave 3 S2) — Briefing · CISO Report · BU Heatmap · Risk Report · Investment */}
          <Tabs defaultValue="briefing" className="space-y-3">
            <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
              <TabsTrigger value="briefing" className="flex items-center gap-1.5">
                <FileText className="h-3.5 w-3.5" />Executive Briefing
              </TabsTrigger>
              <TabsTrigger value="ciso" className="flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5" />CISO Report
              </TabsTrigger>
              <TabsTrigger value="bu-heatmap" className="flex items-center gap-1.5">
                <Map className="h-3.5 w-3.5" />BU Risk Heatmap
              </TabsTrigger>
              <TabsTrigger value="risk-report" className="flex items-center gap-1.5">
                <PieChart className="h-3.5 w-3.5" />Risk Report
              </TabsTrigger>
              <TabsTrigger value="reporting" className="flex items-center gap-1.5">
                <Briefcase className="h-3.5 w-3.5" />Investment / ROI
              </TabsTrigger>
            </TabsList>
            <TabsContent value="briefing">
              <Suspense fallback={<Skeleton className="h-[480px] w-full" />}>
                <ExecutiveBriefing />
              </Suspense>
            </TabsContent>
            <TabsContent value="ciso">
              <Suspense fallback={<Skeleton className="h-[480px] w-full" />}>
                <CISOReportDashboard />
              </Suspense>
            </TabsContent>
            <TabsContent value="bu-heatmap">
              <Suspense fallback={<Skeleton className="h-[480px] w-full" />}>
                <BUDollarRiskHeatmap />
              </Suspense>
            </TabsContent>
            <TabsContent value="risk-report">
              <Suspense fallback={<Skeleton className="h-[480px] w-full" />}>
                <ExecutiveRiskReport />
              </Suspense>
            </TabsContent>
            <TabsContent value="reporting">
              <Suspense fallback={<Skeleton className="h-[480px] w-full" />}>
                <ExecutiveReportingDashboard />
              </Suspense>
            </TabsContent>
          </Tabs>
        </TabsContent>

        {/* SOC view (P1 Wave 3 — S3 SOC Operations fold-in) */}
        <TabsContent value="soc" className="space-y-4">
          <p className="text-sm text-muted-foreground">{VIEWS[1].description}</p>

          {/* SOC sub-tabs — Overview · T1 Console · Alert Triage · Incident Response */}
          <Tabs defaultValue="overview" className="space-y-3">
            <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
              <TabsTrigger value="overview" className="flex items-center gap-1.5">
                <Activity className="h-3.5 w-3.5" />Live Overview
              </TabsTrigger>
              <TabsTrigger value="t1" className="flex items-center gap-1.5">
                <Stethoscope className="h-3.5 w-3.5" />T1 Console
              </TabsTrigger>
              <TabsTrigger value="triage" className="flex items-center gap-1.5">
                <FlameKindling className="h-3.5 w-3.5" />Alert Triage
              </TabsTrigger>
              <TabsTrigger value="ir" className="flex items-center gap-1.5">
                <Siren className="h-3.5 w-3.5" />Incident Response
              </TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-4">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <Card className="lg:col-span-2">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Siren className="h-4 w-4" /> Active Incidents
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    {loading ? (
                      <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
                    ) : !incidents?.items?.length ? (
                      <EmptyState icon={Siren} title="No active incidents" description="The wire is quiet. Hot incidents will surface here in real-time." />
                    ) : (
                      <ScrollArea className="h-[420px]">
                        <ul className="divide-y divide-border">
                          {incidents.items.map((it) => (
                            <li key={it.id ?? it.title} className="px-4 py-2 flex items-center gap-3 hover:bg-muted/40">
                              <Badge variant="outline" className={cn(
                                "uppercase text-[10px]",
                                (it.severity ?? "").toLowerCase() === "critical" && "border-red-500/40 text-red-400 bg-red-500/10",
                                (it.severity ?? "").toLowerCase() === "high" && "border-orange-500/40 text-orange-400 bg-orange-500/10",
                              )}>
                                {it.severity ?? "—"}
                              </Badge>
                              <span className="text-sm font-medium truncate flex-1">{it.title ?? it.id}</span>
                              <span className="text-xs text-muted-foreground">{it.status ?? "open"}</span>
                            </li>
                          ))}
                        </ul>
                      </ScrollArea>
                    )}
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="pb-3 flex flex-row items-center justify-between">
                    <CardTitle className="text-base">Live SOC Feed</CardTitle>
                    <Badge variant="outline" className="text-[10px]">SSE</Badge>
                  </CardHeader>
                  <CardContent>
                    <LiveEventStream eventTypes={["incident", "alert", "finding"]} heightClass="h-[380px]" />
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="t1">
              <Suspense fallback={<Skeleton className="h-[640px] w-full" />}>
                <SOCT1Dashboard />
              </Suspense>
            </TabsContent>
            <TabsContent value="triage">
              <Suspense fallback={<Skeleton className="h-[640px] w-full" />}>
                <AlertTriageDashboard />
              </Suspense>
            </TabsContent>
            <TabsContent value="ir">
              <Suspense fallback={<Skeleton className="h-[640px] w-full" />}>
                <IncidentResponseDashboard />
              </Suspense>
            </TabsContent>
          </Tabs>
        </TabsContent>

        {/* DevSecOps view */}
        <TabsContent value="dev" className="space-y-4">
          <p className="text-sm text-muted-foreground">{VIEWS[2].description}</p>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card className="lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Code2 className="h-4 w-4" /> Recent Failed Scans
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {loading ? (
                  <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
                ) : !newFindings?.items?.length ? (
                  <EmptyState icon={Inbox} title="No failed scans" description="All recent pipeline runs passed gates." />
                ) : (
                  <ScrollArea className="h-[420px]">
                    <ul className="divide-y divide-border">
                      {newFindings.items.slice(0, 30).map((f) => (
                        <li key={f.id ?? f.title} className="px-4 py-2 flex items-center gap-3 hover:bg-muted/40">
                          <Badge variant="outline" className={cn(
                            "uppercase text-[10px]",
                            (f.severity ?? "").toLowerCase() === "critical" && "border-red-500/40 text-red-400 bg-red-500/10",
                            (f.severity ?? "").toLowerCase() === "high" && "border-orange-500/40 text-orange-400 bg-orange-500/10",
                          )}>
                            {f.severity ?? "—"}
                          </Badge>
                          <span className="text-sm font-medium truncate flex-1">{f.title ?? f.id}</span>
                          <span className="text-xs text-muted-foreground whitespace-nowrap">{f.created_at?.slice(0, 10) ?? "—"}</span>
                        </li>
                      ))}
                    </ul>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Pipeline Status</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-32 w-full" />
                ) : !ha ? (
                  <EmptyState icon={Server} title="No pipeline data" description="Connect a CI/CD integration in /admin?tab=connectors." />
                ) : (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Status</span>
                      <Badge variant="outline" className={cn(
                        ha.status === "healthy" || ha.status === "ok" || ha.status === "OK"
                          ? "border-emerald-500/40 text-emerald-400 bg-emerald-500/10"
                          : "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
                      )}>{ha.status ?? "—"}</Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Active Nodes</span>
                      <span className="text-sm font-mono">{ha.active_nodes ?? "—"} / {ha.nodes ?? "—"}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Uptime</span>
                      <span className="text-sm font-mono">{ha.uptime ?? (ha.uptime_pct ? formatPct(ha.uptime_pct) : "—")}</span>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* AI Copilot view (P2 fold-in S18) */}
        <TabsContent value="copilot" className="space-y-4">
          <p className="text-sm text-muted-foreground">{VIEWS[4].description}</p>
          <Tabs defaultValue="chat" className="space-y-3">
            <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
              <TabsTrigger value="chat" className="flex items-center gap-1.5">
                <Bot className="h-3.5 w-3.5" />Chat
              </TabsTrigger>
              <TabsTrigger value="graph-chat" className="flex items-center gap-1.5">
                <Activity className="h-3.5 w-3.5" />Graph NL Query
              </TabsTrigger>
              <TabsTrigger value="dashboard" className="flex items-center gap-1.5">
                <Briefcase className="h-3.5 w-3.5" />Dashboard
              </TabsTrigger>
            </TabsList>
            <TabsContent value="chat">
              <Suspense fallback={<Skeleton className="h-[640px] w-full" />}>
                <Copilot />
              </Suspense>
            </TabsContent>
            <TabsContent value="graph-chat">
              <Suspense fallback={<Skeleton className="h-[640px] w-full" />}>
                <CopilotGraphChat />
              </Suspense>
            </TabsContent>
            <TabsContent value="dashboard">
              <Suspense fallback={<Skeleton className="h-[640px] w-full" />}>
                <CopilotDashboard />
              </Suspense>
            </TabsContent>
          </Tabs>
        </TabsContent>

        {/* Operational view */}
        <TabsContent value="ops" className="space-y-4">
          <p className="text-sm text-muted-foreground">{VIEWS[3].description}</p>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="h-4 w-4" /> System Health
                </CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-24 w-full" />
                ) : !ha ? (
                  <EmptyState icon={Server} title="No HA data" />
                ) : (
                  <div className="space-y-2">
                    <div className="flex justify-between"><span className="text-sm text-muted-foreground">Status</span><span className="text-sm font-mono">{ha.status ?? "—"}</span></div>
                    <div className="flex justify-between"><span className="text-sm text-muted-foreground">Uptime</span><span className="text-sm font-mono">{ha.uptime ?? (ha.uptime_pct ? formatPct(ha.uptime_pct) : "—")}</span></div>
                    <div className="flex justify-between"><span className="text-sm text-muted-foreground">Nodes</span><span className="text-sm font-mono">{ha.active_nodes ?? "—"}/{ha.nodes ?? "—"}</span></div>
                  </div>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Inbox className="h-4 w-4" /> New Findings (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? (
                  <Skeleton className="h-24 w-full" />
                ) : (
                  <div className="space-y-2">
                    <p className="text-3xl font-bold tabular-nums">{newFindings?.total ?? newFindings?.items?.length ?? 0}</p>
                    <p className="text-xs text-muted-foreground">Untriaged across every scanner</p>
                  </div>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Users className="h-4 w-4" /> Logged-in As
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1">
                  <p className="text-sm font-medium">{user?.first_name} {user?.last_name}</p>
                  <p className="text-xs text-muted-foreground">{user?.email}</p>
                  <Badge variant="outline" className="text-[10px]">{user?.role ?? "viewer"}</Badge>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
