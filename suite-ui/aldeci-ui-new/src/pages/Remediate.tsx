/**
 * Remediation Center HERO — Phase 3 P1 (S19 in UX_CONSOLIDATION_PLAN_2026-04-26.md).
 *
 * Single hero at top-level /remediate. Tab structure:
 *   - Suggested Fixes   (AutoFix items waiting for human approval)
 *   - Auto-Apply Queue  (queued for autonomous application after rules pass)
 *   - Approval Workflow (multi-stage human approval / waiver requests)
 *   - Closed            (applied / rejected / waived — historical)
 *   - Waivers           (WaiversExplorer + AutoWaiverRules side-by-side)
 *   - Workflows         (lazy-loaded existing Workflows screen)
 *   - Center            (lazy-loaded existing RemediationCenter screen)
 *
 * Real apiFetch only. Pulls from /api/v1/autofix/* and /api/v1/waivers/*.
 * EmptyState when endpoints return 404/501. NO MOCKS.
 *
 * Route: /remediate (top-level nav per plan)
 */

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ClipboardCheck,
  Clock,
  Code2,
  FileCheck,
  GitPullRequest,
  Lightbulb,
  ListChecks,
  PlayCircle,
  RefreshCw,
  Search,
  Settings2,
  ShieldOff,
  Sparkles,
  Wrench,
  X,
  XCircle,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// Lazy-load existing screens as tabs (zero functionality loss)
const WaiversExplorer = lazy(() => import("@/pages/WaiversExplorer"));
const AutoWaiverRules = lazy(() => import("@/pages/AutoWaiverRules"));
const WaiverRequestModal = lazy(() => import("@/pages/WaiverRequestModal"));
const RemediationCenter = lazy(() => import("@/pages/remediate/RemediationCenter"));
const Workflows = lazy(() => import("@/pages/remediate/Workflows"));
// Wave 1 Phase 3 fold-ins (2026-04-27)
const RiskRegisterDashboard = lazy(() => import("@/pages/RiskRegisterDashboard"));
const RiskTreatmentDashboard = lazy(() => import("@/pages/RiskTreatmentDashboard"));
const PatchManagementDashboard = lazy(() => import("@/pages/PatchManagementDashboard"));
const PostureAdvisor = lazy(() => import("@/pages/PostureAdvisor"));
const ScheduledReportsDashboard = lazy(() => import("@/pages/ScheduledReportsDashboard"));

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface AutoFixItem {
  id?: string;
  fix_id?: string;
  finding_id?: string;
  title?: string;
  status?: string;        // suggested / queued / pending_approval / applied / rejected / waived / failed
  fix_type?: string;
  language?: string;
  confidence?: number;    // 0..1
  risk_score?: number;
  created_at?: string;
  applied_at?: string;
  pull_request_url?: string;
  scanner?: string;
  source?: string;
  cve?: string;
  cve_id?: string;
  asset?: string;
  asset_id?: string;
  diff?: string;
  approver?: string;
}

interface AutoFixListResponse {
  items?: AutoFixItem[];
  fixes?: AutoFixItem[];
  data?: AutoFixItem[];
  total?: number;
}

interface AutoFixStats {
  total?: number;
  suggested?: number;
  queued?: number;
  pending_approval?: number;
  applied?: number;
  rejected?: number;
  waived?: number;
  failed?: number;
  by_fix_type?: Record<string, number>;
  by_confidence?: Record<string, number>;
  avg_confidence?: number;
  applied_this_week?: number;
}

type TabKey = "suggested" | "queue" | "approval" | "closed" | "waivers" | "workflows" | "center" | "risk-register" | "risk-treatment" | "patch" | "posture-advisor" | "scheduled-reports";

interface TabSpec {
  key: TabKey;
  label: string;
  icon: typeof Wrench;
  status?: string;            // server filter
  description: string;
}

const TABS: TabSpec[] = [
  { key: "suggested", label: "Suggested Fixes",   icon: Sparkles,        status: "suggested",        description: "AutoFix candidates generated from finding signal — review confidence + diff before approving." },
  { key: "queue",     label: "Auto-Apply Queue",  icon: PlayCircle,      status: "queued",           description: "Fixes scheduled for autonomous application — gated by AutoWaiver rules + risk threshold." },
  { key: "approval",  label: "Approval Workflow", icon: ClipboardCheck,  status: "pending_approval", description: "Multi-stage human approval queue — waivers, RBAC sign-off, exec approval." },
  { key: "closed",    label: "Closed",            icon: CheckCircle2,    status: "applied",          description: "Historical — applied, rejected, or waived. Provides audit trail for SOC2 / SOX." },
  { key: "waivers",            label: "Waivers",            icon: ShieldOff,    description: "WaiversExplorer + AutoWaiverRules side-by-side. Manage exception policies and active waivers." },
  { key: "workflows",          label: "Workflows",          icon: Settings2,    description: "Existing Workflows screen — multi-step remediation playbooks and SOAR automations." },
  { key: "center",             label: "Center",             icon: Wrench,       description: "Legacy Remediation Center deep-dive (cases, bulk operations, ticket integration)." },
  { key: "risk-register",      label: "Risk Register",      icon: ListChecks,   description: "Wave 1 Phase 3 fold-in — enterprise risk register with likelihood/impact scoring and lifecycle tracking. /api/v1/risk-register-engine." },
  { key: "risk-treatment",     label: "Risk Treatment",     icon: ClipboardCheck, description: "Wave 1 Phase 3 fold-in — risk treatment workflow tracking: progress, overdue items, owner accountability. /api/v1/risk-treatment." },
  { key: "patch",              label: "Patch Mgmt",         icon: Activity,     description: "Wave 1 Phase 3 fold-in — patch management lifecycle: pending, in-progress, applied patches by severity. /api/v1/patch-management." },
  { key: "posture-advisor",    label: "Posture Advisor",    icon: Lightbulb,    description: "Wave 1 Phase 3 fold-in — AI-driven posture recommendations, prioritized roadmap, quick-win actions. /api/v1/posture-advisor." },
  { key: "scheduled-reports",  label: "Scheduled Reports",  icon: FileCheck,    description: "Wave 1 Phase 3 fold-in — report schedules, delivery history, templates, Slack/email delivery. /api/v1/scheduled-reports." },
];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T | null> {
  const res = await fetch(buildApiUrl(path), {
    ...init,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (res.status === 404 || res.status === 501) return null;
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

function fixesFromResponse(r: unknown): AutoFixItem[] {
  if (Array.isArray(r)) return r as AutoFixItem[];
  if (!r || typeof r !== "object") return [];
  const obj = r as AutoFixListResponse;
  return obj.items ?? obj.fixes ?? obj.data ?? [];
}

function fixId(f: AutoFixItem): string {
  return f.id ?? f.fix_id ?? f.finding_id ?? f.title ?? "unknown";
}

function confTone(c?: number) {
  if (c == null) return "border-border text-muted-foreground";
  if (c >= 0.8) return "border-emerald-500/40 text-emerald-400 bg-emerald-500/10";
  if (c >= 0.5) return "border-amber-500/40 text-amber-400 bg-amber-500/10";
  return "border-red-500/40 text-red-400 bg-red-500/10";
}

function confLabel(c?: number) {
  if (c == null) return "—";
  if (c >= 0.8) return "HIGH";
  if (c >= 0.5) return "MED";
  return "LOW";
}

function statusTone(s?: string) {
  switch ((s ?? "").toLowerCase()) {
    case "applied":
    case "merged":
      return "border-emerald-500/40 text-emerald-400 bg-emerald-500/10";
    case "rejected":
    case "failed":
      return "border-red-500/40 text-red-400 bg-red-500/10";
    case "waived":
      return "border-violet-500/40 text-violet-400 bg-violet-500/10";
    case "pending_approval":
    case "queued":
      return "border-amber-500/40 text-amber-400 bg-amber-500/10";
    case "suggested":
      return "border-sky-500/40 text-sky-400 bg-sky-500/10";
    default:
      return "border-border text-muted-foreground";
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function Remediate() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = (searchParams.get("tab") as TabKey | null) ?? "suggested";

  const [tab, setTab] = useState<TabKey>(initialTab);
  const [fixes, setFixes] = useState<AutoFixItem[]>([]);
  const [stats, setStats] = useState<AutoFixStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<AutoFixItem | null>(null);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (tab === "suggested") next.delete("tab");
    else next.set("tab", tab);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [tab, searchParams, setSearchParams]);

  const activeSpec = useMemo(() => TABS.find((t) => t.key === tab) ?? TABS[0], [tab]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [statsR, listR] = await Promise.allSettled([
        apiFetch<AutoFixStats>("/api/v1/autofix/stats"),
        activeSpec.status
          ? apiFetch<AutoFixListResponse | AutoFixItem[]>(
              `/api/v1/autofix/fixes?status=${encodeURIComponent(activeSpec.status)}&limit=200`,
            )
          : Promise.resolve(null),
      ]);

      if (listR.status === "fulfilled") {
        if (listR.value === null) {
          if (activeSpec.status) setUnavailable(true);
          setFixes([]);
        } else {
          setUnavailable(false);
          setFixes(fixesFromResponse(listR.value));
        }
      } else {
        setErr(String((listR.reason as Error)?.message ?? listR.reason));
      }
      if (statsR.status === "fulfilled" && statsR.value) setStats(statsR.value);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [activeSpec.status]);

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    load();
  }, [load]);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return fixes;
    return fixes.filter((f) => {
      const hay = [
        f.title,
        f.cve ?? f.cve_id,
        f.scanner ?? f.source,
        f.asset ?? f.asset_id,
        f.fix_type,
        f.status,
        f.language,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [fixes, filter]);

  const apply = useCallback(async (item: AutoFixItem) => {
    const id = fixId(item);
    try {
      await apiFetch(`/api/v1/autofix/fixes/${encodeURIComponent(id)}/apply`, { method: "POST" });
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }, [load]);

  const reject = useCallback(async (item: AutoFixItem) => {
    const id = fixId(item);
    try {
      await apiFetch(`/api/v1/autofix/fixes/${encodeURIComponent(id)}/reject`, { method: "POST" });
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }, [load]);

  // KPIs (use stats if available, else derive from current view)
  const kpis = useMemo(() => {
    const total = stats?.total ?? fixes.length;
    const suggested = stats?.suggested ?? fixes.filter((f) => (f.status ?? "").toLowerCase() === "suggested").length;
    const pending = stats?.pending_approval ?? fixes.filter((f) => (f.status ?? "").toLowerCase() === "pending_approval").length;
    const applied = stats?.applied ?? fixes.filter((f) => (f.status ?? "").toLowerCase() === "applied").length;
    const avgConf = stats?.avg_confidence ?? (fixes.length > 0
      ? fixes.reduce((s, f) => s + (f.confidence ?? 0), 0) / fixes.length
      : 0);
    return {
      total,
      suggested,
      pending,
      applied,
      avgConf: Math.round(avgConf * 100),
    };
  }, [stats, fixes]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Remediate"
        description="Suggested fixes, auto-apply queue, approval workflow, and waivers — one place for everything between detection and closure."
        badge="HERO"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Total Fixes" value={kpis.total.toLocaleString()} icon={Wrench} />
        <KpiCard title="Suggested" value={kpis.suggested.toLocaleString()} icon={Sparkles} trend={kpis.suggested > 0 ? "up" : "flat"} />
        <KpiCard title="Pending Approval" value={kpis.pending.toLocaleString()} icon={ClipboardCheck} />
        <KpiCard title="Applied" value={kpis.applied.toLocaleString()} icon={CheckCircle2} trend="up" />
        <KpiCard title="Avg Confidence" value={`${kpis.avgConf}%`} icon={Activity} />
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabKey)} className="space-y-4">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          {TABS.map((t) => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="flex items-center gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        {/* AutoFix list tabs (suggested / queue / approval / closed) */}
        {TABS.filter((t) => t.status).map((t) => (
          <TabsContent key={t.key} value={t.key} className="space-y-4">
            <p className="text-sm text-muted-foreground">{t.description}</p>

            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter title, CVE, scanner, asset, fix type…"
                  className="pl-8"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                />
              </div>
              <Badge variant="outline">
                {visible.length} of {fixes.length}
              </Badge>
            </div>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base">{t.label}</CardTitle>
                <CardDescription>
                  Live data from <code className="text-[10px]">/api/v1/autofix/fixes?status={t.status}</code>
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {loading ? (
                  <div className="space-y-2 p-4">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <Skeleton key={i} className="h-10 w-full" />
                    ))}
                  </div>
                ) : err ? (
                  <ErrorState title="Failed to load fixes" message={err} onRetry={load} />
                ) : unavailable ? (
                  <EmptyState
                    icon={Wrench}
                    title="AutoFix endpoint not available"
                    description="`/api/v1/autofix/fixes` returned 404 or 501. AutoFix engine may not be running yet — check Brain pipeline step 8."
                  />
                ) : visible.length === 0 ? (
                  <EmptyState
                    icon={CheckCircle2}
                    title={`No ${t.label.toLowerCase()}`}
                    description="Either everything is clean here, or no fixes match the current filter."
                  />
                ) : (
                  <ScrollArea className="h-[520px]">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[110px]">Confidence</TableHead>
                          <TableHead>Fix</TableHead>
                          <TableHead className="w-[120px]">Type</TableHead>
                          <TableHead className="w-[100px]">Lang</TableHead>
                          <TableHead className="w-[140px]">CVE / Asset</TableHead>
                          <TableHead className="w-[110px]">Status</TableHead>
                          <TableHead className="w-[180px] text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {visible.map((f) => {
                          const id = fixId(f);
                          const isSel = selected && fixId(selected) === id;
                          return (
                            <TableRow
                              key={id}
                              className={cn("cursor-pointer hover:bg-muted/40", isSel && "bg-muted/60")}
                              onClick={() => setSelected(f)}
                            >
                              <TableCell>
                                <div className="space-y-1">
                                  <Badge variant="outline" className={confTone(f.confidence)}>
                                    {confLabel(f.confidence)}
                                  </Badge>
                                  {f.confidence != null && (
                                    <Progress value={Math.round(f.confidence * 100)} className="h-1" />
                                  )}
                                </div>
                              </TableCell>
                              <TableCell className="font-medium">
                                {f.title ?? "(untitled fix)"}
                                {f.pull_request_url && (
                                  <span className="block text-[10px] text-muted-foreground mt-0.5">
                                    <GitPullRequest className="inline h-3 w-3 mr-1" />
                                    PR linked
                                  </span>
                                )}
                              </TableCell>
                              <TableCell className="text-xs">
                                <Badge variant="outline" className="capitalize text-[10px]">
                                  {f.fix_type ?? "—"}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground capitalize">
                                {f.language ?? "—"}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground truncate max-w-[140px]">
                                <div>{f.cve ?? f.cve_id ?? "—"}</div>
                                <div className="text-[10px]">{f.asset ?? f.asset_id ?? "—"}</div>
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className={statusTone(f.status)}>
                                  {(f.status ?? "—").toString().replace("_", " ").toUpperCase()}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right">
                                {(t.key === "suggested" || t.key === "approval") && (
                                  <div className="flex justify-end gap-1">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-7 px-2 text-[11px]"
                                      onClick={(e) => { e.stopPropagation(); apply(f); }}
                                      disabled={refreshing}
                                    >
                                      <CheckCircle2 className="h-3 w-3 mr-1" />
                                      Apply
                                    </Button>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-7 px-2 text-[11px]"
                                      onClick={(e) => { e.stopPropagation(); reject(f); }}
                                      disabled={refreshing}
                                    >
                                      <XCircle className="h-3 w-3 mr-1" />
                                      Reject
                                    </Button>
                                  </div>
                                )}
                                {t.key === "closed" && (
                                  <span className="text-[11px] text-muted-foreground">
                                    {f.applied_at
                                      ? new Date(f.applied_at).toLocaleDateString()
                                      : "—"}
                                  </span>
                                )}
                                {t.key === "queue" && (
                                  <span className="text-[11px] text-muted-foreground inline-flex items-center gap-1">
                                    <Clock className="h-3 w-3" />
                                    queued
                                  </span>
                                )}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        ))}

        {/* Waivers tab — folds in WaiversExplorer + AutoWaiverRules + WaiverRequestModal */}
        <TabsContent value="waivers" className="space-y-4">
          <p className="text-sm text-muted-foreground">{TABS.find((t) => t.key === "waivers")?.description}</p>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <ShieldOff className="h-4 w-4" />
                  Waivers Explorer
                </CardTitle>
                <CardDescription>Active exception policies (read-only inline view).</CardDescription>
              </CardHeader>
              <CardContent>
                <Suspense fallback={<TabSkeleton />}><WaiversExplorer /></Suspense>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Settings2 className="h-4 w-4" />
                  Auto-Waiver Rules
                </CardTitle>
                <CardDescription>Auto-grant policies — define which findings get waived without human review.</CardDescription>
              </CardHeader>
              <CardContent>
                <Suspense fallback={<TabSkeleton />}><AutoWaiverRules /></Suspense>
              </CardContent>
            </Card>
          </div>
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <FileCheck className="h-4 w-4" />
                Request a Waiver
              </CardTitle>
              <CardDescription>Submit a new waiver request with risk justification + expiry.</CardDescription>
            </CardHeader>
            <CardContent>
              <Suspense fallback={<TabSkeleton />}><WaiverRequestModal /></Suspense>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="workflows">
          <Suspense fallback={<TabSkeleton />}><Workflows /></Suspense>
        </TabsContent>

        <TabsContent value="center">
          <Suspense fallback={<TabSkeleton />}><RemediationCenter /></Suspense>
        </TabsContent>

        {/* ── Wave 1 Phase 3 fold-ins (2026-04-27) ── */}
        <TabsContent value="risk-register">
          <Suspense fallback={<TabSkeleton />}><RiskRegisterDashboard /></Suspense>
        </TabsContent>

        <TabsContent value="risk-treatment">
          <Suspense fallback={<TabSkeleton />}><RiskTreatmentDashboard /></Suspense>
        </TabsContent>

        <TabsContent value="patch">
          <Suspense fallback={<TabSkeleton />}><PatchManagementDashboard /></Suspense>
        </TabsContent>

        <TabsContent value="posture-advisor">
          <Suspense fallback={<TabSkeleton />}><PostureAdvisor /></Suspense>
        </TabsContent>

        <TabsContent value="scheduled-reports">
          <Suspense fallback={<TabSkeleton />}><ScheduledReportsDashboard /></Suspense>
        </TabsContent>
      </Tabs>

      {/* Side drawer — fix detail + diff preview */}
      {selected && (
        <motion.aside
          key={fixId(selected)}
          initial={{ x: 540, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 540, opacity: 0 }}
          transition={{ duration: 0.25 }}
          className="fixed right-0 top-0 z-40 h-screen w-full max-w-[560px] border-l border-border bg-background shadow-2xl flex flex-col"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="min-w-0">
              <h3 className="font-semibold truncate">{selected.title ?? fixId(selected)}</h3>
              <p className="text-xs text-muted-foreground truncate font-mono">
                {fixId(selected)}
              </p>
            </div>
            <Button variant="ghost" size="icon" onClick={() => setSelected(null)} aria-label="Close">
              <X className="h-4 w-4" />
            </Button>
          </div>
          <ScrollArea className="flex-1">
            <div className="p-4 space-y-3 text-sm">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Fix Profile</CardTitle>
                </CardHeader>
                <CardContent className="text-xs space-y-2">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type</span>
                    <Badge variant="outline" className="capitalize text-[10px]">{selected.fix_type ?? "—"}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Status</span>
                    <Badge variant="outline" className={statusTone(selected.status)}>
                      {(selected.status ?? "—").toString().replace("_", " ").toUpperCase()}
                    </Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Language</span>
                    <span className="font-medium capitalize">{selected.language ?? "—"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Scanner</span>
                    <span className="font-medium">{selected.scanner ?? selected.source ?? "—"}</span>
                  </div>
                  {selected.confidence != null && (
                    <div className="space-y-1">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Confidence</span>
                        <span className={cn("tabular-nums font-medium", confTone(selected.confidence).split(" ")[1])}>
                          {Math.round(selected.confidence * 100)}% ({confLabel(selected.confidence)})
                        </span>
                      </div>
                      <Progress value={Math.round(selected.confidence * 100)} className="h-1.5" />
                    </div>
                  )}
                </CardContent>
              </Card>

              {selected.diff && (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      <Code2 className="h-3.5 w-3.5" />
                      Patch Preview
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <pre className="rounded bg-muted p-3 text-[10px] font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
                      {selected.diff}
                    </pre>
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">Actions</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <Button
                    size="sm"
                    className="w-full"
                    onClick={() => apply(selected)}
                    disabled={refreshing || (selected.status ?? "").toLowerCase() === "applied"}
                  >
                    <CheckCircle2 className="h-3.5 w-3.5 mr-2" />
                    Apply Fix
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full"
                    onClick={() => reject(selected)}
                    disabled={refreshing || (selected.status ?? "").toLowerCase() === "rejected"}
                  >
                    <XCircle className="h-3.5 w-3.5 mr-2" />
                    Reject
                  </Button>
                  {selected.pull_request_url && (
                    <Button
                      asChild
                      size="sm"
                      variant="outline"
                      className="w-full"
                    >
                      <a href={selected.pull_request_url} target="_blank" rel="noopener noreferrer">
                        <GitPullRequest className="h-3.5 w-3.5 mr-2" />
                        Open Pull Request
                      </a>
                    </Button>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <AlertTriangle className="h-3.5 w-3.5" />
                    Endpoint
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-xs">
                  <code className="block rounded bg-muted p-2 font-mono">
                    POST /api/v1/autofix/fixes/{fixId(selected)}/apply
                  </code>
                </CardContent>
              </Card>
            </div>
          </ScrollArea>
        </motion.aside>
      )}
    </motion.div>
  );
}

function TabSkeleton() {
  return (
    <div className="space-y-3 p-4">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}
