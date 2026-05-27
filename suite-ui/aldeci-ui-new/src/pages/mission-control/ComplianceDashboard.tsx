/**
 * Compliance Dashboard — P07 Persona (Compliance Officer / Auditor)
 * Route: /mission-control/compliance
 *
 * Data sources (real API):
 *   - /api/v1/compliance/frameworks  → framework list + metadata
 *   - /api/v1/compliance-scanner/results  → scan results (score, passed, failed per profile)
 *   - /api/v1/compliance-scanner/profiles → profiles with framework tags
 *   - /api/v1/ctem/cycles             → CTEM cycle list
 *
 * NO mock fallbacks. Empty state shown when API returns [].
 */

import { useState, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell,
} from "recharts";
import {
  ShieldCheck, AlertTriangle, Clock, Download, RefreshCw,
  Filter, ChevronRight, X, CheckCircle2, XCircle, Minus,
  FileText, Calendar, TrendingUp, AlertCircle, BookOpen,
  ChevronDown, ExternalLink, Loader2, Plus, Activity, Target,
  Search, ListChecks, ShieldAlert, Megaphone,
} from "lucide-react";
import axios from "axios";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { EmptyState } from "@/components/shared/EmptyState";
import { complianceApi, getStoredAuthToken, getStoredAuthStrategy, getStoredOrgId, buildApiUrl } from "@/lib/api";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

type RagStatus = "green" | "yellow" | "red";

interface FrameworkCard {
  id: string;
  name: string;
  shortLabel: string;
  pct: number;
  passingControls: number;
  totalControls: number;
  failingControls: number;
  lastScanDate: string;
  score: number;
}

// ─────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────

function ragColor(pct: number): RagStatus {
  if (pct >= 85) return "green";
  if (pct >= 70) return "yellow";
  return "red";
}

const RAG_CLASSES: Record<RagStatus, { border: string; text: string; bg: string; arc: string }> = {
  green:  { border: "border-green-500/40",  text: "text-green-400",  bg: "bg-green-500/10",  arc: "#22c55e" },
  yellow: { border: "border-yellow-500/40", text: "text-yellow-400", bg: "bg-yellow-500/10", arc: "#eab308" },
  red:    { border: "border-red-500/40",    text: "text-red-400",    bg: "bg-red-500/10",    arc: "#ef4444" },
};

// ─────────────────────────────────────────────────────────────
// Arc Gauge
// ─────────────────────────────────────────────────────────────

function ArcGauge({ pct, color }: { pct: number; color: string }) {
  const r = 38;
  const circ = 2 * Math.PI * r;
  const arc = circ * 0.75;
  const filled = (pct / 100) * arc;
  return (
    <svg width="92" height="68" viewBox="0 0 92 68" className="overflow-visible">
      <path d="M 8 62 A 38 38 0 1 1 84 62" fill="none" stroke="oklch(0.25 0.01 250)" strokeWidth="7" strokeLinecap="round" />
      <path d="M 8 62 A 38 38 0 1 1 84 62" fill="none" stroke={color} strokeWidth="7" strokeLinecap="round"
        strokeDasharray={`${filled} ${circ}`} className="transition-all duration-700" />
      <text x="46" y="46" textAnchor="middle" fill="currentColor" fontSize="18" fontWeight="700" fontFamily="JetBrains Mono, monospace">{pct}</text>
      <text x="46" y="60" textAnchor="middle" fill={color} fontSize="8" fontWeight="600">%</text>
    </svg>
  );
}

// ─────────────────────────────────────────────────────────────
// Framework Status Card
// ─────────────────────────────────────────────────────────────

function FrameworkStatusCard({ fw, onClick }: { fw: FrameworkCard; onClick: () => void }) {
  const rag = ragColor(fw.pct);
  const styles = RAG_CLASSES[rag];
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <Card className={cn("border cursor-pointer hover:bg-muted/20 transition-colors duration-150", styles.border)} onClick={onClick}>
        <CardContent className="pt-5 pb-4 px-5">
          <div className="flex items-start justify-between mb-3">
            <div className="min-w-0">
              <p className="text-xs font-semibold uppercase tracking-widest text-muted-foreground mb-0.5">{fw.shortLabel}</p>
              <p className="text-sm font-medium leading-tight text-foreground truncate max-w-[120px]">{fw.name}</p>
            </div>
            <div className={cn("rounded-md p-1.5 shrink-0", styles.bg)}>
              <ShieldCheck className={cn("h-4 w-4", styles.text)} />
            </div>
          </div>
          <div className="flex items-end justify-between gap-3">
            <ArcGauge pct={fw.pct} color={styles.arc} />
            <div className="space-y-2 text-right pb-1">
              <div>
                <p className="text-xs text-muted-foreground">Passing</p>
                <p className="text-sm font-mono font-semibold tabular-nums">
                  {fw.passingControls}<span className="text-muted-foreground font-normal">/{fw.totalControls}</span>
                </p>
              </div>
              {fw.failingControls > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground">Failing</p>
                  <p className="text-sm font-mono font-semibold tabular-nums text-red-400">{fw.failingControls}</p>
                </div>
              )}
            </div>
          </div>
          <Separator className="my-3" />
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Last scan: <span className="font-mono">{fw.lastScanDate}</span></span>
            <span className={cn("font-medium", styles.text)}>{fw.score.toFixed(0)}%</span>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ─────────────────────────────────────────────────────────────
// CTEM Cycles Panel (already real — keep as-is)
// ─────────────────────────────────────────────────────────────

type CtemStage = "scoping" | "discovery" | "prioritization" | "validation" | "mobilization";

interface CtemCycle {
  id: string;
  name: string;
  start_date?: string;
  current_stage: CtemStage;
  exposures?: string[];
  completion_pct?: number;
  org_id?: string;
}

const CTEM_STAGE_ORDER: CtemStage[] = ["scoping", "discovery", "prioritization", "validation", "mobilization"];

const CTEM_STAGE_META: Record<CtemStage, { label: string; icon: React.FC<{ className?: string }>; color: string; bg: string; border: string }> = {
  scoping:        { label: "Scoping",        icon: Target,      color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30"   },
  discovery:      { label: "Discovery",      icon: Search,      color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30"   },
  prioritization: { label: "Prioritization", icon: ListChecks,  color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  validation:     { label: "Validation",     icon: ShieldAlert, color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  mobilization:   { label: "Mobilization",   icon: Megaphone,   color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30"  },
};

function ctemAuthHeaders(): Record<string, string> {
  const token = getStoredAuthToken();
  const strategy = getStoredAuthStrategy();
  const orgId = getStoredOrgId();
  const headers: Record<string, string> = { "Content-Type": "application/json", "X-Org-ID": orgId };
  if (token) {
    if (strategy === "jwt") {
      headers.Authorization = token.toLowerCase().startsWith("bearer ") ? token : `Bearer ${token}`;
    } else {
      headers["X-API-Key"] = token;
    }
  }
  return headers;
}

async function listCtemCycles(orgId: string): Promise<CtemCycle[]> {
  const url = buildApiUrl("/api/v1/ctem/cycles", { org_id: orgId });
  const res = await axios.get<CtemCycle[]>(url, { headers: ctemAuthHeaders() });
  return Array.isArray(res.data) ? res.data : [];
}

async function createCtemCycle(name: string, orgId: string): Promise<CtemCycle> {
  const url = buildApiUrl("/api/v1/ctem/cycles", { org_id: orgId });
  const res = await axios.post<CtemCycle>(url, { name }, { headers: ctemAuthHeaders() });
  return res.data;
}

async function advanceCtemStage(cycleId: string): Promise<CtemCycle> {
  const url = buildApiUrl(`/api/v1/ctem/cycles/${cycleId}/advance`);
  const res = await axios.post<CtemCycle>(url, {}, { headers: ctemAuthHeaders() });
  return res.data;
}

function StageIndicator({ current }: { current: CtemStage }) {
  const currentIdx = CTEM_STAGE_ORDER.indexOf(current);
  return (
    <div className="flex items-center gap-1 flex-wrap" role="group" aria-label={`Current stage: ${CTEM_STAGE_META[current].label}`}>
      {CTEM_STAGE_ORDER.map((stage, idx) => {
        const meta = CTEM_STAGE_META[stage];
        const Icon = meta.icon;
        const isCompleted = idx < currentIdx;
        const isActive = idx === currentIdx;
        return (
          <div key={stage} className="flex items-center gap-1">
            <div
              role="img"
              aria-label={`${meta.label} ${isActive ? "(current)" : isCompleted ? "(completed)" : "(upcoming)"}`}
              aria-current={isActive ? "step" : undefined}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium font-mono transition-all",
                isActive ? cn(meta.color, meta.bg, meta.border, "ring-1 ring-current shadow-sm")
                  : isCompleted ? "text-green-400 bg-green-500/5 border-green-500/20"
                  : "text-muted-foreground bg-muted/20 border-border"
              )}
            >
              <Icon className="h-3 w-3" />
              <span className="hidden sm:inline">{meta.label}</span>
              {isCompleted && <CheckCircle2 className="h-3 w-3 text-green-400" />}
            </div>
            {idx < CTEM_STAGE_ORDER.length - 1 && (
              <ChevronRight className={cn("h-3 w-3", idx < currentIdx ? "text-green-400" : "text-muted-foreground/40")} aria-hidden />
            )}
          </div>
        );
      })}
    </div>
  );
}

function CtemCyclesPanel() {
  const orgId = getStoredOrgId();
  const queryClient = useQueryClient();
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const { data: cycles, isLoading, isError, refetch } = useQuery<CtemCycle[]>({
    queryKey: ["ctem-cycles", orgId],
    queryFn: () => listCtemCycles(orgId),
    refetchInterval: 60_000,
    staleTime: 30_000,
  });

  const createMutation = useMutation({
    mutationFn: () => createCtemCycle(`Cycle ${new Date().toISOString().slice(0, 10)}`, orgId),
    onSuccess: () => { setErrorMsg(null); queryClient.invalidateQueries({ queryKey: ["ctem-cycles", orgId] }); },
    onError: (err: unknown) => {
      const message = axios.isAxiosError(err) ? (err.response?.data?.detail ?? err.message) : String(err);
      setErrorMsg(`Create failed: ${message}`);
    },
  });

  const advanceMutation = useMutation({
    mutationFn: (cycleId: string) => advanceCtemStage(cycleId),
    onSuccess: () => { setErrorMsg(null); queryClient.invalidateQueries({ queryKey: ["ctem-cycles", orgId] }); },
    onError: (err: unknown) => {
      const message = axios.isAxiosError(err) ? (err.response?.data?.detail ?? err.message) : String(err);
      setErrorMsg(`Advance failed: ${message}`);
    },
  });

  const handleCreate = useCallback(() => { createMutation.mutate(); }, [createMutation]);
  const cycleList = cycles ?? [];

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            CTEM Cycles
            <span className="text-xs font-normal text-muted-foreground ml-1">(5 stages)</span>
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isLoading} className="gap-1.5" aria-label="Refresh CTEM cycles">
              <RefreshCw className={cn("h-3.5 w-3.5", isLoading && "animate-spin")} />
              Refresh
            </Button>
            <Button size="sm" onClick={handleCreate} disabled={createMutation.isPending} className="gap-1.5" aria-label="Create new CTEM cycle">
              {createMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
              New Cycle
            </Button>
          </div>
        </div>
        {errorMsg && (
          <div className="mt-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400 font-mono">{errorMsg}</div>
        )}
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="py-12 flex items-center justify-center"><Loader2 className="h-5 w-5 animate-spin text-muted-foreground" /></div>
        ) : isError ? (
          <div className="py-8"><ErrorState message="Failed to load CTEM cycles" onRetry={refetch} /></div>
        ) : cycleList.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="No CTEM cycles"
            description="Create a cycle to manage continuous threat exposure across 5 stages."
            action={
              <Button onClick={handleCreate} disabled={createMutation.isPending} className="gap-1.5">
                {createMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                New cycle
              </Button>
            }
          />
        ) : (
          <>
            <div className="grid grid-cols-[1.4fr_2fr_0.7fr_0.6fr_0.7fr] gap-3 px-4 py-2 border-b border-border bg-muted/20 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              <span>Cycle</span><span>Stage Progress</span><span className="text-right">Exposures</span><span className="text-right">Done %</span><span className="text-right">Action</span>
            </div>
            <div className="divide-y divide-border">
              {cycleList.map((cycle, idx) => {
                const stage = (cycle.current_stage || "scoping") as CtemStage;
                const exposureCount = Array.isArray(cycle.exposures) ? cycle.exposures.length : 0;
                const completionPct = typeof cycle.completion_pct === "number" ? cycle.completion_pct : 0;
                const isFinalStage = stage === "mobilization";
                const isAdvancingThis = advanceMutation.isPending && advanceMutation.variables === cycle.id;
                return (
                  <motion.div key={cycle.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: idx * 0.03 }}
                    className="grid grid-cols-[1.4fr_2fr_0.7fr_0.6fr_0.7fr] gap-3 px-4 py-3 hover:bg-muted/20 transition-colors items-center">
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{cycle.name}</p>
                      <p className="text-xs font-mono text-muted-foreground truncate mt-0.5">{cycle.id}</p>
                      {cycle.start_date && <p className="text-xs text-muted-foreground mt-0.5">Started <span className="font-mono">{cycle.start_date.slice(0, 10)}</span></p>}
                    </div>
                    <div className="min-w-0"><StageIndicator current={stage} /></div>
                    <div className="text-right"><span className="text-sm font-mono tabular-nums text-foreground">{exposureCount}</span></div>
                    <div className="text-right"><span className="text-sm font-mono tabular-nums text-foreground">{completionPct.toFixed(0)}%</span></div>
                    <div className="text-right">
                      <Button variant={isFinalStage ? "ghost" : "outline"} size="sm"
                        onClick={() => advanceMutation.mutate(cycle.id)}
                        disabled={isFinalStage || isAdvancingThis} className="gap-1.5 text-xs"
                        aria-label={isFinalStage ? `Cycle ${cycle.name} is at final stage` : `Advance ${cycle.name} to next stage`}>
                        {isAdvancingThis ? <Loader2 className="h-3 w-3 animate-spin" /> : <ChevronRight className="h-3 w-3" />}
                        {isFinalStage ? "Complete" : "Advance"}
                      </Button>
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────

interface ScanResult {
  result_id: string;
  profile_id: string;
  total_checks: number;
  passed: number;
  failed: number;
  warnings: number;
  score: number;
  status: string;
  scan_completed: string;
}

interface ScanProfile {
  profile_id: string;
  name: string;
  frameworks: string[];
  last_scan: string;
}

interface ComplianceFrameworkMeta {
  full_name: string;
  issuer: string;
  version: string;
  description: string;
}

interface FrameworksResponse {
  frameworks: string[];
  metadata: Record<string, ComplianceFrameworkMeta>;
}

export default function ComplianceDashboard() {
  const navigate = useNavigate();
  const orgId = getStoredOrgId();
  const [frameworkFilter, setFrameworkFilter] = useState<string>("all");

  // Fetch compliance frameworks list
  const frameworksQuery = useQuery<FrameworksResponse>({
    queryKey: ["compliance-frameworks"],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/compliance/frameworks", { org_id: orgId });
      const res = await axios.get<FrameworksResponse>(url, { headers: ctemAuthHeaders() });
      return res.data;
    },
    staleTime: 120_000,
  });

  // Fetch scan results
  const resultsQuery = useQuery<ScanResult[]>({
    queryKey: ["compliance-scanner-results", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/compliance-scanner/results", { org_id: orgId });
      const res = await axios.get<ScanResult[]>(url, { headers: ctemAuthHeaders() });
      return Array.isArray(res.data) ? res.data : [];
    },
    refetchInterval: 120_000,
    staleTime: 60_000,
  });

  // Fetch scan profiles
  const profilesQuery = useQuery<ScanProfile[]>({
    queryKey: ["compliance-scanner-profiles", orgId],
    queryFn: async () => {
      const url = buildApiUrl("/api/v1/compliance-scanner/profiles", { org_id: orgId });
      const res = await axios.get<ScanProfile[]>(url, { headers: ctemAuthHeaders() });
      return Array.isArray(res.data) ? res.data : [];
    },
    staleTime: 120_000,
  });

  const refetchAll = useCallback(() => {
    resultsQuery.refetch();
    profilesQuery.refetch();
    frameworksQuery.refetch();
  }, [resultsQuery, profilesQuery, frameworksQuery]);

  const isLoading = resultsQuery.isLoading || profilesQuery.isLoading || frameworksQuery.isLoading;
  const isError = resultsQuery.isError && profilesQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load compliance data" onRetry={refetchAll} />;

  const results = resultsQuery.data ?? [];
  const profiles = profilesQuery.data ?? [];
  const frameworksMeta = frameworksQuery.data?.metadata ?? {};
  const frameworkKeys = frameworksQuery.data?.frameworks ?? [];

  // Build profile map for quick lookup
  const profileMap = new Map<string, ScanProfile>();
  for (const p of profiles) profileMap.set(p.profile_id, p);

  // Aggregate results by framework key
  const fwAggMap = new Map<string, { passed: number; total: number; failed: number; scores: number[]; lastScan: string }>();

  for (const r of results) {
    const profile = profileMap.get(r.profile_id);
    const fwList = profile?.frameworks ?? ["SOC2"];
    for (const fw of fwList) {
      const existing = fwAggMap.get(fw) ?? { passed: 0, total: 0, failed: 0, scores: [], lastScan: "" };
      existing.passed += r.passed;
      existing.total += r.total_checks;
      existing.failed += r.failed;
      existing.scores.push(r.score);
      if (!existing.lastScan || r.scan_completed > existing.lastScan) existing.lastScan = r.scan_completed;
      fwAggMap.set(fw, existing);
    }
  }

  // Build FrameworkCard list — use real API data, fall back to framework list with zero counts
  const allFrameworkKeys = fwAggMap.size > 0 ? Array.from(fwAggMap.keys()) : frameworkKeys;

  const frameworks: FrameworkCard[] = allFrameworkKeys.map((key) => {
    const agg = fwAggMap.get(key);
    const meta = frameworksMeta[key];
    const avgScore = agg && agg.scores.length > 0
      ? Math.round(agg.scores.reduce((a, b) => a + b, 0) / agg.scores.length)
      : 0;
    const pct = agg && agg.total > 0 ? Math.round((agg.passed / agg.total) * 100) : avgScore;
    return {
      id: key,
      name: meta?.full_name ?? key,
      shortLabel: key,
      pct,
      passingControls: agg?.passed ?? 0,
      totalControls: agg?.total ?? 0,
      failingControls: agg?.failed ?? 0,
      lastScanDate: agg?.lastScan ? agg.lastScan.slice(0, 10) : "—",
      score: avgScore,
    };
  });

  const filteredFrameworks = frameworkFilter === "all"
    ? frameworks
    : frameworks.filter((f) => f.id === frameworkFilter);

  // KPIs
  const totalFrameworks = frameworks.length;
  const compliantCount = frameworks.filter((f) => f.pct >= 85).length;
  const totalGaps = frameworks.reduce((sum, f) => sum + f.failingControls, 0);
  const avgCompliance = totalFrameworks > 0
    ? Math.round(frameworks.reduce((sum, f) => sum + f.pct, 0) / totalFrameworks)
    : 0;

  // Gap bar chart data
  const gapBarData = frameworks.map((f) => ({
    framework: f.shortLabel,
    gaps: f.failingControls,
    fill: ragColor(f.pct) === "green" ? "#22c55e" : ragColor(f.pct) === "yellow" ? "#eab308" : "#ef4444",
  }));

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title="Compliance Dashboard"
        description="Governance posture across compliance frameworks — P07 Compliance Officer"
        badge="P07"
      >
        <Button variant="outline" size="sm" onClick={refetchAll}>
          <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
          Refresh
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Avg Compliance" value={`${avgCompliance}%`} icon={ShieldCheck}
          trend={avgCompliance >= 85 ? "up" : "down"} trendLabel="Across all frameworks" />
        <KpiCard title="Compliant" value={`${compliantCount}/${totalFrameworks}`} icon={CheckCircle2}
          trend={compliantCount === totalFrameworks ? "up" : "flat"} trendLabel="Frameworks ≥85%" />
        <KpiCard title="Total Failures" value={totalGaps} icon={AlertTriangle}
          trend="down" trendLabel="Failing checks" />
        <KpiCard title="Scan Results" value={results.length} icon={Activity}
          trend="flat" trendLabel="Total scans recorded" />
      </div>

      {/* Framework filter */}
      <div className="flex items-center gap-2">
        <Filter className="h-3.5 w-3.5 text-muted-foreground" />
        <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
          <SelectTrigger className="h-7 text-xs w-[160px]">
            <SelectValue placeholder="Framework" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Frameworks</SelectItem>
            {frameworks.map((fw) => (
              <SelectItem key={fw.id} value={fw.id}>{fw.shortLabel}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Framework Status Cards */}
      <section aria-label="Framework Status">
        <h2 className="text-sm font-semibold uppercase tracking-widest text-muted-foreground mb-3">Framework Status</h2>
        {filteredFrameworks.length === 0 ? (
          <EmptyState icon={ShieldCheck} title="No compliance data" description="No scan results found. Run a compliance scan to populate this dashboard." />
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3">
            {filteredFrameworks.map((fw) => (
              <FrameworkStatusCard key={fw.id} fw={fw} onClick={() => setFrameworkFilter(fw.id === frameworkFilter ? "all" : fw.id)} />
            ))}
          </div>
        )}
      </section>

      {/* Gap Analysis */}
      {frameworks.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" />
              Failing Checks by Framework
            </CardTitle>
          </CardHeader>
          <CardContent>
            {gapBarData.every((d) => d.gaps === 0) ? (
              <p className="text-sm text-muted-foreground py-4 text-center">No failing checks across any framework.</p>
            ) : (
              <div className="h-[160px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={gapBarData} margin={{ top: 0, right: 0, left: -24, bottom: 0 }} barSize={22}>
                    <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.25 0.01 250)" vertical={false} />
                    <XAxis dataKey="framework" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontFamily: "JetBrains Mono, monospace" }} axisLine={false} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={{ background: "oklch(0.17 0.01 250)", border: "1px solid oklch(0.25 0.01 250)", borderRadius: 8, fontSize: 12 }} cursor={{ fill: "oklch(0.25 0.01 250 / 0.4)" }} />
                    <Bar dataKey="gaps" radius={[3, 3, 0, 0]} name="Failing">
                      {gapBarData.map((entry, i) => <Cell key={i} fill={entry.fill} fillOpacity={0.85} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Scan Results Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-primary" />
            Recent Scan Results
            <span className="text-xs font-normal text-muted-foreground">({results.length} scans)</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {results.length === 0 ? (
            <EmptyState icon={FileText} title="No scan results" description="Run a compliance scan to populate results." />
          ) : (
            <>
              <div className="grid grid-cols-[1fr_0.7fr_0.6fr_0.6fr_0.5fr_0.8fr] gap-2 px-4 py-2 border-b border-border bg-muted/20 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                <span>Profile ID</span><span className="text-right">Total</span><span className="text-right">Passed</span><span className="text-right">Failed</span><span className="text-right">Score</span><span className="text-right">Completed</span>
              </div>
              <div className="divide-y divide-border max-h-[360px] overflow-y-auto">
                {results.slice(0, 30).map((r, idx) => (
                  <motion.div key={r.result_id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: idx * 0.015 }}
                    className="grid grid-cols-[1fr_0.7fr_0.6fr_0.6fr_0.5fr_0.8fr] gap-2 px-4 py-2.5 hover:bg-muted/20 transition-colors items-center">
                    <span className="text-xs font-mono text-muted-foreground truncate">{r.result_id.slice(0, 8)}…</span>
                    <span className="text-xs font-mono text-right tabular-nums">{r.total_checks}</span>
                    <span className="text-xs font-mono text-right tabular-nums text-green-400">{r.passed}</span>
                    <span className="text-xs font-mono text-right tabular-nums text-red-400">{r.failed}</span>
                    <span className={cn("text-xs font-mono font-semibold text-right tabular-nums", r.score >= 85 ? "text-green-400" : r.score >= 70 ? "text-yellow-400" : "text-red-400")}>
                      {r.score.toFixed(0)}%
                    </span>
                    <span className="text-xs text-right text-muted-foreground font-mono">{r.scan_completed.slice(0, 10)}</span>
                  </motion.div>
                ))}
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* CTEM Cycles */}
      <section aria-label="CTEM Cycles">
        <h2 className="text-sm font-semibold uppercase tracking-widest text-muted-foreground mb-3">Continuous Threat Exposure Management</h2>
        <CtemCyclesPanel />
      </section>
    </div>
  );
}
