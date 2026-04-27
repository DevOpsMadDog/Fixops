/**
 * Brain HERO — 12-step pipeline visualization + Multi-LLM Council rail.
 *
 * Phase 3 P0, S15 in UX_CONSOLIDATION_PLAN_2026-04-26.md.
 *
 * Folds in: BrainPipeline (12-step viz), MultiLLM (consensus rail),
 * BrainVisualization (neural map tab), AlgorithmicLab, Predictions, MLDashboard,
 * FactorWeightsView, ScoreTransparencyPanel.
 *
 * Real apiFetch only — `/api/v1/brain/pipeline/runs`, `/api/v1/brain/stats`,
 * `/api/v1/llm/consensus`. NO MOCKS. EmptyState when endpoint returns 404/501.
 *
 * Route: /brain
 */

import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Brain as BrainIcon,
  CheckCircle2,
  Cpu,
  Database,
  FileText,
  GitBranch,
  Hash,
  Layers,
  Lock,
  Network,
  Play,
  RefreshCw,
  Search,
  Shield,
  Target,
  Timer,
  Users,
  X,
  Zap,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";

import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

// Lazy-load companion dashboards as tabs (zero functionality loss)
const MultiLLM = lazy(() => import("@/pages/ai/MultiLLM"));
const AlgorithmicLab = lazy(() => import("@/pages/ai/AlgorithmicLab"));
const Predictions = lazy(() => import("@/pages/ai/Predictions"));
const MLDashboard = lazy(() => import("@/pages/ai/MLDashboard"));
const BrainVisualization = lazy(() => import("@/pages/BrainVisualization"));
const FactorWeightsView = lazy(() => import("@/pages/FactorWeightsView"));
const ScoreTransparencyPanel = lazy(() => import("@/pages/ScoreTransparencyPanel"));

// ─────────────────────────────────────────────────────────────────────────────
// 12-step Brain Pipeline canon (from CTEM_PLUS_IDENTITY.md + brain_pipeline.py)
// ─────────────────────────────────────────────────────────────────────────────

interface PipelineStep {
  id: number;
  key: string;
  name: string;
  desc: string;
  icon: typeof BrainIcon;
}

const PIPELINE: PipelineStep[] = [
  { id: 1, key: "connect", name: "Connect", desc: "Pull findings from connected scanners + uploads", icon: Database },
  { id: 2, key: "normalize", name: "Normalize", desc: "Map scanner formats → canonical Finding schema", icon: FileText },
  { id: 3, key: "resolve-identity", name: "Resolve Identity", desc: "Asset + component identity resolution across scans", icon: Hash },
  { id: 4, key: "fp-suppress", name: "FP Suppress", desc: "False-positive suppression (rule + ML signals)", icon: AlertTriangle },
  { id: 5, key: "dedupe", name: "Dedupe", desc: "Cross-scanner dedup via fingerprint + semantic match", icon: GitBranch },
  { id: 6, key: "graph", name: "Graph", desc: "Knowledge graph relationship building", icon: Network },
  { id: 7, key: "enrich", name: "Enrich", desc: "CVE / EPSS / KEV / threat-intel overlay", icon: Search },
  { id: 8, key: "score", name: "Score", desc: "BRS scoring with factor-weights + transparency", icon: Target },
  { id: 9, key: "policy", name: "Policy", desc: "Policy-as-code evaluation (rules / DSL / hooks)", icon: Layers },
  { id: 10, key: "consensus", name: "Consensus", desc: "Multi-LLM council vote (5 + chairman)", icon: Users },
  { id: 11, key: "pentest", name: "Pentest", desc: "MPTE micro-pentest verification of exploitability", icon: Shield },
  { id: 12, key: "evidence", name: "Evidence", desc: "Quantum-signed compliance evidence bundle", icon: Lock },
];

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface PipelineRun {
  run_id?: string;
  id?: string;
  status?: string;
  started_at?: string;
  completed_at?: string;
  steps_completed?: number;
  total_findings?: number;
  decisions_made?: number;
  source?: string;
  current_step?: string;
}

interface BrainStats {
  total_nodes?: number;
  node_count?: number;
  total_edges?: number;
  edge_count?: number;
  status?: string;
}

interface ConsensusVote {
  model?: string;
  name?: string;
  vote?: string;
  decision?: string;
  confidence?: number;
  reasoning?: string;
}

interface ConsensusResponse {
  finding_id?: string;
  decision?: string;
  agreement?: number;
  votes?: ConsensusVote[];
  members?: ConsensusVote[];
  chairman?: ConsensusVote;
  escalated_to?: string;
}

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

function runsFromResponse(r: unknown): PipelineRun[] {
  if (Array.isArray(r)) return r as PipelineRun[];
  if (!r || typeof r !== "object") return [];
  const obj = r as { items?: PipelineRun[]; runs?: PipelineRun[] };
  return obj.items ?? obj.runs ?? [];
}

function stepIndexFromKey(key?: string): number {
  if (!key) return -1;
  const k = key.toLowerCase();
  return PIPELINE.findIndex((s) => s.key === k || s.name.toLowerCase() === k);
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function Brain() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialTab = searchParams.get("tab") ?? "pipeline";

  const [tab, setTab] = useState<string>(initialTab);
  const [runs, setRuns] = useState<PipelineRun[]>([]);
  const [stats, setStats] = useState<BrainStats>({});
  const [consensus, setConsensus] = useState<ConsensusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [activeStep, setActiveStep] = useState<PipelineStep | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (tab === "pipeline") next.delete("tab");
    else next.set("tab", tab);
    if (next.toString() !== searchParams.toString()) {
      setSearchParams(next, { replace: true });
    }
  }, [tab, searchParams, setSearchParams]);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [runsRes, statsRes, consensusRes] = await Promise.allSettled([
        apiFetch<unknown>("/api/v1/brain/pipeline/runs?limit=20"),
        apiFetch<BrainStats>("/api/v1/brain/stats"),
        apiFetch<ConsensusResponse>("/api/v1/llm/consensus/latest"),
      ]);

      if (runsRes.status === "fulfilled") {
        if (runsRes.value === null) {
          setUnavailable(true);
        } else {
          setRuns(runsFromResponse(runsRes.value));
          setUnavailable(false);
        }
      }
      if (statsRes.status === "fulfilled" && statsRes.value) setStats(statsRes.value);
      if (consensusRes.status === "fulfilled" && consensusRes.value) setConsensus(consensusRes.value);

      // Surface the first hard failure (network / 5xx)
      const failed = [runsRes, statsRes, consensusRes].find(
        (r) => r.status === "rejected",
      ) as PromiseRejectedResult | undefined;
      if (failed && runsRes.status === "rejected") {
        setErr(String(failed.reason?.message ?? failed.reason));
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const triggerRun = useCallback(async () => {
    setRunning(true);
    try {
      await apiFetch("/api/v1/brain/pipeline/run", {
        method: "POST",
        body: JSON.stringify({ source: "manual", scan_all: true }),
      });
      setTimeout(load, 1500);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setRunning(false);
    }
  }, [load]);

  const latestRun = runs[0];
  const currentStepIdx = stepIndexFromKey(latestRun?.current_step);
  const completedSteps = latestRun?.steps_completed ?? (currentStepIdx >= 0 ? currentStepIdx : 0);

  const nodeCount = stats.total_nodes ?? stats.node_count ?? 0;
  const edgeCount = stats.total_edges ?? stats.edge_count ?? 0;
  const completed = runs.filter((r) => (r.status ?? "").toLowerCase() === "completed").length;
  const totalFindings = runs.reduce((s, r) => s + (r.total_findings ?? 0), 0);
  const totalDecisions = runs.reduce((s, r) => s + (r.decisions_made ?? 0), 0);

  const votes: ConsensusVote[] = useMemo(
    () => consensus?.members ?? consensus?.votes ?? [],
    [consensus],
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6 p-6"
    >
      <PageHeader
        title="Brain"
        description="12-step decision pipeline + Multi-LLM Council. Click a step to see what it did to the latest finding."
        badge="HERO"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("mr-2 h-4 w-4", refreshing && "animate-spin")} />
              Refresh
            </Button>
            <Button size="sm" onClick={triggerRun} disabled={running}>
              <Play className="mr-2 h-4 w-4" />
              {running ? "Starting…" : "Run Pipeline"}
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <KpiCard title="Graph Nodes" value={nodeCount.toLocaleString()} icon={Database} trend="up" />
        <KpiCard title="Graph Edges" value={edgeCount.toLocaleString()} icon={Network} trend="up" />
        <KpiCard title="Runs (recent)" value={runs.length} icon={Activity} />
        <KpiCard title="Completed" value={completed} icon={CheckCircle2} trend="up" />
        <KpiCard title="Decisions" value={totalDecisions} icon={Cpu} />
      </div>

      <Tabs value={tab} onValueChange={setTab} className="space-y-4">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          <TabsTrigger value="pipeline">12-Step Pipeline</TabsTrigger>
          <TabsTrigger value="neural">Neural Map</TabsTrigger>
          <TabsTrigger value="consensus">Multi-LLM Consensus</TabsTrigger>
          <TabsTrigger value="lab">Algorithmic Lab</TabsTrigger>
          <TabsTrigger value="predictions">Predictions</TabsTrigger>
          <TabsTrigger value="ml">ML Dashboard</TabsTrigger>
          <TabsTrigger value="score">Score Transparency</TabsTrigger>
          <TabsTrigger value="weights">Factor Weights</TabsTrigger>
        </TabsList>

        {/* ───────────────────────────────── PIPELINE TAB ─────────────────────── */}
        <TabsContent value="pipeline" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left: 12-step viz + last-run table */}
            <div className="lg:col-span-2 space-y-4">
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center justify-between">
                    <span>Pipeline (12 steps)</span>
                    {latestRun && (
                      <Badge variant="outline" className="text-[10px]">
                        latest: {latestRun.status ?? "running"} · {completedSteps}/12
                      </Badge>
                    )}
                  </CardTitle>
                  <CardDescription>
                    Click any step to inspect what it did to the most recent finding.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {loading ? (
                    <div className="grid grid-cols-3 gap-2 md:grid-cols-4 lg:grid-cols-6">
                      {Array.from({ length: 12 }).map((_, i) => (
                        <Skeleton key={i} className="h-20 w-full" />
                      ))}
                    </div>
                  ) : unavailable ? (
                    <EmptyState
                      icon={BrainIcon}
                      title="Brain pipeline endpoint not available"
                      description="`/api/v1/brain/pipeline/runs` returned 404 or 501. Brain pipeline service may not be running yet."
                    />
                  ) : (
                    <div className="grid grid-cols-3 gap-2 md:grid-cols-4 lg:grid-cols-6">
                      {PIPELINE.map((step, idx) => {
                        const Icon = step.icon;
                        const done = idx < completedSteps;
                        const current = idx === currentStepIdx;
                        return (
                          <motion.button
                            key={step.id}
                            type="button"
                            onClick={() => setActiveStep(step)}
                            initial={{ opacity: 0, y: 4 }}
                            animate={{
                              opacity: 1,
                              y: 0,
                              scale: current ? [1, 1.03, 1] : 1,
                            }}
                            transition={{
                              duration: 0.3,
                              scale: { repeat: current ? Infinity : 0, duration: 1.6 },
                            }}
                            className={cn(
                              "flex flex-col items-start gap-1.5 rounded-lg border p-3 text-left transition-colors",
                              "hover:border-primary/60 hover:bg-muted/30",
                              done && "border-emerald-500/40 bg-emerald-500/5",
                              current && "border-primary/80 bg-primary/10 shadow-md",
                              !done && !current && "border-border bg-muted/20",
                            )}
                          >
                            <div className="flex w-full items-center justify-between">
                              <Icon
                                className={cn(
                                  "h-4 w-4",
                                  done ? "text-emerald-400" : current ? "text-primary" : "text-muted-foreground",
                                )}
                              />
                              <span className="text-[10px] tabular-nums text-muted-foreground">
                                {String(step.id).padStart(2, "0")}
                              </span>
                            </div>
                            <span className="text-xs font-semibold">{step.name}</span>
                            <span className="text-[10px] text-muted-foreground line-clamp-2">{step.desc}</span>
                          </motion.button>
                        );
                      })}
                    </div>
                  )}
                  {!unavailable && !loading && latestRun && (
                    <div className="mt-4 space-y-1.5">
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>Run {latestRun.run_id ?? latestRun.id ?? "—"}</span>
                        <span>{completedSteps}/12 steps</span>
                      </div>
                      <Progress value={(completedSteps / 12) * 100} />
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Recent Runs</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  {loading ? (
                    <div className="space-y-2 p-4">
                      {Array.from({ length: 4 }).map((_, i) => (
                        <Skeleton key={i} className="h-8 w-full" />
                      ))}
                    </div>
                  ) : err ? (
                    <ErrorState message={err} onRetry={load} />
                  ) : runs.length === 0 ? (
                    <EmptyState
                      icon={Timer}
                      title="No pipeline runs yet"
                      description="Click ‘Run Pipeline’ above to trigger the first end-to-end Brain run."
                    />
                  ) : (
                    <ScrollArea className="h-[320px]">
                      <div className="divide-y divide-border">
                        {runs.map((r) => (
                          <div key={r.run_id ?? r.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-xs">
                            <span className="font-mono text-muted-foreground truncate max-w-[180px]">
                              {r.run_id ?? r.id ?? "—"}
                            </span>
                            <Badge variant="outline" className="capitalize">
                              {r.status ?? "unknown"}
                            </Badge>
                            <span className="tabular-nums text-muted-foreground">
                              {r.total_findings ?? 0} findings
                            </span>
                            <span className="tabular-nums text-muted-foreground">
                              {r.decisions_made ?? 0} decisions
                            </span>
                            <span className="text-muted-foreground truncate max-w-[140px]">
                              {r.source ?? "—"}
                            </span>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Right: Multi-LLM Council vote rail */}
            <Card className="lg:row-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  Multi-LLM Council
                </CardTitle>
                <CardDescription>
                  Latest finding consensus — 5 members + chairman + Opus escalation.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {loading ? (
                  <div className="space-y-2">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <Skeleton key={i} className="h-12 w-full" />
                    ))}
                  </div>
                ) : !consensus ? (
                  <EmptyState
                    icon={Users}
                    title="No consensus yet"
                    description="Council fires once the next finding reaches step 10. `/api/v1/llm/consensus/latest` returned no record."
                  />
                ) : (
                  <>
                    <div className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground">Decision</span>
                        <Badge variant="outline">{consensus.decision ?? "pending"}</Badge>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground">Agreement</span>
                        <span className="tabular-nums font-medium">
                          {consensus.agreement != null ? `${Math.round(consensus.agreement * 100)}%` : "—"}
                        </span>
                      </div>
                      {consensus.escalated_to && (
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted-foreground">Escalated</span>
                          <Badge variant="outline" className="border-amber-500/40 text-amber-400">
                            {consensus.escalated_to}
                          </Badge>
                        </div>
                      )}
                    </div>

                    <div className="space-y-1.5">
                      {votes.map((v, i) => (
                        <div
                          key={(v.model ?? v.name ?? "model") + i}
                          className="rounded-md border border-border bg-background/50 p-2.5 space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium">{v.model ?? v.name ?? "model"}</span>
                            <Badge variant="outline" className="text-[10px] capitalize">
                              {v.vote ?? v.decision ?? "—"}
                            </Badge>
                          </div>
                          {v.confidence != null && (
                            <Progress value={Math.round(v.confidence * 100)} className="h-1" />
                          )}
                          {v.reasoning && (
                            <p className="text-[10px] text-muted-foreground line-clamp-2">{v.reasoning}</p>
                          )}
                        </div>
                      ))}
                      {consensus.chairman && (
                        <div className="rounded-md border border-primary/40 bg-primary/5 p-2.5 space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium">
                              Chairman · {consensus.chairman.model ?? consensus.chairman.name ?? ""}
                            </span>
                            <Badge variant="outline" className="text-[10px]">
                              {consensus.chairman.vote ?? consensus.chairman.decision ?? "—"}
                            </Badge>
                          </div>
                          {consensus.chairman.reasoning && (
                            <p className="text-[10px] text-muted-foreground line-clamp-3">
                              {consensus.chairman.reasoning}
                            </p>
                          )}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            {/* Bottom-left widget: aggregated metrics */}
            <Card className="lg:col-span-2">
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  Pipeline Throughput
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4">
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Total findings ingested</p>
                    <p className="text-2xl font-semibold tabular-nums">{totalFindings.toLocaleString()}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Total decisions emitted</p>
                    <p className="text-2xl font-semibold tabular-nums">{totalDecisions.toLocaleString()}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-xs text-muted-foreground">Decision rate</p>
                    <p className="text-2xl font-semibold tabular-nums">
                      {totalFindings > 0
                        ? `${Math.round((totalDecisions / totalFindings) * 100)}%`
                        : "—"}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─────────────────────────────── COMPANION TABS ──────────────────────── */}
        <TabsContent value="neural">
          <Suspense fallback={<TabSkeleton />}><BrainVisualization /></Suspense>
        </TabsContent>
        <TabsContent value="consensus">
          <Suspense fallback={<TabSkeleton />}><MultiLLM /></Suspense>
        </TabsContent>
        <TabsContent value="lab">
          <Suspense fallback={<TabSkeleton />}><AlgorithmicLab /></Suspense>
        </TabsContent>
        <TabsContent value="predictions">
          <Suspense fallback={<TabSkeleton />}><Predictions /></Suspense>
        </TabsContent>
        <TabsContent value="ml">
          <Suspense fallback={<TabSkeleton />}><MLDashboard /></Suspense>
        </TabsContent>
        <TabsContent value="score">
          <Suspense fallback={<TabSkeleton />}><ScoreTransparencyPanel /></Suspense>
        </TabsContent>
        <TabsContent value="weights">
          <Suspense fallback={<TabSkeleton />}><FactorWeightsView /></Suspense>
        </TabsContent>
      </Tabs>

      {/* Step detail drawer */}
      {activeStep && (
        <motion.aside
          key={activeStep.id}
          initial={{ x: 480, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          exit={{ x: 480, opacity: 0 }}
          transition={{ duration: 0.25 }}
          className="fixed right-0 top-0 z-40 h-screen w-full max-w-[460px] border-l border-border bg-background shadow-2xl flex flex-col"
        >
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="min-w-0 flex items-center gap-2">
              <activeStep.icon className="h-5 w-5 text-primary shrink-0" />
              <div className="min-w-0">
                <h3 className="font-semibold truncate">
                  Step {String(activeStep.id).padStart(2, "0")}: {activeStep.name}
                </h3>
                <p className="text-xs text-muted-foreground truncate">{activeStep.desc}</p>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={() => setActiveStep(null)} aria-label="Close">
              <X className="h-4 w-4" />
            </Button>
          </div>
          <ScrollArea className="flex-1">
            <div className="p-4 space-y-3 text-sm">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">What this step does</CardTitle>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground space-y-2">
                  <p>{activeStep.desc}</p>
                  {latestRun ? (
                    <div className="space-y-1.5">
                      <div className="flex justify-between"><span>Run</span><span className="font-mono">{latestRun.run_id ?? latestRun.id}</span></div>
                      <div className="flex justify-between"><span>Status</span><Badge variant="outline" className="capitalize">{latestRun.status ?? "—"}</Badge></div>
                      <div className="flex justify-between"><span>Step idx</span><span>{activeStep.id}/12</span></div>
                      <div className="flex justify-between">
                        <span>Position</span>
                        <span className="flex items-center gap-1">
                          {activeStep.id <= completedSteps ? "completed" : activeStep.id - 1 === currentStepIdx ? "running" : "pending"}
                          <ArrowRight className="h-3 w-3" />
                        </span>
                      </div>
                    </div>
                  ) : (
                    <p className="italic">No active run — trigger one above to populate per-step telemetry.</p>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Zap className="h-3.5 w-3.5" />
                    Endpoint
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-xs">
                  <code className="block rounded bg-muted p-2 font-mono">
                    GET /api/v1/brain/pipeline/runs/&lt;run_id&gt;/steps/{activeStep.key}
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
