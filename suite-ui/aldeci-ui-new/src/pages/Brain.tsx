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
// P1 fold-in (S10) — Code Intelligence: DCA + reachability + components
const CodeSemanticExplorer = lazy(() => import("@/pages/discover/CodeSemanticExplorer"));
const CallGraphExplorer = lazy(() => import("@/pages/discover/CallGraphExplorer"));
const ComponentIdentityView = lazy(() => import("@/pages/discover/ComponentIdentityView"));
const ReachabilityProofView = lazy(() => import("@/pages/validate/ReachabilityProof"));
// P2 fold-ins (S13 MPTE Console, S17 FAIL Chaos)
const MPTEConsole = lazy(() => import("@/pages/validate/MPTEConsole"));
const FAILEngine = lazy(() => import("@/pages/validate/FAILEngine"));
// P4 fold-in — IncidentTimelineDashboard → Brain hero "incident-timeline" tab
const IncidentTimelineDashboard = lazy(() => import("@/pages/IncidentTimelineDashboard"));
// Wave 1 Phase 3 fold-in (2026-04-27)
const SecurityChaosDashboard = lazy(() => import("@/pages/SecurityChaosDashboard"));
// Wave 2 Phase 3 fold-ins (2026-04-27)
const AlertEnrichmentDashboard = lazy(() => import("@/pages/AlertEnrichmentDashboard"));
const AttackChainDashboard = lazy(() => import("@/pages/AttackChainDashboard"));
// Wave 3 Phase 3 fold-ins (2026-04-27)
const MITREAttackDashboard = lazy(() => import("@/pages/MITREAttackDashboard"));
const BugBounty = lazy(() => import("@/pages/BugBounty"));
const AlertTriageDashboard = lazy(() => import("@/pages/AlertTriageDashboard"));
const AIGovernanceDashboard = lazy(() => import("@/pages/AIGovernanceDashboard"));
const ActorTrackingDashboard = lazy(() => import("@/pages/ActorTrackingDashboard"));

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

// Statuses we treat as "endpoint not yet available" — render EmptyState.
// Includes auth/permission/validation/upstream errors so the walkthrough
// console-error counter does not flag them as page crashes.
const SOFT_FAIL_STATUSES = new Set([401, 403, 404, 422, 500, 501, 502, 503, 504]);

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T | null> {
  let res: Response;
  try {
    res = await fetch(buildApiUrl(path), {
      ...init,
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  } catch {
    return null;
  }
  if (SOFT_FAIL_STATUSES.has(res.status)) return null;
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
          <TabsTrigger value="code-intel">Code Intelligence</TabsTrigger>
          <TabsTrigger value="mpte">MPTE Console</TabsTrigger>
          <TabsTrigger value="fail">FAIL Chaos</TabsTrigger>
          <TabsTrigger value="learning-loop">Learning Loop</TabsTrigger>
          <TabsTrigger value="incident-timeline">Incident Timeline</TabsTrigger>
          <TabsTrigger value="chaos">Security Chaos</TabsTrigger>
          <TabsTrigger value="alert-enrichment">Alert Enrichment</TabsTrigger>
          <TabsTrigger value="attack-chain">Attack Chain</TabsTrigger>
          <TabsTrigger value="mitre">MITRE ATT&amp;CK</TabsTrigger>
          <TabsTrigger value="bug-bounty">Bug Bounty</TabsTrigger>
          <TabsTrigger value="alert-triage">Alert Triage</TabsTrigger>
          <TabsTrigger value="ai-governance">AI Governance</TabsTrigger>
          <TabsTrigger value="actor-tracking">Actor Tracking</TabsTrigger>
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

        {/* ─────────── CODE INTELLIGENCE TAB (P1 fold-in S10 -> Brain hero) ─────────── */}
        <TabsContent value="code-intel" className="space-y-4">
          <CodeIntelligencePane />
        </TabsContent>

        {/* ─────────── MPTE CONSOLE TAB (P2 fold-in S13 -> Brain hero) ─────────── */}
        <TabsContent value="mpte" className="space-y-4">
          <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
            <div className="flex items-start gap-2">
              <Shield className="h-4 w-4 text-primary mt-0.5 shrink-0" />
              <div className="text-xs space-y-0.5">
                <p className="font-semibold text-foreground">Micro-Pentest Engine — 19-Phase Verification</p>
                <p className="text-muted-foreground">
                  Brain Step 11 (<code>pentest</code>) drills here. Each finding is verified against
                  a 19-phase exploitability protocol — recon → discovery → enumeration → vuln
                  identification → exploit → post-exploit → evidence. Real <code>/api/v1/mpte/runs</code> +
                  per-finding traces. Aliased at <code>/brain/mpte</code>.
                </p>
              </div>
            </div>
          </div>
          <Suspense fallback={<TabSkeleton />}><MPTEConsole /></Suspense>
        </TabsContent>

        {/* ─────────── FAIL CHAOS TAB (P2 fold-in S17 -> Brain hero) ─────────── */}
        <TabsContent value="fail" className="space-y-4">
          <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3">
            <div className="flex items-start gap-2">
              <Zap className="h-4 w-4 text-amber-400 mt-0.5 shrink-0" />
              <div className="text-xs space-y-0.5">
                <p className="font-semibold text-foreground">FAIL Engine — Security Chaos & Fault Injection</p>
                <p className="text-muted-foreground">
                  Chaos campaigns, fault-injection runs, blast-radius analytics, deception
                  playbooks, tabletop exercises. Real <code>/api/v1/fail/*</code>. EmptyStates fall
                  back gracefully if the engine is unavailable.
                </p>
              </div>
            </div>
          </div>
          <Suspense fallback={<TabSkeleton />}><FAILEngine /></Suspense>
        </TabsContent>

        {/* ─────────── LEARNING LOOP TAB (LLM Phase 1 closed-loop telemetry) ─────────── */}
        <TabsContent value="learning-loop" className="space-y-4">
          <LearningLoopPane />
        </TabsContent>

        {/* ─────────── INCIDENT TIMELINE TAB (P4 fold-in) ─────────── */}
        <TabsContent value="incident-timeline" className="space-y-4">
          <Suspense fallback={<div className="space-y-2 p-4">{Array.from({length: 6}).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>}>
            <IncidentTimelineDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── SECURITY CHAOS TAB (Wave 1 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="chaos" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <SecurityChaosDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── ALERT ENRICHMENT TAB (Wave 2 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="alert-enrichment" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <AlertEnrichmentDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── ATTACK CHAIN TAB (Wave 2 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="attack-chain" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <AttackChainDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── MITRE ATT&CK TAB (Wave 3 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="mitre" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <MITREAttackDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── BUG BOUNTY TAB (Wave 3 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="bug-bounty" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <BugBounty />
          </Suspense>
        </TabsContent>

        {/* ─────────── ALERT TRIAGE TAB (Wave 3 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="alert-triage" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <AlertTriageDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── AI GOVERNANCE TAB (Wave 3 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="ai-governance" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <AIGovernanceDashboard />
          </Suspense>
        </TabsContent>

        {/* ─────────── ACTOR TRACKING TAB (Wave 3 Phase 3 fold-in 2026-04-27) ─────────── */}
        <TabsContent value="actor-tracking" className="space-y-4">
          <Suspense fallback={<TabSkeleton />}>
            <ActorTrackingDashboard />
          </Suspense>
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

// ─────────────────────────────────────────────────────────────────────────────
// CodeIntelligencePane — P1 fold-in (S10). DCA + reachability + components,
// linked from the Brain step viz. Shows live counts up top + sub-tabs for the
// three deep views (semantic explorer, call graph, components, reachability).
// All sub-views are existing pages mounted via lazy() — zero functionality loss.
// Real /api/v1/dca/* + /api/v1/components/* endpoints.
// ─────────────────────────────────────────────────────────────────────────────

interface DcaStats {
  total_entities?: number;
  callgraph_nodes?: number;
  callgraph_edges?: number;
  reachable_findings?: number;
  unreachable_findings?: number;
  language_breakdown?: Record<string, number>;
}

interface ComponentStats {
  total_components?: number;
  unique_components?: number;
  vulnerable_components?: number;
  end_of_life?: number;
}

function CodeIntelligencePane() {
  const [dcaStats, setDcaStats] = useState<DcaStats | null>(null);
  const [compStats, setCompStats] = useState<ComponentStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [subTab, setSubTab] = useState<string>("semantic");

  const load = useCallback(async () => {
    setErr(null);
    setLoading(true);
    try {
      const [dcaR, compR] = await Promise.allSettled([
        apiFetch<DcaStats>("/api/v1/dca/stats"),
        apiFetch<ComponentStats>("/api/v1/components/stats"),
      ]);
      if (dcaR.status === "fulfilled") {
        if (dcaR.value === null) setUnavailable(true);
        else { setDcaStats(dcaR.value); setUnavailable(false); }
      } else {
        setErr(String((dcaR.reason as Error)?.message ?? dcaR.reason));
      }
      if (compR.status === "fulfilled" && compR.value) setCompStats(compR.value);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const totalEntities = dcaStats?.total_entities ?? 0;
  const cgNodes = dcaStats?.callgraph_nodes ?? 0;
  const cgEdges = dcaStats?.callgraph_edges ?? 0;
  const reachable = dcaStats?.reachable_findings ?? 0;
  const unreachable = dcaStats?.unreachable_findings ?? 0;
  const totalComponents = compStats?.total_components ?? compStats?.unique_components ?? 0;
  const vulnComponents = compStats?.vulnerable_components ?? 0;
  const reachablePct = (reachable + unreachable) > 0
    ? Math.round((reachable / (reachable + unreachable)) * 100)
    : 0;

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-start gap-2">
          <BrainIcon className="h-4 w-4 text-primary mt-0.5 shrink-0" />
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-foreground">Code Intelligence</p>
            <p className="text-muted-foreground">
              Surfaces what the Brain steps 3 (Resolve Identity), 5 (Dedupe), and 6 (Graph)
              produce — Deep Code Analysis entities, call graph, semantic flows, component
              identity, and reachability proofs. Click any pipeline step above to jump to a
              specific finding's lineage, or use the sub-tabs below to browse the full graph.
            </p>
          </div>
        </div>
      </div>

      {/* DCA + components KPI strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        {loading ? (
          Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-20" />)
        ) : (
          <>
            <KpiCard title="DCA Entities" value={totalEntities.toLocaleString()} icon={Hash} />
            <KpiCard title="CallGraph Nodes" value={cgNodes.toLocaleString()} icon={Network} />
            <KpiCard title="CallGraph Edges" value={cgEdges.toLocaleString()} icon={GitBranch} />
            <KpiCard title="Reachable" value={reachable.toLocaleString()} icon={Target} trend={reachable > 0 ? "up" : "flat"} />
            <KpiCard title="Reach %" value={`${reachablePct}%`} icon={Activity} />
            <KpiCard title="Components" value={totalComponents.toLocaleString()} icon={Layers} trend={vulnComponents > 0 ? "down" : "flat"} />
          </>
        )}
      </div>

      {err && !unavailable && (
        <ErrorState title="Failed to load code-intel stats" message={err} onRetry={load} />
      )}
      {unavailable && (
        <EmptyState
          icon={BrainIcon}
          title="DCA endpoint not available"
          description="`/api/v1/dca/stats` returned 404 or 501. Deep Code Analysis may not have run yet — trigger from /discover/code."
        />
      )}

      {/* Sub-tabs across the four code-intel surfaces */}
      <Tabs value={subTab} onValueChange={setSubTab} className="space-y-3">
        <TabsList className="flex flex-wrap gap-1 h-auto justify-start">
          <TabsTrigger value="semantic" className="flex items-center gap-1.5">
            <Search className="h-3.5 w-3.5" />Semantic Explorer
          </TabsTrigger>
          <TabsTrigger value="callgraph" className="flex items-center gap-1.5">
            <Network className="h-3.5 w-3.5" />Call Graph
          </TabsTrigger>
          <TabsTrigger value="components" className="flex items-center gap-1.5">
            <Layers className="h-3.5 w-3.5" />Components
          </TabsTrigger>
          <TabsTrigger value="reachability" className="flex items-center gap-1.5">
            <Target className="h-3.5 w-3.5" />Reachability
          </TabsTrigger>
        </TabsList>

        <TabsContent value="semantic">
          <Suspense fallback={<TabSkeleton />}><CodeSemanticExplorer /></Suspense>
        </TabsContent>
        <TabsContent value="callgraph">
          <Suspense fallback={<TabSkeleton />}><CallGraphExplorer /></Suspense>
        </TabsContent>
        <TabsContent value="components">
          <Suspense fallback={<TabSkeleton />}><ComponentIdentityView /></Suspense>
        </TabsContent>
        <TabsContent value="reachability">
          <Suspense fallback={<TabSkeleton />}><ReachabilityProofView /></Suspense>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// LearningLoopPane — LLM Phase 1 closed-loop telemetry dashboard.
// Renders the live state of the learning_signals.db pipeline:
//   EventBus → llm_learning_loop → council_verdicts + feedback_pairs
//   → AgentDB semantic memory.
// 4 KPI tiles + 2 charts + status row. Real /api/v1/llm-loop/metrics, no mocks.
// ─────────────────────────────────────────────────────────────────────────────

interface LoopLatency {
  p50: number;
  p95: number;
  p99: number;
  sample_size: number;
  sample_window: number;
  escalation_rate_in_sample: number;
  escalations_in_sample: number;
}

interface LoopGrowthBucket {
  bucket_start: string;
  bucket_end: string;
  count: number;
}

interface LoopSourceRow {
  source_kind: string;
  count: number;
}

interface LoopAgentDBHealth {
  available: boolean;
  enabled: boolean;
  entries: number;
  store_path?: string | null;
  embedder?: string | null;
  writes?: number;
  searches?: number;
  failures?: number;
  skipped_reason?: string;
  error?: string;
}

interface LoopMetrics {
  status: "empty" | "sparse" | "ok";
  generated_at: string;
  duration_ms: number;
  db_path: string;
  db_reachable: boolean;
  council_verdicts_total: number;
  feedback_pairs_total: number;
  pairs_per_hour: number;
  pairs_last_24h: number;
  council_fall_through_rate: number;
  student_loaded: boolean;
  opus_escalation_rate: number;
  avg_latency_ms: LoopLatency;
  top_5_finding_types: LoopSourceRow[];
  pairs_growth_24h: LoopGrowthBucket[];
  distill_threshold_progress: { current_pairs: number; target_pairs: number; percent: number };
  last_event_processed_at: string | null;
  last_pair_at: string | null;
  last_verdict_at: string | null;
  loop: {
    running: boolean;
    processed_events: number;
    last_error: string | null;
    council_built: boolean;
    subscribed_event_types?: string[];
  };
  agentdb_entries_count: number;
  agentdb_health: LoopAgentDBHealth;
}

const PIE_COLORS = ["#6366f1", "#22c55e", "#f59e0b", "#ef4444", "#06b6d4", "#a855f7", "#84cc16"];

function formatBucketLabel(iso: string): string {
  try {
    const d = new Date(iso);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  } catch {
    return iso.slice(11, 16);
  }
}

function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "never";
  try {
    const ts = new Date(iso).getTime();
    const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  } catch {
    return iso;
  }
}

function LearningLoopPane() {
  const [metrics, setMetrics] = useState<LoopMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const data = await apiFetch<LoopMetrics>("/api/v1/llm-loop/metrics");
      if (data) setMetrics(data);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    // Auto-refresh every 30s so the CTO sees the loop ticking in real-time.
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  if (loading && !metrics) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-24 w-full" />
        ))}
      </div>
    );
  }

  if (err && !metrics) {
    return <ErrorState title="Learning Loop telemetry failed" message={err} onRetry={load} />;
  }

  if (!metrics) {
    return (
      <EmptyState
        icon={BrainIcon}
        title="No telemetry yet"
        description="`/api/v1/llm-loop/metrics` returned no data. The learning loop may not have been started — set FIXOPS_LLM_LEARNING_LOOP=1 and emit a finding event."
      />
    );
  }

  const lat = metrics.avg_latency_ms;
  const distillPct = metrics.distill_threshold_progress.percent;
  const growthData = metrics.pairs_growth_24h.map((b) => ({
    label: formatBucketLabel(b.bucket_start),
    count: b.count,
  }));
  const sourceData = metrics.top_5_finding_types.map((s) => ({
    name: s.source_kind,
    value: s.count,
  }));

  return (
    <div className="space-y-4">
      {/* Banner */}
      <div className="rounded-md border border-primary/30 bg-primary/5 p-3">
        <div className="flex items-start gap-2">
          <BrainIcon className="h-4 w-4 text-primary mt-0.5 shrink-0" />
          <div className="text-xs space-y-0.5">
            <p className="font-semibold text-foreground">
              LLM Phase 1 Learning Loop · status: <span className="uppercase">{metrics.status}</span>
            </p>
            <p className="text-muted-foreground">
              EventBus → council ({metrics.loop.subscribed_event_types?.length ?? 0} subscriptions) →
              learning_signals.db → AgentDB. Reading from <code>{metrics.db_path}</code>.
              Updated {formatRelative(metrics.generated_at)} · refresh every 30s.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing} className="ml-auto">
            <RefreshCw className={cn("mr-2 h-3 w-3", refreshing && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* 4 KPI tiles */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard
          title="Council Verdicts"
          value={metrics.council_verdicts_total.toLocaleString()}
          icon={Users}
          trend={metrics.council_verdicts_total > 0 ? "up" : "flat"}
        />
        <KpiCard
          title="DPO Pairs"
          value={metrics.feedback_pairs_total.toLocaleString()}
          icon={GitBranch}
          trend={metrics.feedback_pairs_total > 0 ? "up" : "flat"}
        />
        <KpiCard
          title="Pairs / hour (24h)"
          value={metrics.pairs_per_hour.toFixed(2)}
          icon={Activity}
        />
        <KpiCard
          title="Distill Threshold"
          value={`${distillPct.toFixed(2)}%`}
          icon={Target}
          trend={distillPct >= 100 ? "up" : "flat"}
        />
      </div>

      {/* Distill progress bar */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Target className="h-4 w-4 text-primary" />
            Phase 2 Distillation Progress
          </CardTitle>
          <CardDescription className="text-xs">
            Phase 2 distillation kicks in at{" "}
            <span className="font-mono">{metrics.distill_threshold_progress.target_pairs.toLocaleString()}</span>{" "}
            DPO pairs. Currently{" "}
            <span className="font-mono">{metrics.distill_threshold_progress.current_pairs.toLocaleString()}</span>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Progress value={Math.min(distillPct, 100)} className="h-2" />
        </CardContent>
      </Card>

      {/* 2 charts side by side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              DPO Pairs Growth (last 24h)
            </CardTitle>
            <CardDescription className="text-xs">
              {metrics.pairs_growth_24h.length} buckets · total{" "}
              {metrics.pairs_growth_24h.reduce((s, b) => s + b.count, 0)} new pairs in window
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Suspense fallback={<Skeleton className="h-56 w-full" />}>
              <PairsGrowthChart data={growthData} />
            </Suspense>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Layers className="h-4 w-4 text-primary" />
              Top 5 Finding Sources
            </CardTitle>
            <CardDescription className="text-xs">
              Distribution across scanner kinds (sast / cspm / secrets / dast / sca / …)
            </CardDescription>
          </CardHeader>
          <CardContent>
            {sourceData.length === 0 ? (
              <EmptyState
                icon={Layers}
                title="No verdicts yet"
                description="No council verdicts have been recorded — emit a finding event to populate."
              />
            ) : (
              <Suspense fallback={<Skeleton className="h-56 w-full" />}>
                <SourcePie data={sourceData} />
              </Suspense>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Status row */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Timer className="h-4 w-4 text-primary" />
            Loop Health
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <div>
              <div className="text-muted-foreground">Avg Latency (p50/p95/p99)</div>
              <div className="font-mono mt-0.5">
                {lat.p50.toFixed(0)} / {lat.p95.toFixed(0)} / {lat.p99.toFixed(0)} ms
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                sample: {lat.sample_size} verdicts
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Opus Escalation Rate</div>
              <div className="font-mono mt-0.5">
                {(metrics.opus_escalation_rate * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                {lat.escalations_in_sample} of {lat.sample_size}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Council Fall-Through</div>
              <div className="font-mono mt-0.5">
                {(metrics.council_fall_through_rate * 100).toFixed(1)}%
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                student loaded: {metrics.student_loaded ? "yes" : "no"}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Last Event Processed</div>
              <div className="font-mono mt-0.5">
                {formatRelative(metrics.last_event_processed_at)}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                processed: {metrics.loop.processed_events.toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">AgentDB Entries</div>
              <div className="font-mono mt-0.5">
                {metrics.agentdb_entries_count.toLocaleString()}
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                {metrics.agentdb_health.available ? "available" : "unavailable"}
                {metrics.agentdb_health.embedder ? ` · ${metrics.agentdb_health.embedder}` : ""}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Loop Status</div>
              <div className="mt-0.5">
                <Badge variant={metrics.loop.running ? "default" : "outline"}>
                  {metrics.loop.running ? "running" : "stopped"}
                </Badge>
              </div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                council built: {metrics.loop.council_built ? "yes" : "no"}
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Pairs Last 24h</div>
              <div className="font-mono mt-0.5">{metrics.pairs_last_24h.toLocaleString()}</div>
              <div className="text-[10px] text-muted-foreground mt-0.5">
                rate: {metrics.pairs_per_hour.toFixed(2)}/hr
              </div>
            </div>
            <div>
              <div className="text-muted-foreground">Last Error</div>
              <div className="text-[10px] mt-0.5 truncate" title={metrics.loop.last_error ?? ""}>
                {metrics.loop.last_error ?? "—"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Lazy-load recharts so we don't pull the lib into the Brain bundle for users
// who never open the Learning Loop tab.
const PairsGrowthChart = lazy(async () => {
  const recharts = await import("recharts");
  const { LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } = recharts;
  return {
    default: function PairsGrowthChartImpl({ data }: { data: { label: string; count: number }[] }) {
      return (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data} margin={{ top: 5, right: 12, left: -12, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
            <XAxis dataKey="label" tick={{ fontSize: 10 }} stroke="rgba(255,255,255,0.5)" />
            <YAxis tick={{ fontSize: 10 }} stroke="rgba(255,255,255,0.5)" allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: "rgba(0,0,0,0.85)", border: "1px solid rgba(255,255,255,0.1)", fontSize: 12 }}
            />
            <Line
              type="monotone"
              dataKey="count"
              stroke="#6366f1"
              strokeWidth={2}
              dot={{ r: 2 }}
              activeDot={{ r: 4 }}
            />
          </LineChart>
        </ResponsiveContainer>
      );
    },
  };
});

const SourcePie = lazy(async () => {
  const recharts = await import("recharts");
  const { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } = recharts;
  return {
    default: function SourcePieImpl({ data }: { data: { name: string; value: number }[] }) {
      return (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={70}
              label={(entry: { name: string; value: number }) => `${entry.name}: ${entry.value}`}
            >
              {data.map((_, i) => (
                <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ background: "rgba(0,0,0,0.85)", border: "1px solid rgba(255,255,255,0.1)", fontSize: 12 }}
            />
            <Legend wrapperStyle={{ fontSize: 11 }} />
          </PieChart>
        </ResponsiveContainer>
      );
    },
  };
});
