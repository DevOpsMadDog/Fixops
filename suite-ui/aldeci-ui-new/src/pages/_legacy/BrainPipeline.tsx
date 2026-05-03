import { useState, useEffect, useCallback } from "react";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { motion, AnimatePresence } from "framer-motion";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  Brain, Workflow, Play, CheckCircle, Clock, AlertTriangle,
  Database, Shield, Zap, Target, GitBranch, Activity,
  BarChart3, ArrowRight, RefreshCw, ChevronRight, Layers,
  FileText, Search, Eye, Network, Lock,
  XCircle, Timer, Hash, TrendingUp,
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const PIPELINE_STEPS = [
  { id: 1, name: "Ingest", desc: "SARIF/CycloneDX/SPDX ingestion & normalization", icon: Database, color: "text-blue-400", bg: "bg-blue-500/10" },
  { id: 2, name: "Parse", desc: "Multi-scanner result parsing & field mapping", icon: FileText, color: "text-blue-400", bg: "bg-blue-500/10" },
  { id: 3, name: "Normalize", desc: "Canonical schema mapping & severity standardization", icon: Layers, color: "text-cyan-400", bg: "bg-cyan-500/10" },
  { id: 4, name: "Deduplicate", desc: "Cross-scanner dedup via fingerprint + semantic match", icon: GitBranch, color: "text-cyan-400", bg: "bg-cyan-500/10" },
  { id: 5, name: "Correlate", desc: "Knowledge graph enrichment & relationship building", icon: Network, color: "text-emerald-400", bg: "bg-emerald-500/10" },
  { id: 6, name: "Enrich", desc: "CVE/EPSS/KEV threat intelligence overlay", icon: Search, color: "text-emerald-400", bg: "bg-emerald-500/10" },
  { id: 7, name: "Contextualize", desc: "APP_ID hierarchy & blast radius calculation", icon: Target, color: "text-yellow-400", bg: "bg-yellow-500/10" },
  { id: 8, name: "Decide", desc: "Multi-LLM consensus decision (triage/fix/accept/defer)", icon: Brain, color: "text-yellow-400", bg: "bg-yellow-500/10" },
  { id: 9, name: "Verify", desc: "MPTE micro-pentest validation of exploitability", icon: Shield, color: "text-orange-400", bg: "bg-orange-500/10" },
  { id: 10, name: "Remediate", desc: "AI auto-fix generation & PR creation", icon: Zap, color: "text-orange-400", bg: "bg-orange-500/10" },
  { id: 11, name: "Evidence", desc: "Quantum-signed compliance evidence bundle", icon: Lock, color: "text-red-400", bg: "bg-red-500/10" },
  { id: 12, name: "Learn", desc: "Outcome feedback loop & model retraining", icon: Activity, color: "text-red-400", bg: "bg-red-500/10" },
];

const PIE_COLORS = ["#22c55e", "#eab308", "#3b82f6", "#ef4444", "#a855f7", "#06b6d4"];

interface PipelineRun {
  run_id: string; status: string; started_at: string; completed_at?: string;
  steps_completed: number; total_findings: number; decisions_made: number; source: string;
}

export default function BrainPipeline() {
  const [runs, setRuns] = useState<PipelineRun[]>([]);
  const [stats, setStats] = useState<Record<string, unknown>>({});
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [selectedRun, setSelectedRun] = useState<PipelineRun | null>(null);
  const [activeStep, setActiveStep] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [runsRes, statsRes, healthRes] = await Promise.allSettled([
        apiClient("/api/v1/brain/pipeline/runs"),
        apiClient("/api/v1/brain/stats"),
        apiClient("/api/v1/brain/health"),
      ]);
      if (runsRes.status === "fulfilled") setRuns(toArray(runsRes.value).slice(0, 50) as unknown as PipelineRun[]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      if (healthRes.status === "fulfilled") setHealth(healthRes.value ?? {});
    } catch { /* handled */ } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  if (loading) return <PageSkeleton />;

  const triggerRun = async () => {
    setRunning(true);
    try {
      const res = await apiClient("/api/v1/brain/pipeline/run", { method: "POST", body: JSON.stringify({ source: "manual", scan_all: true }) });
      toast.success(`Pipeline run started: ${(res as Record<string, unknown>)?.run_id || "initiated"}`);
      setTimeout(fetchData, 2000);
    } catch (e: unknown) { toast.error(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`); }
    finally { setRunning(false); }
  };

  const nodeCount = Number(stats?.total_nodes ?? stats?.node_count ?? 0);
  const edgeCount = Number(stats?.total_edges ?? stats?.edge_count ?? 0);
  const healthStatus = String(health?.status ?? "operational");
  const completedCount = runs.filter(r => r.status === "completed").length;
  const avgFindings = runs.length > 0 ? Math.round(runs.reduce((s, r) => s + (r.total_findings || 0), 0) / runs.length) : 0;

  const statusCounts = (() => {
    const c: Record<string, number> = {};
    runs.forEach(r => { c[r.status || "unknown"] = (c[r.status || "unknown"] || 0) + 1; });
    return Object.entries(c).map(([name, value]) => ({ name, value }));
  })();

  const runChart = runs.slice(0, 15).reverse().map((r, i) => ({
    name: `#${i + 1}`, findings: r.total_findings || 0, decisions: r.decisions_made || 0,
  }));

  const parseTypes = (raw: unknown, fallback: Record<string, number>) => {
    const d = raw ?? fallback;
    if (Array.isArray(d)) return d.map((r: Record<string, unknown>) => ({ name: String(r.label || r.type || ""), count: Number(r.count || 0) }));
    return Object.entries(d as Record<string, unknown>).map(([name, count]) => ({ name, count: Number(count) }));
  };
  const entityTypes = parseTypes(stats?.entity_types ?? stats?.node_types, { App: 0, Finding: 0, CVE: 0, Component: 0, Evidence: 0, Decision: 0 });
  const edgeTypesData = parseTypes(stats?.edge_types ?? stats?.relationship_types, { HAS_FINDING: 0, AFFECTS: 0, REMEDIATES: 0, EVIDENCES: 0, CORRELATES: 0, ENRICHED_BY: 0 });

  return (
    <div className="space-y-6 p-6">
      <PageHeader title="Brain Pipeline" description="12-step Decision Intelligence Engine — from scanner ingestion to quantum-signed evidence" badge="AI Engine"
        actions={<div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
          <Button size="sm" onClick={triggerRun} disabled={running}><Play className="h-4 w-4 mr-1" />{running ? "Running..." : "Run Pipeline"}</Button>
        </div>} />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard title="Graph Nodes" value={nodeCount.toLocaleString()} icon={Database} trend="up" trendLabel="Growing" />
        <KpiCard title="Graph Edges" value={edgeCount.toLocaleString()} icon={Network} trend="up" trendLabel="Relationships" />
        <KpiCard title="Pipeline Runs" value={runs.length} icon={Workflow} trend="flat" trendLabel={`${completedCount} completed`} />
        <KpiCard title="Avg Findings/Run" value={avgFindings} icon={Hash} trend="flat" trendLabel="Per run" />
        <KpiCard title="Engine Health" value={healthStatus === "operational" ? "Healthy" : healthStatus} icon={Activity} trend={healthStatus === "operational" ? "up" : "down"} trendLabel={healthStatus} />
      </div>

      {/* Interactive 12-Step Pipeline Grid */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Workflow className="h-5 w-5" />12-Step Decision Pipeline</CardTitle>
          <CardDescription>Every finding flows through all 12 steps — click any step for details</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
            {PIPELINE_STEPS.map((step, idx) => {
              const Icon = step.icon;
              const isActive = activeStep === step.id;
              return (
                <TooltipProvider key={step.id}><Tooltip><TooltipTrigger asChild>
                  <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.04 }}
                    className="relative group cursor-pointer" onClick={() => setActiveStep(isActive ? null : step.id)}>
                    <div className={cn("border rounded-lg p-3 transition-all duration-200",
                      isActive ? "border-primary bg-primary/5 shadow-lg shadow-primary/10 ring-1 ring-primary/30" : "border-border/50 bg-card hover:border-primary/50 hover:bg-accent/30")}>
                      <div className="flex items-center gap-2 mb-1.5">
                        <div className={cn("p-1.5 rounded-md", step.bg, step.color)}><Icon className="h-3.5 w-3.5" /></div>
                        <Badge variant="outline" className="text-[10px] px-1.5 py-0">Step {step.id}</Badge>
                      </div>
                      <p className="text-sm font-semibold">{step.name}</p>
                      <p className="text-[11px] text-muted-foreground leading-tight mt-0.5 line-clamp-2">{step.desc}</p>
                    </div>
                    {idx < PIPELINE_STEPS.length - 1 && idx % 6 !== 5 && (
                      <ArrowRight className="absolute -right-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground/40 hidden xl:block" />
                    )}
                  </motion.div>
                </TooltipTrigger>
                <TooltipContent side="bottom" className="max-w-xs">
                  <p className="font-medium">Step {step.id}: {step.name}</p>
                  <p className="text-xs text-muted-foreground mt-1">{step.desc}</p>
                </TooltipContent></Tooltip></TooltipProvider>
              );
            })}
          </div>
          <AnimatePresence>
            {activeStep && (() => {
              const step = PIPELINE_STEPS.find(s => s.id === activeStep)!;
              const Icon = step.icon;
              return (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                  <Separator className="my-4" />
                  <div className="p-4 rounded-lg bg-accent/20 border border-border/50 flex items-start gap-4">
                    <div className={cn("p-3 rounded-xl", step.bg, step.color)}><Icon className="h-6 w-6" /></div>
                    <div className="flex-1">
                      <h3 className="font-semibold text-lg">Step {step.id}: {step.name}</h3>
                      <p className="text-sm text-muted-foreground mt-1">{step.desc}</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
                        {[{ label: "Status", value: "Active", color: "text-emerald-400" },
                          { label: "Last Run", value: runs[0]?.started_at ? new Date(runs[0].started_at).toLocaleTimeString() : "—", color: "" },
                          { label: "Items", value: String(runs[0]?.total_findings ?? 0), color: "" },
                          { label: "Duration", value: "—", color: "" },
                        ].map(m => (
                          <div key={m.label} className="text-center p-2 rounded bg-background/50">
                            <p className="text-[10px] text-muted-foreground uppercase">{m.label}</p>
                            <p className={cn("text-sm font-bold", m.color)}>{m.value}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>);
            })()}
          </AnimatePresence>
        </CardContent>
      </Card>

      <Tabs defaultValue="runs" className="space-y-4">
        <TabsList>
          <TabsTrigger value="runs">Pipeline Runs</TabsTrigger>
          <TabsTrigger value="charts">Analytics</TabsTrigger>
          <TabsTrigger value="graph">Graph Stats</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>

        <TabsContent value="runs">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <Card><CardContent className="p-0"><ScrollArea className="h-[500px]"><div className="divide-y divide-border/50">
                {runs.length === 0 && (
                  <div className="p-8 text-center text-muted-foreground">
                    <Brain className="h-12 w-12 mx-auto mb-3 opacity-40" />
                    <p className="text-sm font-medium">No pipeline runs yet</p>
                    <p className="text-xs mt-1">Click "Run Pipeline" to process ingested findings</p>
                  </div>
                )}
                {runs.map((run, i) => (
                  <motion.div key={run.run_id || i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}
                    className={cn("flex items-center justify-between p-4 cursor-pointer transition-colors", selectedRun?.run_id === run.run_id ? "bg-accent/40" : "hover:bg-accent/20")}
                    onClick={() => setSelectedRun(run)}>
                    <div className="flex items-center gap-3">
                      <div className={cn("p-2 rounded-lg", run.status === "completed" ? "bg-emerald-500/10 text-emerald-400" : run.status === "running" ? "bg-yellow-500/10 text-yellow-400" : run.status === "failed" ? "bg-red-500/10 text-red-400" : "bg-muted text-muted-foreground")}>
                        {run.status === "completed" ? <CheckCircle className="h-4 w-4" /> : run.status === "running" ? <RefreshCw className="h-4 w-4 animate-spin" /> : run.status === "failed" ? <XCircle className="h-4 w-4" /> : <Clock className="h-4 w-4" />}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{run.run_id || `Run ${i + 1}`}</p>
                        <p className="text-xs text-muted-foreground">{run.source || "manual"} · {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 text-xs">
                      <div className="text-right"><p className="font-medium">{run.steps_completed || 12}/12</p><p className="text-muted-foreground">{run.total_findings || 0} findings</p></div>
                      <Badge variant={run.status === "completed" ? "default" : run.status === "failed" ? "destructive" : "secondary"}>{run.status || "pending"}</Badge>
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    </div>
                  </motion.div>
                ))}
              </div></ScrollArea></CardContent></Card>
            </div>
            <Card>
              <CardHeader><CardTitle className="text-sm">Run Details</CardTitle></CardHeader>
              <CardContent>
                {selectedRun ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <Badge variant={selectedRun.status === "completed" ? "default" : "secondary"}>{selectedRun.status}</Badge>
                      <span className="text-xs text-muted-foreground font-mono">{selectedRun.run_id}</span>
                    </div>
                    {[{ l: "Source", v: selectedRun.source || "manual" }, { l: "Started", v: selectedRun.started_at ? new Date(selectedRun.started_at).toLocaleString() : "—" },
                      { l: "Completed", v: selectedRun.completed_at ? new Date(selectedRun.completed_at).toLocaleString() : "—" },
                      { l: "Steps", v: `${selectedRun.steps_completed || 12} / 12` }, { l: "Findings", v: String(selectedRun.total_findings || 0) }, { l: "Decisions", v: String(selectedRun.decisions_made || 0) },
                    ].map(item => (
                      <div key={item.l} className="flex justify-between text-sm py-1.5 border-b border-border/30"><span className="text-muted-foreground">{item.l}</span><span className="font-medium">{item.v}</span></div>
                    ))}
                    <div className="mt-2"><p className="text-xs text-muted-foreground mb-1">Progress</p>
                      <Progress value={((selectedRun.steps_completed || 12) / 12) * 100} className="h-2" />
                      <div className="flex justify-between text-[10px] text-muted-foreground mt-1"><span>Ingest</span><span>Learn</span></div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-12 text-muted-foreground"><Eye className="h-8 w-8 mx-auto mb-2 opacity-40" /><p className="text-sm">Select a run</p></div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="charts">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><BarChart3 className="h-4 w-4" />Run History</CardTitle>
                <CardDescription>Findings and decisions per pipeline run</CardDescription></CardHeader>
              <CardContent>{runChart.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={runChart}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="findings" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Findings" />
                    <Bar dataKey="decisions" fill="#22c55e" radius={[4, 4, 0, 0]} name="Decisions" />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                  </BarChart>
                </ResponsiveContainer>
              ) : <div className="h-[280px] flex items-center justify-center text-muted-foreground text-sm">No data yet</div>}</CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><TrendingUp className="h-4 w-4" />Status Distribution</CardTitle>
                <CardDescription>Pipeline run outcomes</CardDescription></CardHeader>
              <CardContent>{statusCounts.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart><Pie data={statusCounts} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={3} dataKey="value"
                    label={({ name, value }: { name: string; value: number }) => `${name} (${value})`}>
                    {statusCounts.map((_, idx) => <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />)}
                  </Pie><RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} /></PieChart>
                </ResponsiveContainer>
              ) : <div className="h-[280px] flex items-center justify-center text-muted-foreground text-sm">No runs</div>}</CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="graph">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Database className="h-4 w-4" />Entity Types</CardTitle></CardHeader>
              <CardContent>
                {entityTypes.some(e => e.count > 0) && (<><ResponsiveContainer width="100%" height={200}>
                  <BarChart data={entityTypes} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis type="number" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 10 }} width={90} stroke="hsl(var(--muted-foreground))" />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                  </BarChart></ResponsiveContainer><Separator className="my-3" /></>)}
                <div className="space-y-1.5">{entityTypes.map(({ name, count }) => (
                  <div key={name} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                    <span className="text-sm">{name}</span><Badge variant="outline">{count}</Badge></div>
                ))}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Network className="h-4 w-4" />Relationship Types</CardTitle></CardHeader>
              <CardContent>
                {edgeTypesData.some(e => e.count > 0) && (<><ResponsiveContainer width="100%" height={200}>
                  <BarChart data={edgeTypesData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis type="number" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis type="category" dataKey="name" tick={{ fontSize: 10 }} width={110} stroke="hsl(var(--muted-foreground))" />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="count" fill="#22c55e" radius={[0, 4, 4, 0]} />
                  </BarChart></ResponsiveContainer><Separator className="my-3" /></>)}
                <div className="space-y-1.5">{edgeTypesData.map(({ name, count }) => (
                  <div key={name} className="flex items-center justify-between py-1.5 border-b border-border/30 last:border-0">
                    <span className="text-sm font-mono text-xs">{name}</span><Badge variant="outline">{count}</Badge></div>
                ))}</div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="config">
          <Card><CardContent className="p-6"><div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[{ label: "Deduplication", desc: "Cross-scanner fingerprint + semantic matching", enabled: true, icon: GitBranch },
              { label: "Threat Enrichment", desc: "EPSS, KEV, MITRE ATT&CK overlay", enabled: true, icon: Search },
              { label: "Multi-LLM Consensus", desc: "3+ LLM voting for triage decisions", enabled: true, icon: Brain },
              { label: "MPTE Verification", desc: "Micro-pentest exploitability proof", enabled: true, icon: Shield },
              { label: "Auto-Fix Generation", desc: "AI-powered code fix PRs", enabled: true, icon: Zap },
              { label: "Quantum Signing", desc: "ML-DSA + RSA hybrid evidence signatures", enabled: true, icon: Lock },
              { label: "Self-Learning", desc: "Outcome feedback adjusts future decisions", enabled: true, icon: Activity },
              { label: "Continuous Pipeline", desc: "Auto-trigger on new scan results", enabled: false, icon: Timer },
            ].map(cfg => { const I = cfg.icon; return (
              <div key={cfg.label} className="flex items-center justify-between p-3 border border-border/50 rounded-lg hover:bg-accent/20 transition-colors">
                <div className="flex items-center gap-3"><div className="p-2 rounded-lg bg-muted"><I className="h-4 w-4 text-muted-foreground" /></div>
                  <div><p className="text-sm font-medium">{cfg.label}</p><p className="text-xs text-muted-foreground">{cfg.desc}</p></div></div>
                <Badge variant={cfg.enabled ? "default" : "outline"}>{cfg.enabled ? "Enabled" : "Disabled"}</Badge>
              </div>); })}
          </div></CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
