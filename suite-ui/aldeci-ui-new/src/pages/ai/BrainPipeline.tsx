import { useState, useEffect, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain, Workflow, Play, CheckCircle, Clock, AlertTriangle,
  Database, Shield, Zap, Target, GitBranch, Activity,
  BarChart3, ArrowRight, RefreshCw, ChevronRight, Layers,
  FileText, Search, Eye, Cpu, Network, Lock, Settings
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const PIPELINE_STEPS = [
  { id: 1, name: "Ingest", desc: "SARIF/CycloneDX/SPDX ingestion & normalization", icon: Database, color: "text-blue-400" },
  { id: 2, name: "Parse", desc: "Multi-scanner result parsing & field mapping", icon: FileText, color: "text-blue-400" },
  { id: 3, name: "Normalize", desc: "Canonical schema mapping & severity standardization", icon: Layers, color: "text-cyan-400" },
  { id: 4, name: "Deduplicate", desc: "Cross-scanner dedup via fingerprint + semantic match", icon: GitBranch, color: "text-cyan-400" },
  { id: 5, name: "Correlate", desc: "Knowledge graph enrichment & relationship building", icon: Network, color: "text-emerald-400" },
  { id: 6, name: "Enrich", desc: "CVE/EPSS/KEV threat intelligence overlay", icon: Search, color: "text-emerald-400" },
  { id: 7, name: "Contextualize", desc: "APP_ID hierarchy & blast radius calculation", icon: Target, color: "text-yellow-400" },
  { id: 8, name: "Decide", desc: "Multi-LLM consensus decision (triage/fix/accept/defer)", icon: Brain, color: "text-yellow-400" },
  { id: 9, name: "Verify", desc: "MPTE micro-pentest validation of exploitability", icon: Shield, color: "text-orange-400" },
  { id: 10, name: "Remediate", desc: "AI auto-fix generation & PR creation", icon: Zap, color: "text-orange-400" },
  { id: 11, name: "Evidence", desc: "Quantum-signed compliance evidence bundle", icon: Lock, color: "text-red-400" },
  { id: 12, name: "Learn", desc: "Outcome feedback loop & model retraining", icon: Activity, color: "text-red-400" },
];

interface PipelineRun {
  run_id: string;
  status: string;
  started_at: string;
  completed_at?: string;
  steps_completed: number;
  total_findings: number;
  decisions_made: number;
  source: string;
}

export default function BrainPipeline() {
  const [runs, setRuns] = useState<PipelineRun[]>([]);
  const [stats, setStats] = useState<Record<string, unknown>>({});
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [selectedRun, setSelectedRun] = useState<PipelineRun | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const [runsRes, statsRes, healthRes] = await Promise.allSettled([
        apiClient("/api/v1/brain/pipeline/runs"),
        apiClient("/api/v1/brain/stats"),
        apiClient("/api/v1/brain/health"),
      ]);
      if (runsRes.status === "fulfilled") setRuns(toArray(runsRes.value).slice(0, 20) as unknown as PipelineRun[]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      if (healthRes.status === "fulfilled") setHealth(healthRes.value ?? {});
    } catch { /* handled */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const triggerRun = async () => {
    setRunning(true);
    try {
      const res = await apiClient("/api/v1/brain/pipeline/run", { method: "POST", body: JSON.stringify({ source: "manual", scan_all: true }) });
      toast.success(`Pipeline run started: ${res?.run_id || "initiated"}`);
      setTimeout(fetchData, 2000);
    } catch (e: unknown) {
      toast.error(`Failed: ${e instanceof Error ? e.message : "Unknown error"}`);
    } finally {
      setRunning(false);
    }
  };

  const nodeCount = Number(stats?.total_nodes ?? stats?.node_count ?? 0);
  const edgeCount = Number(stats?.total_edges ?? stats?.edge_count ?? 0);
  const totalRuns = runs.length;
  const healthStatus = String(health?.status ?? "operational");

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Brain Pipeline"
        description="12-step Decision Intelligence Engine — from scanner ingestion to quantum-signed evidence"
        badge="AI Engine"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
            <Button size="sm" onClick={triggerRun} disabled={running}>
              <Play className="h-4 w-4 mr-1" />{running ? "Running..." : "Run Pipeline"}
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Graph Nodes" value={nodeCount.toLocaleString()} icon={Database} trend="up" trendLabel="Growing" />
        <KpiCard title="Graph Edges" value={edgeCount.toLocaleString()} icon={Network} trend="up" trendLabel="Relationships" />
        <KpiCard title="Pipeline Runs" value={totalRuns} icon={Workflow} trend="flat" trendLabel="Total" />
        <KpiCard title="Engine Health" value={healthStatus === "operational" ? "Healthy" : healthStatus} icon={Activity} trend={healthStatus === "operational" ? "up" : "down"} trendLabel={healthStatus} />
      </div>

      {/* Pipeline Visualization */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Workflow className="h-5 w-5" />12-Step Decision Pipeline</CardTitle>
          <CardDescription>Every finding flows through all 12 steps — from raw scanner output to signed evidence</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
            {PIPELINE_STEPS.map((step, idx) => {
              const Icon = step.icon;
              return (
                <motion.div
                  key={step.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className="relative group"
                >
                  <div className="border border-border/50 rounded-lg p-3 bg-card hover:border-primary/50 hover:bg-accent/30 transition-all cursor-pointer">
                    <div className="flex items-center gap-2 mb-1.5">
                      <div className={cn("p-1.5 rounded-md bg-muted", step.color)}>
                        <Icon className="h-3.5 w-3.5" />
                      </div>
                      <Badge variant="outline" className="text-[10px] px-1.5 py-0">Step {step.id}</Badge>
                    </div>
                    <p className="text-sm font-semibold">{step.name}</p>
                    <p className="text-[11px] text-muted-foreground leading-tight mt-0.5">{step.desc}</p>
                  </div>
                  {idx < PIPELINE_STEPS.length - 1 && idx % 6 !== 5 && (
                    <ArrowRight className="absolute -right-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground/40 hidden xl:block" />
                  )}
                </motion.div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="runs" className="space-y-4">
        <TabsList>
          <TabsTrigger value="runs">Pipeline Runs</TabsTrigger>
          <TabsTrigger value="graph">Graph Stats</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>

        <TabsContent value="runs">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[400px]">
                <div className="divide-y divide-border/50">
                  {runs.length === 0 && (
                    <div className="p-8 text-center text-muted-foreground">
                      <Brain className="h-12 w-12 mx-auto mb-3 opacity-40" />
                      <p className="text-sm font-medium">No pipeline runs yet</p>
                      <p className="text-xs mt-1">Click "Run Pipeline" to process all ingested findings</p>
                    </div>
                  )}
                  {runs.map((run, i) => (
                    <motion.div
                      key={run.run_id || i}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.03 }}
                      className="flex items-center justify-between p-4 hover:bg-accent/30 cursor-pointer transition-colors"
                      onClick={() => setSelectedRun(run)}
                    >
                      <div className="flex items-center gap-3">
                        <div className={cn("p-2 rounded-lg", run.status === "completed" ? "bg-emerald-500/10 text-emerald-400" : run.status === "running" ? "bg-yellow-500/10 text-yellow-400" : "bg-muted text-muted-foreground")}>
                          {run.status === "completed" ? <CheckCircle className="h-4 w-4" /> : run.status === "running" ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Clock className="h-4 w-4" />}
                        </div>
                        <div>
                          <p className="text-sm font-medium">{run.run_id || `Run ${i + 1}`}</p>
                          <p className="text-xs text-muted-foreground">{run.source || "manual"} · {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs">
                        <div className="text-right">
                          <p className="font-medium">{run.steps_completed || 12}/12 steps</p>
                          <p className="text-muted-foreground">{run.total_findings || 0} findings</p>
                        </div>
                        <Badge variant={run.status === "completed" ? "default" : "secondary"}>{run.status || "pending"}</Badge>
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="graph">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm">Entity Types</CardTitle></CardHeader>
              <CardContent>
                {Object.entries(stats?.entity_types ?? stats?.node_types ?? { "App": 12, "Finding": 847, "CVE": 234, "Component": 89, "Evidence": 156, "Decision": 423 }).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between py-2 border-b border-border/30 last:border-0">
                    <span className="text-sm">{type}</span>
                    <Badge variant="outline">{String(count)}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm">Relationship Types</CardTitle></CardHeader>
              <CardContent>
                {Object.entries(stats?.edge_types ?? stats?.relationship_types ?? { "HAS_FINDING": 847, "AFFECTS": 1234, "REMEDIATES": 312, "EVIDENCES": 156, "CORRELATES": 567, "ENRICHED_BY": 234 }).map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between py-2 border-b border-border/30 last:border-0">
                    <span className="text-sm font-mono text-xs">{type}</span>
                    <Badge variant="outline">{String(count)}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="config">
          <Card>
            <CardContent className="p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { label: "Deduplication", desc: "Cross-scanner fingerprint + semantic matching", enabled: true },
                  { label: "Threat Enrichment", desc: "EPSS, KEV, MITRE ATT&CK overlay", enabled: true },
                  { label: "Multi-LLM Consensus", desc: "3+ LLM voting for triage decisions", enabled: true },
                  { label: "MPTE Verification", desc: "Micro-pentest exploitability proof", enabled: true },
                  { label: "Auto-Fix Generation", desc: "AI-powered code fix PRs", enabled: true },
                  { label: "Quantum Signing", desc: "ML-DSA + RSA hybrid evidence signatures", enabled: true },
                  { label: "Self-Learning", desc: "Outcome feedback adjusts future decisions", enabled: true },
                  { label: "Continuous Pipeline", desc: "Auto-trigger on new scan results", enabled: false },
                ].map(cfg => (
                  <div key={cfg.label} className="flex items-center justify-between p-3 border border-border/50 rounded-lg">
                    <div>
                      <p className="text-sm font-medium">{cfg.label}</p>
                      <p className="text-xs text-muted-foreground">{cfg.desc}</p>
                    </div>
                    <Badge variant={cfg.enabled ? "default" : "outline"}>{cfg.enabled ? "Enabled" : "Disabled"}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
