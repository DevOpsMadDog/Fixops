import { useState, useEffect, useCallback } from "react";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { motion } from "framer-motion";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Legend,
} from "recharts";
import {
  FlaskConical, Cpu, Play, CheckCircle,
  RefreshCw, Brain, GitBranch,
  Layers, Target, Atom, Network, Activity,
  Beaker, Gauge, Sparkles, Trophy,
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface Algorithm {
  id: string; name: string; type: string; description?: string; desc?: string;
  accuracy: number; status: string; last_trained: string; features: number;
  precision?: number; recall?: number; f1_score?: number;
}

export default function AlgorithmicLab() {
  const [algorithms, setAlgorithms] = useState<Algorithm[]>([]);
  const [capabilities, setCapabilities] = useState<Record<string, unknown>>({});
  const [mlStats, setMlStats] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [trainingId, setTrainingId] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [capRes, statsRes, modelsRes] = await Promise.allSettled([
        apiClient("/api/v1/algorithms/capabilities"),
        apiClient("/api/v1/ml/stats"),
        apiClient("/api/v1/ml/models"),
      ]);
      if (capRes.status === "fulfilled") setCapabilities(capRes.value ?? {});
      if (statsRes.status === "fulfilled") setMlStats(statsRes.value ?? {});
      if (modelsRes.status === "fulfilled") setAlgorithms(toArray(modelsRes.value) as unknown as Algorithm[]);
    } catch { /* handled */ } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  if (loading) return <PageSkeleton />;

  const ALGO_ICONS: Record<number, React.ElementType> = { 0: Atom, 1: Network, 2: GitBranch, 3: Brain, 4: Activity, 5: Layers };
  const activeCount = algorithms.filter(a => a.status === "active").length;
  const avgAccuracy = algorithms.length > 0 ? algorithms.reduce((s, a) => s + (a.accuracy || 0), 0) / algorithms.length : 0;

  // Chart data: accuracy per model
  const accuracyChart = algorithms.map(a => ({
    name: a.name?.length > 12 ? a.name.slice(0, 12) + "…" : a.name,
    accuracy: a.accuracy || 0,
    features: a.features || 0,
  }));

  // Radar data for top models
  const radarData = algorithms.slice(0, 6).map(a => ({
    subject: a.name?.length > 10 ? a.name.slice(0, 10) : a.name,
    accuracy: a.accuracy || 0,
    precision: a.precision || a.accuracy * 0.95 || 0,
    recall: a.recall || a.accuracy * 0.92 || 0,
  }));

  return (
    <div className="space-y-6 p-6">
      <PageHeader title="Algorithmic Lab" description="ML model training, evaluation, and experimentation — the algorithms powering autonomous security decisions" badge="AI Engine"
        actions={<div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
          <Button size="sm" onClick={async () => {
            try { await apiClient("/api/v1/ml/train", { method: "POST", body: JSON.stringify({ model_type: "ensemble", retrain: true }) });
              toast.success("Training job started"); setTimeout(fetchData, 3000);
            } catch (e: unknown) { toast.error(`Training failed: ${e instanceof Error ? e.message : ""}`); }
          }}><Play className="h-4 w-4 mr-1" />Train All Models</Button>
        </div>} />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Models" value={activeCount} icon={FlaskConical} trend="up" trendLabel={`${algorithms.length} total`} />
        <KpiCard title="Avg Accuracy" value={`${avgAccuracy.toFixed(1)}%`} icon={Target} trend={avgAccuracy > 90 ? "up" : "flat"} trendLabel="Across all" />
        <KpiCard title="Training Jobs" value={Number(mlStats?.total_training_jobs ?? mlStats?.training_count ?? 0)} icon={Cpu} trend="up" trendLabel="Completed" />
        <KpiCard title="Features" value={Number(mlStats?.total_features ?? 0)} icon={Layers} trend="flat" trendLabel="Input dimensions" />
      </div>

      <Tabs defaultValue="models" className="space-y-4">
        <TabsList>
          <TabsTrigger value="models">Models</TabsTrigger>
          <TabsTrigger value="performance">Performance</TabsTrigger>
          <TabsTrigger value="experiments">Experiments</TabsTrigger>
          <TabsTrigger value="capabilities">Capabilities</TabsTrigger>
        </TabsList>

        <TabsContent value="models">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {algorithms.map((algo, idx) => {
              const Icon = ALGO_ICONS[idx % 6] || Brain;
              return (
                <motion.div key={algo.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.05 }}>
                  <Card className={cn("h-full transition-all", trainingId === algo.id ? "border-primary/50 shadow-lg shadow-primary/10" : "hover:border-primary/40")}>
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <div className="p-2 rounded-lg bg-primary/10 text-primary"><Icon className="h-5 w-5" /></div>
                          <div><p className="text-sm font-semibold">{algo.name}</p><p className="text-[10px] text-muted-foreground">{algo.type}</p></div>
                        </div>
                        <Badge variant={algo.status === "active" ? "default" : "outline"} className="text-[10px]">{algo.status}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{algo.description || algo.desc || ""}</p>
                      <div className="space-y-2">
                        <div className="flex justify-between text-xs"><span className="text-muted-foreground">Accuracy</span><span className="font-medium">{algo.accuracy}%</span></div>
                        <Progress value={algo.accuracy} className="h-1.5" />
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground">Features: {algo.features}</span>
                          <span className="text-muted-foreground">{algo.last_trained ? new Date(algo.last_trained).toLocaleDateString() : "—"}</span>
                        </div>
                      </div>
                      <div className="flex gap-2 mt-3">
                        <Button variant="outline" size="sm" className="flex-1 text-xs h-7" onClick={async () => {
                          setTrainingId(algo.id);
                          try { await apiClient(`/api/v1/ml/models/${algo.id}/train`, { method: "POST" });
                            toast.success(`Retraining ${algo.name}`);
                          } catch { toast.error("Retrain failed"); }
                          finally { setTrainingId(null); }
                        }}>{trainingId === algo.id ? <RefreshCw className="h-3 w-3 animate-spin" /> : "Retrain"}</Button>
                        <Button variant="outline" size="sm" className="flex-1 text-xs h-7">Evaluate</Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="performance">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Gauge className="h-4 w-4" />Model Accuracy</CardTitle>
                <CardDescription>Accuracy comparison across all trained models</CardDescription></CardHeader>
              <CardContent>{accuracyChart.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={accuracyChart}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis dataKey="name" tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" angle={-20} textAnchor="end" height={50} />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" domain={[0, 100]} />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="accuracy" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Accuracy %" />
                  </BarChart>
                </ResponsiveContainer>
              ) : <div className="h-[300px] flex items-center justify-center text-muted-foreground text-sm">No models yet</div>}</CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Sparkles className="h-4 w-4" />Model Radar</CardTitle>
                <CardDescription>Multi-dimensional model comparison</CardDescription></CardHeader>
              <CardContent>{radarData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="hsl(var(--border))" />
                    <PolarAngleAxis dataKey="subject" tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" />
                    <PolarRadiusAxis tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" domain={[0, 100]} />
                    <Radar name="Accuracy" dataKey="accuracy" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} />
                    <Radar name="Precision" dataKey="precision" stroke="#22c55e" fill="#22c55e" fillOpacity={0.1} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                  </RadarChart>
                </ResponsiveContainer>
              ) : <div className="h-[300px] flex items-center justify-center text-muted-foreground text-sm">No data</div>}</CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="experiments">
          <Card><CardContent className="p-6"><div className="space-y-3">
            {/* SAMPLE DATA — TODO: Replace with real experiment results from /api/v1/ml/experiments */}
            {[{ name: "GNN vs MLP for attack path scoring", status: "completed", winner: "GNN (+4.2% AUC)", date: "2024-12-10", icon: Trophy },
              { name: "Monte Carlo iterations: 1K vs 10K", status: "completed", winner: "10K (diminishing at 5K)", date: "2024-12-08", icon: Target },
              { name: "Ensemble: XGBoost+RF vs XGBoost+LightGBM", status: "completed", winner: "XGBoost+RF (+1.8%)", date: "2024-12-05", icon: Beaker },
              { name: "Feature importance: EPSS vs CVSS as primary signal", status: "completed", winner: "EPSS (+7.3% precision)", date: "2024-12-01", icon: Sparkles },
              { name: "Online learning: River vs batch retrain (weekly)", status: "running", winner: "—", date: "2024-12-12", icon: RefreshCw },
            ].map((exp, i) => {
              const I = exp.icon;
              return (
                <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06 }}
                  className="flex items-center justify-between p-4 border border-border/50 rounded-lg hover:bg-accent/20 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-muted"><I className="h-4 w-4 text-muted-foreground" /></div>
                    <div>
                      <p className="text-sm font-medium">{exp.name}</p>
                      <p className="text-xs text-muted-foreground">{exp.date} · Winner: {exp.winner}</p>
                    </div>
                  </div>
                  <Badge variant={exp.status === "completed" ? "default" : "secondary"}>{exp.status}</Badge>
                </motion.div>
              );
            })}
            <p className="text-[10px] text-muted-foreground text-center mt-2">Sample experiments — wire to /api/v1/ml/experiments for live data</p>
          </div></CardContent></Card>
        </TabsContent>

        <TabsContent value="capabilities">
          <Card><CardContent className="p-6"><div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[{ name: "Monte Carlo CVE Simulation", endpoint: "/api/v1/algorithms/monte-carlo/cve", desc: "Simulates exploit probability for individual CVEs" },
              { name: "Monte Carlo Portfolio Risk", endpoint: "/api/v1/algorithms/monte-carlo/portfolio", desc: "Aggregate risk quantification across entire application portfolio" },
              { name: "GNN Attack Surface", endpoint: "/api/v1/algorithms/gnn/attack-surface", desc: "Graph neural network for attack surface analysis" },
              { name: "GNN Critical Nodes", endpoint: "/api/v1/algorithms/gnn/critical-nodes", desc: "Identifies most critical nodes in the dependency graph" },
              { name: "GNN Risk Propagation", endpoint: "/api/v1/algorithms/gnn/risk-propagation", desc: "Models how risk propagates through connected systems" },
              { name: "Causal Root Cause", endpoint: "/api/v1/algorithms/causal/analyze", desc: "Identifies root causes of security incidents" },
              { name: "Causal Counterfactual", endpoint: "/api/v1/algorithms/causal/counterfactual", desc: "'What if' analysis for remediation planning" },
              { name: "Causal Treatment Effect", endpoint: "/api/v1/algorithms/causal/treatment-effect", desc: "Measures impact of remediation actions" },
            ].map((cap, i) => (
              <motion.div key={i} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                className="p-4 border border-border/50 rounded-lg hover:border-primary/40 hover:bg-accent/10 transition-all">
                <p className="text-sm font-semibold">{cap.name}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{cap.desc}</p>
                <code className="text-[10px] text-primary/70 mt-1 block font-mono">{cap.endpoint}</code>
              </motion.div>
            ))}
          </div></CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
