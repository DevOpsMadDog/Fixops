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
import { motion } from "framer-motion";
import {
  FlaskConical, Cpu, BarChart3, Play, CheckCircle,
  RefreshCw, TrendingUp, Activity, Brain, GitBranch,
  Layers, Target, Zap, Settings, Atom, Network
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface Algorithm {
  id: string;
  name: string;
  type: string;
  description: string;
  accuracy: number;
  status: string;
  last_trained: string;
  features: number;
}

export default function AlgorithmicLab() {
  const [algorithms, setAlgorithms] = useState<Algorithm[]>([]);
  const [capabilities, setCapabilities] = useState<Record<string, unknown>>({});
  const [mlStats, setMlStats] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [capRes, statsRes, modelsRes] = await Promise.allSettled([
        apiClient("/api/v1/algorithms/capabilities"),
        apiClient("/api/v1/ml/stats"),
        apiClient("/api/v1/ml/models"),
      ]);
      if (capRes.status === "fulfilled") setCapabilities(capRes.value ?? {});
      if (statsRes.status === "fulfilled") setMlStats(statsRes.value ?? {});
      if (modelsRes.status === "fulfilled") setAlgorithms(toArray(modelsRes.value));
    } catch { /* handled */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) return <PageSkeleton />;

  const ALGO_ICONS: Record<number, React.ElementType> = { 0: Atom, 1: Network, 2: GitBranch, 3: Brain, 4: Activity, 5: Layers };

  const activeCount = algorithms.filter(a => a.status === "active").length;
  const avgAccuracy = algorithms.reduce((s, a) => s + (a.accuracy || 0), 0) / Math.max(algorithms.length, 1);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="Algorithmic Lab"
        description="ML model training, evaluation, and experimentation — the algorithms powering autonomous security decisions"
        badge="AI Engine"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
            <Button size="sm" onClick={async () => {
              try {
                await apiClient("/api/v1/ml/train", { method: "POST", body: JSON.stringify({ model_type: "ensemble", retrain: true }) });
                toast.success("Training job started");
                setTimeout(fetchData, 3000);
              } catch (e: unknown) { toast.error(`Training failed: ${e instanceof Error ? e.message : ""}`); }
            }}><Play className="h-4 w-4 mr-1" />Train All Models</Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Models" value={activeCount} icon={FlaskConical} trend="up" trendLabel="Running" />
        <KpiCard title="Avg Accuracy" value={`${avgAccuracy.toFixed(1)}%`} icon={Target} trend={avgAccuracy > 90 ? "up" : "flat"} trendLabel="Across all" />
        <KpiCard title="Training Jobs" value={Number(mlStats?.total_training_jobs ?? mlStats?.training_count ?? 12)} icon={Cpu} trend="up" trendLabel="Completed" />
        <KpiCard title="Features" value={Number(mlStats?.total_features ?? 284)} icon={Layers} trend="flat" trendLabel="Input dimensions" />
      </div>

      <Tabs defaultValue="models" className="space-y-4">
        <TabsList>
          <TabsTrigger value="models">Models</TabsTrigger>
          <TabsTrigger value="experiments">Experiments</TabsTrigger>
          <TabsTrigger value="capabilities">Capabilities</TabsTrigger>
        </TabsList>

        <TabsContent value="models">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {algorithms.map((algo, idx) => {
              const Icon = ALGO_ICONS[idx] || Brain;
              return (
                <motion.div key={algo.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.05 }}>
                  <Card className="h-full hover:border-primary/40 transition-all">
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <div className="p-2 rounded-lg bg-primary/10 text-primary"><Icon className="h-5 w-5" /></div>
                          <div>
                            <p className="text-sm font-semibold">{algo.name}</p>
                            <p className="text-[10px] text-muted-foreground">{algo.type}</p>
                          </div>
                        </div>
                        <Badge variant={algo.status === "active" ? "default" : "outline"} className="text-[10px]">{algo.status}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3">{(algo as any).description || (algo as any).desc || ""}</p>
                      <div className="space-y-2">
                        <div className="flex justify-between text-xs"><span className="text-muted-foreground">Accuracy</span><span className="font-medium">{algo.accuracy}%</span></div>
                        <Progress value={algo.accuracy} className="h-1.5" />
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground">Features: {algo.features}</span>
                          <span className="text-muted-foreground">Trained: {algo.last_trained ? new Date(algo.last_trained).toLocaleDateString() : "—"}</span>
                        </div>
                      </div>
                      <div className="flex gap-2 mt-3">
                        <Button variant="outline" size="sm" className="flex-1 text-xs h-7" onClick={async () => {
                          try {
                            await apiClient(`/api/v1/ml/models/${algo.id}/train`, { method: "POST" });
                            toast.success(`Retraining ${algo.name}`);
                          } catch { toast.error("Retrain failed"); }
                        }}>Retrain</Button>
                        <Button variant="outline" size="sm" className="flex-1 text-xs h-7">Evaluate</Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="experiments">
          <Card>
            <CardContent className="p-6">
              <div className="space-y-3">
              {/* SAMPLE DATA — TODO: Replace with real experiment results from /api/v1/ml/experiments */}
                {[
                  { name: "GNN vs MLP for attack path scoring", status: "completed", winner: "GNN (+4.2% AUC)", date: "2024-12-10" },
                  { name: "Monte Carlo iterations: 1K vs 10K", status: "completed", winner: "10K (diminishing at 5K)", date: "2024-12-08" },
                  { name: "Ensemble: XGBoost+RF vs XGBoost+LightGBM", status: "completed", winner: "XGBoost+RF (+1.8%)", date: "2024-12-05" },
                  { name: "Feature importance: EPSS vs CVSS as primary signal", status: "completed", winner: "EPSS (+7.3% precision)", date: "2024-12-01" },
                  { name: "Online learning: River vs batch retrain (weekly)", status: "running", winner: "—", date: "2024-12-12" },
                ].map((exp, i) => (
                  <div key={i} className="flex items-center justify-between p-3 border border-border/50 rounded-lg hover:bg-accent/20 transition-colors">
                    <div>
                      <p className="text-sm font-medium">{exp.name}</p>
                      <p className="text-xs text-muted-foreground">{exp.date} · Winner: {exp.winner}</p>
                    </div>
                    <Badge variant={exp.status === "completed" ? "default" : "secondary"}>{exp.status}</Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="capabilities">
          <Card>
            <CardContent className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { name: "Monte Carlo CVE Simulation", endpoint: "/api/v1/algorithms/monte-carlo/cve", desc: "Simulates exploit probability for individual CVEs" },
                  { name: "Monte Carlo Portfolio Risk", endpoint: "/api/v1/algorithms/monte-carlo/portfolio", desc: "Aggregate risk quantification across entire application portfolio" },
                  { name: "GNN Attack Surface", endpoint: "/api/v1/algorithms/gnn/attack-surface", desc: "Graph neural network for attack surface analysis" },
                  { name: "GNN Critical Nodes", endpoint: "/api/v1/algorithms/gnn/critical-nodes", desc: "Identifies most critical nodes in the dependency graph" },
                  { name: "GNN Risk Propagation", endpoint: "/api/v1/algorithms/gnn/risk-propagation", desc: "Models how risk propagates through connected systems" },
                  { name: "Causal Root Cause", endpoint: "/api/v1/algorithms/causal/analyze", desc: "Identifies root causes of security incidents" },
                  { name: "Causal Counterfactual", endpoint: "/api/v1/algorithms/causal/counterfactual", desc: "'What if' analysis for remediation planning" },
                  { name: "Causal Treatment Effect", endpoint: "/api/v1/algorithms/causal/treatment-effect", desc: "Measures impact of remediation actions" },
                ].map((cap, i) => (
                  <div key={i} className="p-3 border border-border/50 rounded-lg">
                    <p className="text-sm font-semibold">{cap.name}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{cap.desc}</p>
                    <code className="text-[10px] text-primary/70 mt-1 block font-mono">{cap.endpoint}</code>
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
