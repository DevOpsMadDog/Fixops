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
import { Separator } from "@/components/ui/separator";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip as RechartsTooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  TrendingUp, TrendingDown, Activity, RefreshCw,
  Target, Brain, Zap, Play,
  ArrowUpRight, ArrowDownRight, Minus, Shield,
  Layers, Network, Eye, AlertTriangle, BarChart3,
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface Forecast {
  id: string; metric: string; current_value: number; predicted_value: number;
  confidence: number; trend: string; horizon: string; created_at: string;
}

interface MarkovState {
  state: string; probability: number; transitions: Record<string, number>;
}

export default function Predictions() {
  const [forecasts, setForecasts] = useState<Forecast[]>([]);
  const [markovStates, setMarkovStates] = useState<MarkovState[]>([]);
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [simulating, setSimulating] = useState(false);
  const [selectedForecast, setSelectedForecast] = useState<Forecast | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [forecastRes, markovRes, healthRes] = await Promise.allSettled([
        apiClient("/api/v1/predictions"),
        apiClient("/api/v1/predictions/markov/states"),
        apiClient("/api/v1/predictions/health"),
      ]);
      if (forecastRes.status === "fulfilled") setForecasts(toArray(forecastRes.value).slice(0, 30) as unknown as Forecast[]);
      if (markovRes.status === "fulfilled") setMarkovStates(toArray(markovRes.value) as unknown as MarkovState[]);
      if (healthRes.status === "fulfilled") setHealth(healthRes.value ?? {});
    } catch { /* handled */ } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  if (loading) return <PageSkeleton />;

  const healthStatus = String(health?.status ?? "operational");
  const upTrends = forecasts.filter(f => f.trend === "up" || f.predicted_value > f.current_value).length;
  const downTrends = forecasts.filter(f => f.trend === "down" || f.predicted_value < f.current_value).length;
  const avgConfidence = forecasts.length > 0 ? forecasts.reduce((s, f) => s + (f.confidence || 0), 0) / forecasts.length : 0;

  // Risk trend chart (forecasts over time):
  const trendChart = forecasts.slice(0, 12).reverse().map((f, i) => ({
    name: `T+${i + 1}`,
    current: f.current_value || 0,
    predicted: f.predicted_value || 0,
    confidence: (f.confidence || 0) * 100,
  }));

  // Markov state distribution chart
  const markovChart = markovStates.map(s => ({
    name: s.state?.length > 12 ? s.state.slice(0, 12) + "…" : s.state,
    probability: Math.round((s.probability || 0) * 100),
  }));

  const trendIcon = (trend: string, current: number, predicted: number) => {
    if (trend === "up" || predicted > current) return <ArrowUpRight className="h-3.5 w-3.5 text-red-400" />;
    if (trend === "down" || predicted < current) return <ArrowDownRight className="h-3.5 w-3.5 text-emerald-400" />;
    return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
  };

  const simulateAttack = async () => {
    setSimulating(true);
    try {
      const res = await apiClient("/api/v1/predictions/simulate-attack", {
        method: "POST",
        body: JSON.stringify({ attack_type: "supply_chain", target: "production", iterations: 1000 }),
      });
      toast.success(`Simulation complete: ${(res as Record<string, unknown>)?.result || "done"}`);
      fetchData();
    } catch (e: unknown) { toast.error(`Simulation failed: ${e instanceof Error ? e.message : ""}`); }
    finally { setSimulating(false); }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader title="AI Predictions" description="Risk forecasting with Bayesian models, Markov chain state machines, and Monte Carlo attack simulations" badge="AI Engine"
        actions={<div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
          <Button size="sm" onClick={simulateAttack} disabled={simulating}>
            <Play className="h-4 w-4 mr-1" />{simulating ? "Simulating..." : "Simulate Attack"}
          </Button>
        </div>} />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard title="Forecasts" value={forecasts.length} icon={TrendingUp} trend="flat" trendLabel="Active" />
        <KpiCard title="Risk Rising" value={upTrends} icon={ArrowUpRight} trend="down" trendLabel="Needs attention" />
        <KpiCard title="Risk Falling" value={downTrends} icon={ArrowDownRight} trend="up" trendLabel="Improving" />
        <KpiCard title="Avg Confidence" value={`${(avgConfidence * 100).toFixed(0)}%`} icon={Target} trend={avgConfidence > 0.8 ? "up" : "flat"} trendLabel="Model confidence" />
        <KpiCard title="Engine" value={healthStatus === "operational" ? "Healthy" : healthStatus} icon={Activity} trend={healthStatus === "operational" ? "up" : "down"} trendLabel={healthStatus} />
      </div>

      <Tabs defaultValue="forecasts" className="space-y-4">
        <TabsList>
          <TabsTrigger value="forecasts">Risk Forecasts</TabsTrigger>
          <TabsTrigger value="trends">Trend Analysis</TabsTrigger>
          <TabsTrigger value="markov">Markov States</TabsTrigger>
          <TabsTrigger value="simulation">Simulation</TabsTrigger>
        </TabsList>

        <TabsContent value="forecasts">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <Card><CardContent className="p-0"><ScrollArea className="h-[480px]"><div className="divide-y divide-border/50">
                {forecasts.length === 0 && (
                  <div className="p-8 text-center text-muted-foreground">
                    <TrendingUp className="h-12 w-12 mx-auto mb-3 opacity-40" />
                    <p className="text-sm font-medium">No forecasts generated yet</p>
                    <p className="text-xs mt-1">Run predictions to forecast risk trends</p>
                  </div>
                )}
                {forecasts.map((f, i) => (
                  <motion.div key={f.id || i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}
                    className={cn("flex items-center justify-between p-4 cursor-pointer transition-colors",
                      selectedForecast?.id === f.id ? "bg-accent/40" : "hover:bg-accent/20")}
                    onClick={() => setSelectedForecast(f)}>
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-muted">{trendIcon(f.trend, f.current_value, f.predicted_value)}</div>
                      <div>
                        <p className="text-sm font-medium">{f.metric || `Forecast ${i + 1}`}</p>
                        <p className="text-xs text-muted-foreground">{f.horizon || "7d"} horizon · {f.created_at ? new Date(f.created_at).toLocaleDateString() : "—"}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 text-sm">
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Current → Predicted</p>
                        <p className="font-medium">{f.current_value?.toFixed(1)} → {f.predicted_value?.toFixed(1)}</p>
                      </div>
                      <Badge variant={f.confidence > 0.8 ? "default" : f.confidence > 0.5 ? "secondary" : "outline"}>{(f.confidence * 100).toFixed(0)}%</Badge>
                    </div>
                  </motion.div>
                ))}
              </div></ScrollArea></CardContent></Card>
            </div>
            <Card>
              <CardHeader><CardTitle className="text-sm">Forecast Details</CardTitle></CardHeader>
              <CardContent>{selectedForecast ? (
                <div className="space-y-3">
                  <p className="font-semibold">{selectedForecast.metric}</p>
                  <div className="flex gap-2">{trendIcon(selectedForecast.trend, selectedForecast.current_value, selectedForecast.predicted_value)}
                    <Badge variant="outline">{selectedForecast.trend || "stable"}</Badge></div>
                  {[{ l: "Current", v: selectedForecast.current_value?.toFixed(2) },
                    { l: "Predicted", v: selectedForecast.predicted_value?.toFixed(2) },
                    { l: "Confidence", v: `${(selectedForecast.confidence * 100).toFixed(1)}%` },
                    { l: "Horizon", v: selectedForecast.horizon || "7d" },
                    { l: "Created", v: selectedForecast.created_at ? new Date(selectedForecast.created_at).toLocaleString() : "—" },
                  ].map(item => (
                    <div key={item.l} className="flex justify-between text-sm py-1.5 border-b border-border/30"><span className="text-muted-foreground">{item.l}</span><span className="font-medium">{item.v}</span></div>
                  ))}
                  <div className="mt-2"><p className="text-xs text-muted-foreground mb-1">Confidence</p><Progress value={selectedForecast.confidence * 100} className="h-2" /></div>
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground"><Eye className="h-8 w-8 mx-auto mb-2 opacity-40" /><p className="text-sm">Select a forecast</p></div>
              )}</CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="trends">
          <div className="grid grid-cols-1 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><BarChart3 className="h-4 w-4" />Risk Trajectory</CardTitle>
                <CardDescription>Current vs predicted risk values over time</CardDescription></CardHeader>
              <CardContent>{trendChart.length > 0 ? (
                <ResponsiveContainer width="100%" height={320}>
                  <AreaChart data={trendChart}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Area type="monotone" dataKey="current" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} name="Current" />
                    <Area type="monotone" dataKey="predicted" stroke="#ef4444" fill="#ef4444" fillOpacity={0.1} name="Predicted" strokeDasharray="5 5" />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : <div className="h-[320px] flex items-center justify-center text-muted-foreground text-sm">No forecast data</div>}</CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="markov">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Network className="h-4 w-4" />State Probabilities</CardTitle>
                <CardDescription>Current probability distribution across system states</CardDescription></CardHeader>
              <CardContent>{markovChart.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={markovChart}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis dataKey="name" tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" domain={[0, 100]} />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="probability" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Probability %" />
                  </BarChart>
                </ResponsiveContainer>
              ) : <div className="h-[280px] flex items-center justify-center text-muted-foreground text-sm">No Markov states</div>}</CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Layers className="h-4 w-4" />State Details</CardTitle></CardHeader>
              <CardContent><ScrollArea className="h-[280px]"><div className="space-y-3">
                {markovStates.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">No states defined</p>}
                {markovStates.map((s, i) => (
                  <motion.div key={i} initial={{ opacity: 0, x: -5 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
                    className="p-3 border border-border/50 rounded-lg hover:bg-accent/20 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-semibold">{s.state}</span>
                      <Badge variant="outline">{(s.probability * 100).toFixed(1)}%</Badge>
                    </div>
                    <Progress value={s.probability * 100} className="h-1.5 mb-2" />
                    {s.transitions && Object.keys(s.transitions).length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {Object.entries(s.transitions).map(([target, prob]) => (
                          <span key={target} className="text-[10px] px-1.5 py-0.5 rounded bg-muted">
                            → {target}: {((prob as number) * 100).toFixed(0)}%
                          </span>
                        ))
                      }
                      </div>
                    )}
                  </motion.div>
                ))}
              </div></ScrollArea></CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="simulation">
          <Card>
            <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Shield className="h-4 w-4" />Attack Simulation</CardTitle>
              <CardDescription>Monte Carlo attack chain simulation with configurable parameters</CardDescription></CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[{ type: "Supply Chain", desc: "Simulate upstream dependency compromise via malicious package injection", endpoint: "/api/v1/predictions/simulate-attack", icon: Network },
                  { type: "Lateral Movement", desc: "Model attacker progression from initial foothold through internal network", endpoint: "/api/v1/predictions/attack-chain", icon: Zap },
                  { type: "Combined Analysis", desc: "Multi-vector analysis combining all threat models and EPSS data", endpoint: "/api/v1/predictions/combined-analysis", icon: Brain },
                ].map((sim, i) => { const I = sim.icon; return (
                  <motion.div key={i} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
                    className="p-4 border border-border/50 rounded-lg hover:border-primary/40 transition-all">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="p-2 rounded-lg bg-primary/10 text-primary"><I className="h-4 w-4" /></div>
                      <p className="text-sm font-semibold">{sim.type}</p>
                    </div>
                    <p className="text-xs text-muted-foreground mb-3">{sim.desc}</p>
                    <Button variant="outline" size="sm" className="w-full text-xs" onClick={async () => {
                      try { await apiClient(sim.endpoint, { method: "POST", body: JSON.stringify({ attack_type: sim.type.toLowerCase().replace(/\s+/g, "_"), iterations: 1000 }) });
                        toast.success(`${sim.type} simulation complete`); fetchData();
                      } catch (e: unknown) { toast.error(`Failed: ${e instanceof Error ? e.message : ""}`); }
                    }}><Play className="h-3 w-3 mr-1" />Run Simulation</Button>
                  </motion.div>
                ); })}
              </div>
              <Separator />
              <div className="text-center text-xs text-muted-foreground">
                <p>Simulations run Monte Carlo iterations (default: 1,000) to model probabilistic attack outcomes.</p>
                <p className="mt-0.5">Results feed back into the Brain Pipeline for decision enrichment.</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
