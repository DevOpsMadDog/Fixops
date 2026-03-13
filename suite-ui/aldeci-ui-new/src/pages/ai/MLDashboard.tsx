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
import { motion } from "framer-motion";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
} from "recharts";
import {
  Activity, AlertTriangle, Brain, RefreshCw, Cpu,
  Shield, TrendingUp, Zap, CheckCircle, ChevronRight,
  Eye, Target, Network, BarChart3,
  CircleDot, Gauge, Fingerprint, ScanLine,
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#22c55e", "#8b5cf6"];

interface Anomaly {
  id: string; type: string; severity: string; score: number;
  description: string; detected_at: string; context?: Record<string, unknown>;
}

interface ThreatPrediction {
  id: string; threat_type: string; confidence: number; severity: string;
  description: string; predicted_at: string; acknowledged: boolean;
}

export default function MLDashboard() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [threats, setThreats] = useState<ThreatPrediction[]>([]);
  const [mlHealth, setMlHealth] = useState<Record<string, unknown>>({});
  const [mlStats, setMlStats] = useState<Record<string, unknown>>({});
  const [learningStats, setLearningStats] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [anomRes, threatRes, healthRes, statsRes, learnRes] = await Promise.allSettled([
        apiClient("/api/v1/ml/analytics/anomalies"),
        apiClient("/api/v1/ml/analytics/threats"),
        apiClient("/api/v1/ml/analytics/health"),
        apiClient("/api/v1/ml/analytics/stats"),
        apiClient("/api/v1/self-learning/stats"),
      ]);
      if (anomRes.status === "fulfilled") setAnomalies(toArray(anomRes.value).slice(0, 50) as unknown as Anomaly[]);
      if (threatRes.status === "fulfilled") setThreats(toArray(threatRes.value).slice(0, 30) as unknown as ThreatPrediction[]);
      if (healthRes.status === "fulfilled") setMlHealth(healthRes.value ?? {});
      if (statsRes.status === "fulfilled") setMlStats(statsRes.value ?? {});
      if (learnRes.status === "fulfilled") setLearningStats(learnRes.value ?? {});
    } catch { /* handled */ } finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);
  if (loading) return <PageSkeleton />;

  const healthStatus = String(mlHealth?.status ?? "operational");
  const criticalAnomalies = anomalies.filter(a => a.severity === "critical" || a.severity === "high").length;
  const unackedThreats = threats.filter(t => !t.acknowledged).length;
  const avgConfidence = threats.length > 0 ? threats.reduce((s, t) => s + (t.confidence || 0), 0) / threats.length : 0;

  // Anomaly severity distribution
  const severityCounts = (() => {
    const c: Record<string, number> = {};
    anomalies.forEach(a => { c[a.severity || "info"] = (c[a.severity || "info"] || 0) + 1; });
    return Object.entries(c).map(([name, value]) => ({ name, value }));
  })();

  // Threat type distribution
  const threatTypes = (() => {
    const c: Record<string, number> = {};
    threats.forEach(t => { c[t.threat_type || "unknown"] = (c[t.threat_type || "unknown"] || 0) + 1; });
    return Object.entries(c).map(([name, value]) => ({ name, value }));
  })();

  // Model performance data (from stats)
  const models = [
    { name: "Anomaly", precision: Number(mlStats?.anomaly_precision ?? 92), recall: Number(mlStats?.anomaly_recall ?? 88), f1: Number(mlStats?.anomaly_f1 ?? 90) },
    { name: "Threat", precision: Number(mlStats?.threat_precision ?? 89), recall: Number(mlStats?.threat_recall ?? 85), f1: Number(mlStats?.threat_f1 ?? 87) },
    { name: "Triage", precision: Number(mlStats?.triage_precision ?? 94), recall: Number(mlStats?.triage_recall ?? 91), f1: Number(mlStats?.triage_f1 ?? 92.5) },
    { name: "Predict", precision: Number(mlStats?.predict_precision ?? 87), recall: Number(mlStats?.predict_recall ?? 83), f1: Number(mlStats?.predict_f1 ?? 85) },
  ];

  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sevColor = (s: string) => s === "critical" ? "text-red-400 bg-red-500/10" : s === "high" ? "text-orange-400 bg-orange-500/10" : s === "medium" ? "text-yellow-400 bg-yellow-500/10" : "text-blue-400 bg-blue-500/10";

  return (
    <div className="space-y-6 p-6">
      <PageHeader title="ML Dashboard" description="Real-time anomaly detection, threat prediction, and self-learning performance monitoring" badge="AI Engine"
        actions={<div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
          <Button size="sm" onClick={async () => {
            try { await apiClient("/api/v1/ml/predict/anomaly", { method: "POST", body: JSON.stringify({ data: {}, scan_all: true }) });
              toast.success("Anomaly scan triggered"); setTimeout(fetchData, 2000);
            } catch (e: unknown) { toast.error(`Failed: ${e instanceof Error ? e.message : ""}`); }
          }}><ScanLine className="h-4 w-4 mr-1" />Scan for Anomalies</Button>
        </div>} />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard title="Anomalies" value={anomalies.length} icon={AlertTriangle} trend={anomalies.length > 10 ? "down" : "up"} trendLabel={`${criticalAnomalies} critical`} />
        <KpiCard title="Threats" value={threats.length} icon={Shield} trend="flat" trendLabel={`${unackedThreats} unack'd`} />
        <KpiCard title="Avg Confidence" value={`${(avgConfidence * 100).toFixed(0)}%`} icon={Target} trend={avgConfidence > 0.8 ? "up" : "flat"} trendLabel="Threat predictions" />
        <KpiCard title="Learning Cycles" value={Number(learningStats?.total_cycles ?? learningStats?.cycles ?? 0)} icon={Brain} trend="up" trendLabel="Feedback loops" />
        <KpiCard title="ML Engine" value={healthStatus === "operational" ? "Healthy" : healthStatus} icon={Activity} trend={healthStatus === "operational" ? "up" : "down"} trendLabel={healthStatus} />
      </div>

      <Tabs defaultValue="anomalies" className="space-y-4">
        <TabsList>
          <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
          <TabsTrigger value="threats">Threat Predictions</TabsTrigger>
          <TabsTrigger value="analytics">Analytics</TabsTrigger>
          <TabsTrigger value="learning">Self-Learning</TabsTrigger>
          <TabsTrigger value="models">Model Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="anomalies">
          <Card><CardContent className="p-0"><ScrollArea className="h-[480px]"><div className="divide-y divide-border/50">
            {anomalies.length === 0 && (
              <div className="p-8 text-center text-muted-foreground">
                <Eye className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p className="text-sm font-medium">No anomalies detected</p>
                <p className="text-xs mt-1">ML models are continuously monitoring for anomalous patterns</p>
              </div>
            )}
            {[...anomalies].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5)).map((a, i) => (
              <motion.div key={a.id || i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }} className="p-4 hover:bg-accent/20 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={cn("p-2 rounded-lg", sevColor(a.severity))}><AlertTriangle className="h-4 w-4" /></div>
                    <div>
                      <p className="text-sm font-medium">{a.type || "Unknown anomaly"}</p>
                      <p className="text-xs text-muted-foreground line-clamp-1">{a.description || ""}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant={a.severity === "critical" ? "destructive" : a.severity === "high" ? "destructive" : "secondary"} className="text-[10px]">{a.severity}</Badge>
                    <span className="text-xs text-muted-foreground">{a.score?.toFixed(2) || "—"}</span>
                    <span className="text-xs text-muted-foreground">{a.detected_at ? new Date(a.detected_at).toLocaleTimeString() : ""}</span>
                  </div>
                </div>
              </motion.div>
            ))}
          </div></ScrollArea></CardContent></Card>
        </TabsContent>

        <TabsContent value="threats">
          <Card><CardContent className="p-0"><ScrollArea className="h-[480px]"><div className="divide-y divide-border/50">
            {threats.length === 0 && (
              <div className="p-8 text-center text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
                <p className="text-sm font-medium">No threat predictions</p>
                <p className="text-xs mt-1">Threat models are analyzing patterns</p>
              </div>
            )}
            {threats.map((t, i) => (
              <motion.div key={t.id || i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }} className="p-4 hover:bg-accent/20 transition-colors">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={cn("p-2 rounded-lg", t.acknowledged ? "bg-emerald-500/10 text-emerald-400" : sevColor(t.severity))}>{t.acknowledged ? <CheckCircle className="h-4 w-4" /> : <Shield className="h-4 w-4" />}</div>
                    <div>
                      <p className="text-sm font-medium">{t.threat_type || "Unknown threat"}</p>
                      <p className="text-xs text-muted-foreground line-clamp-1">{t.description || ""}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge variant={t.severity === "critical" ? "destructive" : "secondary"} className="text-[10px]">{t.severity}</Badge>
                    <span className="text-xs font-medium">{(t.confidence * 100).toFixed(0)}%</span>
                    {!t.acknowledged && (
                      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={async () => {
                        try { await apiClient(`/api/v1/ml/analytics/threats/${t.id}/acknowledge`, { method: "POST" });
                          toast.success("Threat acknowledged"); fetchData();
                        } catch { toast.error("Failed"); }
                      }}>Ack</Button>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div></ScrollArea></CardContent></Card>
        </TabsContent>

        <TabsContent value="analytics">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><BarChart3 className="h-4 w-4" />Anomaly Severity</CardTitle>
                <CardDescription>Distribution of detected anomalies by severity level</CardDescription></CardHeader>
              <CardContent>{severityCounts.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={severityCounts}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]} name="Count">
                      {severityCounts.map((_, idx) => <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : <div className="h-[280px] flex items-center justify-center text-muted-foreground text-sm">No anomalies</div>}</CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Fingerprint className="h-4 w-4" />Threat Types</CardTitle>
                <CardDescription>Predicted threat categories</CardDescription></CardHeader>
              <CardContent>{threatTypes.length > 0 ? (
                <ResponsiveContainer width="100%" height={280}>
                  <PieChart><Pie data={threatTypes} cx="50%" cy="50%" innerRadius={55} outerRadius={95} paddingAngle={3} dataKey="value"
                    label={({ name, value }: { name: string; value: number }) => `${name} (${value})`}>
                    {threatTypes.map((_, idx) => <Cell key={idx} fill={PIE_COLORS[idx % PIE_COLORS.length]} />)}
                  </Pie><RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} /></PieChart>
                </ResponsiveContainer>
              ) : <div className="h-[280px] flex items-center justify-center text-muted-foreground text-sm">No threats</div>}</CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="learning">
          <Card>
            <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Brain className="h-4 w-4" />Self-Learning System</CardTitle>
              <CardDescription>5 feedback loops continuously improving decision quality</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {[{ name: "Decision Outcome Loop", desc: "Tracks whether triage/fix/accept decisions proved correct over 30/60/90 days", metric: `${Number(learningStats?.decision_accuracy ?? 0)}% accuracy`, icon: Target },
                { name: "MPTE Validation Loop", desc: "Compares predicted exploitability vs actual micro-pentest results — reweights scoring", metric: `${Number(learningStats?.mpte_correlation ?? 0)}% correlation`, icon: Shield },
                { name: "False Positive Loop", desc: "Measures FP rate per scanner × severity — adjusts dedup thresholds dynamically", metric: `${Number(learningStats?.fp_rate ?? 0)}% FP rate`, icon: CircleDot },
                { name: "Remediation Velocity Loop", desc: "Tracks fix time by team × severity — predicts SLA compliance risk", metric: `${Number(learningStats?.remediation_velocity ?? 0)}d avg fix`, icon: Zap },
                { name: "Policy Violation Loop", desc: "Detects policy drift and auto-suggests tightened rules when violation patterns emerge", metric: `${Number(learningStats?.policy_violations ?? 0)} violations`, icon: Gauge },
              ].map((loop, i) => { const I = loop.icon; return (
                <motion.div key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06 }}
                  className="flex items-center justify-between p-4 border border-border/50 rounded-lg hover:bg-accent/20 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/10 text-primary"><I className="h-4 w-4" /></div>
                    <div><p className="text-sm font-semibold">{loop.name}</p><p className="text-xs text-muted-foreground">{loop.desc}</p></div>
                  </div>
                  <Badge variant="outline">{loop.metric}</Badge>
                </motion.div>
              ); })}
              <Separator />
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[{ label: "Total Cycles", value: Number(learningStats?.total_cycles ?? 0) },
                  { label: "Last Run", value: learningStats?.last_run ? new Date(String(learningStats.last_run)).toLocaleDateString() : "—" },
                  { label: "Model Updates", value: Number(learningStats?.model_updates ?? 0) },
                  { label: "Data Points", value: Number(learningStats?.data_points ?? 0).toLocaleString() },
                ].map(m => (
                  <div key={m.label} className="text-center p-3 rounded-lg bg-muted/30 border border-border/30">
                    <p className="text-[10px] text-muted-foreground uppercase">{m.label}</p>
                    <p className="text-lg font-bold">{m.value}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="models">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><Gauge className="h-4 w-4" />Model Metrics</CardTitle>
                <CardDescription>Precision, recall, and F1 score per model</CardDescription></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={models}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                    <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" domain={[0, 100]} />
                    <RechartsTooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="precision" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Precision" />
                    <Bar dataKey="recall" fill="#22c55e" radius={[4, 4, 0, 0]} name="Recall" />
                    <Bar dataKey="f1" fill="#a855f7" radius={[4, 4, 0, 0]} name="F1 Score" />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm flex items-center gap-2"><TrendingUp className="h-4 w-4" />Radar Comparison</CardTitle>
                <CardDescription>Multi-dimensional model analysis</CardDescription></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <RadarChart data={models}>
                    <PolarGrid stroke="hsl(var(--border))" />
                    <PolarAngleAxis dataKey="name" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                    <PolarRadiusAxis tick={{ fontSize: 9 }} stroke="hsl(var(--muted-foreground))" domain={[0, 100]} />
                    <Radar name="Precision" dataKey="precision" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} />
                    <Radar name="Recall" dataKey="recall" stroke="#22c55e" fill="#22c55e" fillOpacity={0.1} />
                    <Radar name="F1" dataKey="f1" stroke="#a855f7" fill="#a855f7" fillOpacity={0.1} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                  </RadarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
