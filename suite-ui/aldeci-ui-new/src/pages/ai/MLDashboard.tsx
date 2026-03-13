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
  BarChart3, Activity, TrendingUp, Shield, AlertTriangle,
  RefreshCw, Eye, Brain, Cpu, Database, Target,
  Clock, CheckCircle, Zap, TriangleAlert
} from "lucide-react";
import { apiClient, toArray } from "@/lib/api-utils";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface Anomaly {
  id: string;
  type: string;
  severity: string;
  description: string;
  detected_at: string;
  status: string;
  score: number;
}

interface ThreatIndicator {
  indicator_id: string;
  type: string;
  value: string;
  confidence: number;
  source: string;
  first_seen: string;
}

export default function MLDashboard() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [threats, setThreats] = useState<ThreatIndicator[]>([]);
  const [analyticsHealth, setAnalyticsHealth] = useState<Record<string, unknown>>({});
  const [analyticsStats, setAnalyticsStats] = useState<Record<string, unknown>>({});
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
      if (anomRes.status === "fulfilled") setAnomalies(toArray(anomRes.value).slice(0, 20) as unknown as Anomaly[]);
      if (threatRes.status === "fulfilled") setThreats(toArray(threatRes.value).slice(0, 20) as unknown as ThreatIndicator[]);
      if (healthRes.status === "fulfilled") setAnalyticsHealth(healthRes.value ?? {});
      if (statsRes.status === "fulfilled") setAnalyticsStats(statsRes.value ?? {});
      if (learnRes.status === "fulfilled") setLearningStats(learnRes.value ?? {});
    } catch { /* handled */ } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (loading) return <PageSkeleton />;

  const anomalyCount = anomalies.length || Number(analyticsStats?.total_anomalies ?? 0);
  const threatCount = threats.length || Number(analyticsStats?.total_threats ?? 0);
  const modelHealth = String(analyticsHealth?.status ?? "healthy");
  const learningCycles = Number(learningStats?.total_feedback ?? learningStats?.cycles ?? 0);

  return (
    <div className="space-y-6 p-6">
      <PageHeader
        title="ML Dashboard"
        description="Machine learning analytics — anomaly detection, threat prediction, and self-learning performance"
        badge="AI Engine"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={fetchData}><RefreshCw className="h-4 w-4 mr-1" />Refresh</Button>
            <Button size="sm" onClick={async () => {
              try {
                await apiClient("/api/v1/ml/predict/anomaly", { method: "POST", body: JSON.stringify({ scan_type: "full", lookback_hours: 24 }) });
                toast.success("Anomaly detection scan started");
                setTimeout(fetchData, 2000);
              } catch (e: unknown) { toast.error(`Scan failed: ${e instanceof Error ? e.message : ""}`); }
            }}><Eye className="h-4 w-4 mr-1" />Detect Anomalies</Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Anomalies Detected" value={anomalyCount} icon={AlertTriangle} trend={anomalyCount > 5 ? "down" : "up"} trendLabel={anomalyCount > 5 ? "Investigate" : "Low"} />
        <KpiCard title="Threat Indicators" value={threatCount} icon={Shield} trend="flat" trendLabel="Active" />
        <KpiCard title="ML Health" value={modelHealth === "healthy" ? "Healthy" : modelHealth} icon={Activity} trend={modelHealth === "healthy" ? "up" : "down"} trendLabel="All models" />
        <KpiCard title="Learning Cycles" value={learningCycles} icon={Brain} trend="up" trendLabel="Feedback loops" />
      </div>

      <Tabs defaultValue="anomalies" className="space-y-4">
        <TabsList>
          <TabsTrigger value="anomalies">Anomalies</TabsTrigger>
          <TabsTrigger value="threats">Threat Predictions</TabsTrigger>
          <TabsTrigger value="learning">Self-Learning</TabsTrigger>
          <TabsTrigger value="performance">Model Performance</TabsTrigger>
        </TabsList>

        <TabsContent value="anomalies">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[420px]">
                <div className="divide-y divide-border/50">
                  {anomalies.length === 0 && (
                    <div className="p-8 text-center text-muted-foreground">
                      <Eye className="h-12 w-12 mx-auto mb-3 opacity-40" />
                      <p className="text-sm font-medium">No anomalies detected</p>
                      <p className="text-xs mt-1">Click "Detect Anomalies" to run ML-based anomaly scan</p>
                    </div>
                  )}
                  {anomalies.map((a, i) => (
                    <motion.div key={a.id || i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }} className="p-4 hover:bg-accent/30 transition-colors">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className={cn("p-2 rounded-lg", a.severity === "critical" ? "bg-red-500/10 text-red-400" : a.severity === "high" ? "bg-orange-500/10 text-orange-400" : "bg-yellow-500/10 text-yellow-400")}>
                            <TriangleAlert className="h-4 w-4" />
                          </div>
                          <div>
                            <p className="text-sm font-medium">{a.type || a.description || `Anomaly ${i + 1}`}</p>
                            <p className="text-xs text-muted-foreground">{a.description || "Detected by ML analytics engine"}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">Score: {(a.score * 100).toFixed(0) || "—"}%</span>
                          <Badge variant={a.severity === "critical" ? "destructive" : a.severity === "high" ? "default" : "secondary"}>{a.severity || "medium"}</Badge>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="threats">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[420px]">
                <div className="divide-y divide-border/50">
                  {threats.length === 0 && (
                    <div className="p-8 text-center text-muted-foreground">
                      <Shield className="h-12 w-12 mx-auto mb-3 opacity-40" />
                      <p className="text-sm font-medium">No threat indicators</p>
                      <p className="text-xs mt-1">Threat predictions will appear as the ML models analyze patterns</p>
                    </div>
                  )}
                  {threats.map((t, i) => (
                    <div key={t.indicator_id || i} className="p-4 hover:bg-accent/30 transition-colors">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="text-sm font-medium">{t.type || "Indicator"}: <code className="text-xs font-mono bg-muted px-1 rounded">{t.value || t.indicator_id}</code></p>
                          <p className="text-xs text-muted-foreground">Source: {t.source || "ML Engine"} · First seen: {t.first_seen ? new Date(t.first_seen).toLocaleDateString() : "—"}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs">{t.confidence ? `${(t.confidence * 100).toFixed(0)}%` : "—"} confidence</span>
                          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={async () => {
                            try {
                              await apiClient(`/api/v1/ml/analytics/threats/${t.indicator_id}/acknowledge`, { method: "POST" });
                              toast.success("Acknowledged");
                            } catch { toast.error("Acknowledge failed"); }
                          }}>Ack</Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="learning">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm">Feedback Loops</CardTitle></CardHeader>
              <CardContent>
                {/* SAMPLE DATA — TODO: Wire to real feedback loop metrics from /api/v1/ml/feedback */}
                {[
                  { loop: "False Positive Rate", desc: "Reported FPs adjust severity scoring", metric: "2.1% FP rate" },
                  { loop: "MPTE Verification", desc: "Pentest results refine exploitability models", metric: "89% verified" },
                  { loop: "Remediation Time", desc: "Fix success feeds back to priority scoring", metric: "3.4h avg MTTR" },
                  { loop: "Policy Tuning", desc: "Policy violations adjust thresholds", metric: "12 adjustments" },
                ].map((loop, i) => (
                  <div key={i} className="flex items-center justify-between py-3 border-b border-border/30 last:border-0">
                    <div>
                      <p className="text-sm font-medium">{loop.loop}</p>
                      <p className="text-xs text-muted-foreground">{loop.desc}</p>
                    </div>
                    <Badge variant="outline" className="text-xs">{loop.metric}</Badge>
                  </div>
                ))}
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm">Learning Weights</CardTitle></CardHeader>
              <CardContent>
                {Object.entries(learningStats?.weights ?? {
                  // SAMPLE DATA — TODO: Wire to real model weights from /api/v1/ml/weights
                  "epss_score": 0.28, "cvss_score": 0.15, "kev_status": 0.22,
                  "reachability": 0.18, "data_classification": 0.12, "blast_radius": 0.05
                }).map(([key, val]) => (
                  <div key={key} className="py-2 border-b border-border/30 last:border-0">
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-muted-foreground font-mono">{key}</span>
                      <span className="font-medium">{typeof val === "number" ? (val * 100).toFixed(1) + "%" : String(val)}</span>
                    </div>
                    <Progress value={typeof val === "number" ? val * 100 : 50} className="h-1" />
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="performance">
          <Card>
            <CardContent className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* SAMPLE DATA — TODO: Wire to real model performance metrics from /api/v1/ml/models/metrics */}
                {[
                  { model: "Triage Classifier", precision: 94.2, recall: 91.8, f1: 93.0, auc: 97.1 },
                  { model: "Severity Predictor", precision: 89.7, recall: 93.4, f1: 91.5, auc: 95.8 },
                  { model: "Anomaly Detector", precision: 87.3, recall: 95.1, f1: 91.0, auc: 94.2 },
                  { model: "Risk Scorer", precision: 92.1, recall: 88.9, f1: 90.5, auc: 96.3 },
                  { model: "MTTR Predictor", precision: 85.4, recall: 82.7, f1: 84.0, auc: 91.7 },
                  { model: "False Positive Filter", precision: 96.8, recall: 84.2, f1: 90.1, auc: 97.5 },
                ].map((m, i) => (
                  <Card key={i} className="border-border/50">
                    <CardContent className="p-4">
                      <p className="text-sm font-semibold mb-3">{m.model}</p>
                      {[
                        { label: "Precision", value: m.precision },
                        { label: "Recall", value: m.recall },
                        { label: "F1 Score", value: m.f1 },
                        { label: "AUC-ROC", value: m.auc },
                      ].map(metric => (
                        <div key={metric.label} className="mb-2">
                          <div className="flex justify-between text-xs mb-0.5">
                            <span className="text-muted-foreground">{metric.label}</span>
                            <span className="font-medium">{metric.value}%</span>
                          </div>
                          <Progress value={metric.value} className="h-1" />
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
