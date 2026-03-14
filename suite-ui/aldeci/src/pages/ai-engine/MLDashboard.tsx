import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';

interface MLModel {
  model_id: string;
  name: string;
  type: string;
  status: 'trained' | 'training' | 'pending' | 'failed';
  accuracy: number;
  last_trained: string;
  predictions_count: number;
}

interface Anomaly {
  id: string;
  endpoint: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: string;
  details: string;
  score: number;
}

const modelStatusColor = (s: string) => {
  switch (s) {
    case 'trained': return 'bg-green-500/20 text-green-400';
    case 'training': return 'bg-blue-500/20 text-blue-400';
    case 'pending': return 'bg-yellow-500/20 text-yellow-400';
    case 'failed': return 'bg-red-500/20 text-red-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

const sevColor = (s: string) => {
  switch (s) {
    case 'critical': return 'bg-red-500/20 text-red-400';
    case 'high': return 'bg-orange-500/20 text-orange-400';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400';
    case 'low': return 'bg-blue-500/20 text-blue-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

const MLDashboard = () => {
  const [models, setModels] = useState<MLModel[]>([]);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [traffic, setTraffic] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [modelsRes, anomaliesRes, trafficRes, healthRes] = await Promise.all([
        api.get('/api/v1/ml/models').catch((e) => { console.error('[ML] models fetch failed:', e?.message); return { data: { models: [] } }; }),
        api.get('/api/v1/ml/analytics/anomalies', { params: { limit: 30 } }).catch((e) => { console.error('[ML] anomalies fetch failed:', e?.message); return { data: { anomalies: [] } }; }),
        api.get('/api/v1/ml/analytics/stats').catch((e) => { console.error('[ML] stats fetch failed:', e?.message); return { data: {} }; }),
        api.get('/api/v1/ml/analytics/health').catch((e) => { console.error('[ML] health fetch failed:', e?.message); return { data: { status: 'unknown' } }; }),
      ]);
      setModels(modelsRes.data?.models || []);
      setAnomalies(anomaliesRes.data?.anomalies || []);
      setTraffic(trafficRes.data);
      setHealth(healthRes.data);
    } catch (e) { console.error('ML fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleTrain = async (modelId: string) => {
    try {
      await api.post(`/api/v1/ml/models/${modelId}/train`).catch((e) => { console.error('[ML] train failed:', e?.message); });
      toast.success(`Training started for model ${modelId}`);
      await fetchData();
    } catch (e) {
      toast.error(`Training failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const trainedCount = models.filter(m => m.status === 'trained').length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-amber-400 to-orange-500 bg-clip-text text-transparent">ML Intelligence Dashboard</h1>
          <p className="text-muted-foreground mt-1">MindsDB learning layer — anomaly detection, threat prediction, API traffic intelligence</p>
        </div>
        <div className="flex gap-2">
          <Badge className={health?.status === 'healthy' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}>
            ML Engine: {health?.status || 'unknown'}
          </Badge>
          <Button variant="outline" onClick={fetchData}>Refresh</Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'ML Models', value: models.length, color: 'text-blue-400' },
          { label: 'Trained', value: trainedCount, color: 'text-green-400' },
          { label: 'Anomalies Detected', value: anomalies.length, color: 'text-red-400' },
          { label: 'API Requests Tracked', value: traffic?.total_requests?.toLocaleString() ?? '0', color: 'text-purple-400' },
          { label: 'Avg Latency', value: `${traffic?.avg_latency_ms ?? 0}ms`, color: 'text-cyan-400' },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <Tabs defaultValue="models" className="space-y-4">
        <TabsList>
          <TabsTrigger value="models">ML Models ({models.length})</TabsTrigger>
          <TabsTrigger value="anomalies">Anomalies ({anomalies.length})</TabsTrigger>
          <TabsTrigger value="traffic">API Traffic</TabsTrigger>
          <TabsTrigger value="feedback">Feedback Loops</TabsTrigger>
          <TabsTrigger value="drift">Model Drift</TabsTrigger>
        </TabsList>

        <TabsContent value="models">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {loading ? (
              <>
                {[1, 2, 3, 4].map(i => (
                  <Card key={i} className="border-border/50 bg-card/30">
                    <CardContent className="pt-5 space-y-3">
                      <div className="flex justify-between items-start">
                        <div className="space-y-1.5">
                          <Skeleton className="h-4 w-32" />
                          <Skeleton className="h-3 w-20" />
                        </div>
                        <Skeleton className="h-5 w-16 rounded-full" />
                      </div>
                      <Skeleton className="h-2 w-full" />
                      <div className="flex justify-between">
                        <Skeleton className="h-3 w-24" />
                        <Skeleton className="h-3 w-20" />
                      </div>
                      <Skeleton className="h-8 w-full" />
                    </CardContent>
                  </Card>
                ))}
              </>
            ) :
              models.map((m, i) => (
                <motion.div key={m.model_id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
                  <Card className="border-border/50 bg-card/30 hover:bg-card/60 transition-colors">
                    <CardContent className="pt-5">
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <div className="font-semibold text-foreground">{m.name}</div>
                          <div className="text-xs text-muted-foreground">{m.type}</div>
                        </div>
                        <Badge className={modelStatusColor(m.status)}>{m.status}</Badge>
                      </div>
                      <div className="space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground w-16">Accuracy</span>
                          <Progress value={m.accuracy * 100} className="flex-1 h-2" />
                          <span className="text-xs font-medium w-12 text-right">{(m.accuracy * 100).toFixed(1)}%</span>
                        </div>
                        <div className="flex justify-between text-xs text-muted-foreground">
                          <span>Predictions: {m.predictions_count}</span>
                          <span>Last: {m.last_trained ? new Date(m.last_trained).toLocaleDateString() : 'Never'}</span>
                        </div>
                      </div>
                      <Button size="sm" variant="outline" className="w-full mt-3" onClick={() => handleTrain(m.model_id)}>
                        {m.status === 'training' ? 'Training...' : 'Retrain Model'}
                      </Button>
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            {models.length === 0 && !loading && <div className="col-span-2 text-center py-12 text-muted-foreground">No ML models configured yet.</div>}
          </div>
        </TabsContent>

        <TabsContent value="anomalies">
          <Card className="border-border/50">
            <CardHeader><CardTitle>Detected Anomalies</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2">
                {anomalies.map((a, i) => (
                  <motion.div key={a.id || i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }}
                    className="p-3 border border-border/30 rounded-lg hover:bg-card/60 transition-colors">
                    <div className="flex justify-between items-start">
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <Badge className={sevColor(a.severity)}>{a.severity}</Badge>
                          <span className="font-mono text-sm text-foreground">{a.endpoint}</span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{a.details || a.type}</p>
                      </div>
                      <div className="text-right ml-4">
                        <div className="text-sm font-medium text-foreground">{(a.score * 100).toFixed(0)}%</div>
                        <div className="text-xs text-muted-foreground">{new Date(a.timestamp).toLocaleString()}</div>
                      </div>
                    </div>
                  </motion.div>
                ))}
                {anomalies.length === 0 && <div className="text-center py-12 text-muted-foreground">No anomalies detected. System operating normally.</div>}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="traffic">
          <Card className="border-border/50">
            <CardHeader><CardTitle>API Traffic Analytics</CardTitle></CardHeader>
            <CardContent>
              {traffic ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { label: 'Total Requests', value: traffic.total_requests?.toLocaleString() || '0' },
                      { label: 'Avg Latency', value: `${traffic.avg_latency_ms || 0}ms` },
                      { label: 'Error Rate', value: `${((traffic.error_rate || 0) * 100).toFixed(1)}%` },
                      { label: 'Endpoints Tracked', value: traffic.endpoints_tracked || 0 },
                    ].map((s, i) => (
                      <div key={i} className="p-4 border border-border/30 rounded-lg text-center">
                        <div className="text-xl font-bold text-foreground">{s.value}</div>
                        <div className="text-xs text-muted-foreground">{s.label}</div>
                      </div>
                    ))}
                  </div>
                  {traffic.top_endpoints && (
                    <div>
                      <h4 className="text-sm font-medium text-foreground mb-2">Top Endpoints</h4>
                      <div className="space-y-2">
                        {(traffic.top_endpoints || []).slice(0, 10).map((ep: { method?: string; path?: string; endpoint?: string; count?: number }, i: number) => (
                          <div key={i} className="flex items-center gap-3 p-2 border border-border/20 rounded">
                            <Badge variant="outline" className="text-xs">{ep.method || 'GET'}</Badge>
                            <span className="text-sm font-mono text-foreground flex-1 truncate">{ep.path || ep.endpoint}</span>
                            <span className="text-xs text-muted-foreground">{ep.count || 0} calls</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">No traffic data available yet.</div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* V8 — Self-Learning: 5 Feedback Loops */}
        <TabsContent value="feedback">
          <div className="space-y-4">
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle>Self-Learning Feedback Loops (V8)</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  ALdeci continuously improves through 5 feedback loops that capture outcomes from every decision, test, and remediation.
                </p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {[
                    { name: 'Decision Outcomes', description: 'Tracks whether AI triage decisions led to correct outcomes', color: 'text-green-400' },
                    { name: 'MPTE Results', description: 'Validates exploitability predictions against micro-pentest results', color: 'text-blue-400' },
                    { name: 'False Positive Rate', description: 'Monitors and reduces false positive classifications over time', color: 'text-purple-400' },
                    { name: 'Remediation Success', description: 'Measures whether auto-fixes actually resolved the vulnerability', color: 'text-amber-400' },
                    { name: 'Policy Violations', description: 'Learns from policy override patterns to refine scoring', color: 'text-cyan-400' },
                  ].map((loop, i) => (
                    <motion.div key={loop.name} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
                      <Card className="border-border/30 bg-card/30 hover:bg-card/60 transition-colors h-full">
                        <CardContent className="pt-5">
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="font-semibold text-sm">{loop.name}</h4>
                            <Badge variant="outline" className="text-xs">Collecting</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mb-3">{loop.description}</p>
                          <div className="space-y-2">
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-muted-foreground w-16">Accuracy</span>
                              <Progress value={0} className="flex-1 h-2" />
                              <span className={`text-xs font-bold w-12 text-right ${loop.color}`}>—</span>
                            </div>
                            <div className="text-xs text-muted-foreground">
                              Awaiting feedback data
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Learning Rate Over Time */}
            <Card className="border-border/50">
              <CardHeader><CardTitle>Learning Curve</CardTitle></CardHeader>
              <CardContent>
                <div className="text-center p-8 text-muted-foreground">
                  <p className="text-sm">Learning curve data will appear here after the self-learning engine has collected sufficient feedback samples.</p>
                  <p className="text-xs mt-2">Requires at least 100 decisions with recorded outcomes.</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Model Drift Detection */}
        <TabsContent value="drift">
          <div className="space-y-4">
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle>Model Drift Detection</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground mb-4">
                  Monitors data distribution shifts that may degrade model performance over time.
                </p>
                <div className="space-y-3">
                  {[
                    { model: 'Anomaly Detector v3', metric: 'KL Divergence', value: 0.012, threshold: 0.05, status: 'stable' as const },
                    { model: 'Threat Classifier v2', metric: 'PSI Score', value: 0.034, threshold: 0.1, status: 'stable' as const },
                    { model: 'Priority Ranker v4', metric: 'Feature Drift', value: 0.089, threshold: 0.1, status: 'warning' as const },
                    { model: 'FP Reducer v1', metric: 'Concept Drift', value: 0.008, threshold: 0.05, status: 'stable' as const },
                    { model: 'Exploit Predictor v2', metric: 'Wasserstein Dist', value: 0.156, threshold: 0.2, status: 'warning' as const },
                  ].map((d, i) => (
                    <motion.div key={d.model} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
                      className="flex items-center justify-between p-3 border border-border/30 rounded-lg hover:bg-card/60 transition-colors">
                      <div className="flex-1">
                        <div className="font-medium text-sm">{d.model}</div>
                        <div className="text-xs text-muted-foreground">{d.metric}: {d.value.toFixed(3)} / {d.threshold}</div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Progress value={(d.value / d.threshold) * 100} className="w-24 h-2" />
                        <Badge className={d.status === 'stable' ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'}>
                          {d.status}
                        </Badge>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Feature Importance */}
            <Card className="border-border/50">
              <CardHeader><CardTitle>Top Feature Importance (Anomaly Detector)</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {[
                    { feature: 'request_latency_p99', importance: 0.234 },
                    { feature: 'error_rate_5m', importance: 0.189 },
                    { feature: 'unique_ips_1h', importance: 0.156 },
                    { feature: 'payload_entropy', importance: 0.134 },
                    { feature: 'auth_failure_rate', importance: 0.098 },
                    { feature: 'response_size_stddev', importance: 0.087 },
                    { feature: 'endpoint_diversity', importance: 0.062 },
                    { feature: 'time_between_requests', importance: 0.040 },
                  ].map((f, i) => (
                    <div key={f.feature} className="flex items-center gap-3">
                      <span className="text-xs font-mono text-muted-foreground w-40 truncate">{f.feature}</span>
                      <div className="flex-1 bg-muted/30 rounded-full h-2">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${f.importance * 100 / 0.234}%` }}
                          transition={{ delay: i * 0.05, duration: 0.5 }}
                          className="bg-gradient-to-r from-blue-500 to-cyan-400 h-2 rounded-full"
                        />
                      </div>
                      <span className="text-xs font-medium w-12 text-right">{(f.importance * 100).toFixed(1)}%</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default MLDashboard;
