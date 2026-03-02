import { useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface RiskTrajectoryResult {
  current_risk: number;
  forecast_30d: number;
  forecast_90d?: number;
  trend: string;
  confidence: number;
  trajectory_points?: Array<{ day: number; risk: number }>;
  contributing_factors?: string[];
  recommendations?: string[];
  model?: string;
  cve_count?: number;
}

interface AttackSimResult {
  scenario: string;
  probability: number;
  impact: string;
  attack_paths?: Array<{ step: number; description: string; likelihood: number }>;
  mitigations?: string[];
}

const appleEase = [0.16, 1, 0.3, 1] as const;

const trendColor = (trend: string) => {
  switch (trend?.toLowerCase()) {
    case 'increasing': return 'text-red-400';
    case 'decreasing': return 'text-green-400';
    case 'stable': return 'text-yellow-400';
    default: return 'text-gray-400';
  }
};

const trendIcon = (trend: string) => {
  switch (trend?.toLowerCase()) {
    case 'increasing': return '📈';
    case 'decreasing': return '📉';
    case 'stable': return '➡️';
    default: return '📊';
  }
};

const riskColor = (risk: number) => {
  if (risk >= 0.8) return 'text-red-400';
  if (risk >= 0.6) return 'text-orange-400';
  if (risk >= 0.4) return 'text-yellow-400';
  return 'text-green-400';
};

// ═══════════════════════════════════════════════════════════════════════════
// Risk Score Gauge
// ═══════════════════════════════════════════════════════════════════════════

function RiskGauge({ value, label }: { value: number; label: string }) {
  const percentage = Math.round(value * 100);
  const rotation = -90 + (value * 180);
  const gaugeColor = value >= 0.8 ? '#ef4444' : value >= 0.6 ? '#f97316' : value >= 0.4 ? '#eab308' : '#22c55e';

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-28 h-16 overflow-hidden">
        {/* Background arc */}
        <svg viewBox="0 0 120 60" className="w-full h-full">
          <path d="M 10 55 A 50 50 0 0 1 110 55" fill="none" stroke="rgb(55,65,81)" strokeWidth="8" strokeLinecap="round" />
          <motion.path
            d="M 10 55 A 50 50 0 0 1 110 55"
            fill="none"
            stroke={gaugeColor}
            strokeWidth="8"
            strokeLinecap="round"
            initial={{ pathLength: 0 }}
            animate={{ pathLength: value }}
            transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1] }}
          />
        </svg>
        {/* Needle */}
        <motion.div
          className="absolute bottom-0 left-1/2 origin-bottom"
          style={{ width: 2, height: 40, marginLeft: -1 }}
          initial={{ rotate: -90 }}
          animate={{ rotate: rotation }}
          transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
        >
          <div className="w-full h-full bg-white rounded-full" />
        </motion.div>
      </div>
      <motion.span
        className={`text-2xl font-bold mt-1 ${riskColor(value)}`}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5 }}
      >
        {percentage}%
      </motion.span>
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Trajectory Chart (simplified bar chart)
// ═══════════════════════════════════════════════════════════════════════════

function TrajectoryChart({ points }: { points: Array<{ day: number; risk: number }> }) {
  if (!points?.length) return null;
  const maxRisk = Math.max(...points.map(p => p.risk), 0.01);

  return (
    <div className="flex items-end gap-1 h-32 mt-4">
      {points.map((p, i) => (
        <motion.div
          key={p.day}
          className="flex-1 flex flex-col items-center gap-1"
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: 'auto', opacity: 1 }}
          transition={{ delay: i * 0.05, ease: appleEase }}
        >
          <div className="w-full relative" style={{ height: 100 }}>
            <motion.div
              className="absolute bottom-0 w-full rounded-t-sm"
              style={{
                backgroundColor: p.risk >= 0.8 ? '#ef4444' : p.risk >= 0.6 ? '#f97316' : p.risk >= 0.4 ? '#eab308' : '#22c55e',
                opacity: 0.7,
              }}
              initial={{ height: 0 }}
              animate={{ height: `${(p.risk / maxRisk) * 100}%` }}
              transition={{ delay: i * 0.05 + 0.3, duration: 0.5, ease: appleEase }}
            />
          </div>
          <span className="text-[9px] text-muted-foreground">D{p.day}</span>
        </motion.div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════════

const Predictions = () => {
  const [cveIds, setCveIds] = useState('');
  const [trajectory, setTrajectory] = useState<RiskTrajectoryResult | null>(null);
  const [attackResult, setAttackResult] = useState<AttackSimResult | null>(null);
  const [scenario, setScenario] = useState('');
  const [loading, setLoading] = useState(false);
  const [attackLoading, setAttackLoading] = useState(false);

  const runPrediction = useCallback(async () => {
    if (!cveIds.trim()) {
      toast.error('Please enter at least one CVE ID');
      return;
    }
    setLoading(true);
    toast.info('Running risk trajectory prediction...');
    try {
      const ids = cveIds.split(',').map(s => s.trim()).filter(Boolean);
      const res = await api.post('/api/v1/predictions/risk-trajectory', { cve_ids: ids });
      setTrajectory(res.data as RiskTrajectoryResult);
      toast.success('Prediction complete');
    } catch (err) {
      console.error('Prediction failed', err);
      toast.error('Risk prediction failed');
    } finally {
      setLoading(false);
    }
  }, [cveIds]);

  const runAttackSim = useCallback(async () => {
    if (!scenario.trim()) {
      toast.error('Please describe an attack scenario');
      return;
    }
    setAttackLoading(true);
    toast.info('Simulating attack chain...');
    try {
      const res = await api.post('/api/v1/predictions/attack-chain', { target: scenario.trim() });
      setAttackResult(res.data as AttackSimResult);
      toast.success('Attack simulation complete');
    } catch (err) {
      console.error('Attack sim failed', err);
      toast.error('Attack simulation failed');
    } finally {
      setAttackLoading(false);
    }
  }, [scenario]);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex justify-between items-center"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-400 via-violet-400 to-indigo-400 bg-clip-text text-transparent">
            Risk Predictions
          </h1>
          <p className="text-muted-foreground mt-1">
            Markov Chain & Bayesian Network predictions for vulnerability risk trajectory
          </p>
        </div>
        <Badge variant="outline" className="bg-purple-500/20 text-purple-400 border-purple-500/30">
          🧠 AI Engine
        </Badge>
      </motion.div>

      <Tabs defaultValue="trajectory" className="space-y-4">
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="trajectory">📈 Risk Trajectory</TabsTrigger>
          <TabsTrigger value="attack">⚔️ Attack Chain</TabsTrigger>
        </TabsList>

        {/* Risk Trajectory Tab */}
        <TabsContent value="trajectory">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Input Card */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-lg text-gray-200">Predict Risk Trajectory</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1.5">CVE IDs (comma-separated)</label>
                  <Input
                    value={cveIds}
                    onChange={(e) => setCveIds(e.target.value)}
                    placeholder="CVE-2024-1234, CVE-2024-5678"
                    className="bg-gray-800/50 border-gray-700/50"
                    onKeyDown={(e) => e.key === 'Enter' && runPrediction()}
                  />
                </div>
                <Button
                  onClick={runPrediction}
                  disabled={loading || !cveIds.trim()}
                  className="w-full bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-500 hover:to-violet-500 text-white shadow-lg shadow-purple-500/20"
                >
                  {loading ? (
                    <span className="flex items-center gap-2"><span className="animate-spin">🔮</span> Predicting...</span>
                  ) : '🔮 Run Prediction'}
                </Button>

                {/* Quick presets */}
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground">Quick presets:</p>
                  <div className="flex flex-wrap gap-2">
                    {[
                      { label: 'Log4Shell', value: 'CVE-2021-44228' },
                      { label: 'Spring4Shell', value: 'CVE-2022-22965' },
                      { label: 'MOVEit', value: 'CVE-2023-34362' },
                    ].map(p => (
                      <button
                        key={p.value}
                        onClick={() => setCveIds(p.value)}
                        className="text-xs px-2 py-1 rounded-md border border-gray-700/30 bg-gray-800/30 hover:bg-gray-800/60 text-gray-300 transition-colors"
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Results */}
            <div className="lg:col-span-2 space-y-6">
              <AnimatePresence mode="wait">
                {trajectory ? (
                  <motion.div
                    key="result"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ ease: appleEase }}
                    className="space-y-6"
                  >
                    {/* Score gauges */}
                    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                      <CardContent className="pt-6">
                        <div className="flex justify-around items-start flex-wrap gap-6">
                          <RiskGauge value={trajectory.current_risk ?? 0} label="Current Risk" />
                          <RiskGauge value={trajectory.forecast_30d ?? 0} label="30-Day Forecast" />
                          {trajectory.forecast_90d !== undefined && (
                            <RiskGauge value={trajectory.forecast_90d} label="90-Day Forecast" />
                          )}
                          <div className="flex flex-col items-center pt-2">
                            <span className="text-4xl mb-1">{trendIcon(trajectory.trend)}</span>
                            <span className={`text-xl font-bold ${trendColor(trajectory.trend)}`}>
                              {trajectory.trend || 'Unknown'}
                            </span>
                            <span className="text-xs text-muted-foreground">Trend</span>
                          </div>
                        </div>

                        {/* Trajectory chart */}
                        {trajectory.trajectory_points && trajectory.trajectory_points.length > 0 && (
                          <div className="mt-6 pt-4 border-t border-gray-700/30">
                            <h3 className="text-sm font-medium text-gray-300 mb-2">Risk Trajectory Over Time</h3>
                            <TrajectoryChart points={trajectory.trajectory_points} />
                          </div>
                        )}
                      </CardContent>
                    </Card>

                    {/* Details */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {/* Contributing Factors */}
                      {trajectory.contributing_factors && trajectory.contributing_factors.length > 0 && (
                        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm text-gray-300">⚠️ Contributing Factors</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {trajectory.contributing_factors.map((f, i) => (
                                <motion.div
                                  key={i}
                                  initial={{ opacity: 0, x: -10 }}
                                  animate={{ opacity: 1, x: 0 }}
                                  transition={{ delay: i * 0.05, ease: appleEase }}
                                  className="flex items-start gap-2 text-sm"
                                >
                                  <span className="text-red-400 mt-0.5">•</span>
                                  <span className="text-gray-300">{f}</span>
                                </motion.div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                      )}

                      {/* Recommendations */}
                      {trajectory.recommendations && trajectory.recommendations.length > 0 && (
                        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                          <CardHeader className="pb-2">
                            <CardTitle className="text-sm text-gray-300">✅ Recommendations</CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {trajectory.recommendations.map((r, i) => (
                                <motion.div
                                  key={i}
                                  initial={{ opacity: 0, x: -10 }}
                                  animate={{ opacity: 1, x: 0 }}
                                  transition={{ delay: i * 0.05, ease: appleEase }}
                                  className="flex items-start gap-2 text-sm"
                                >
                                  <span className="text-green-400 mt-0.5">•</span>
                                  <span className="text-gray-300">{r}</span>
                                </motion.div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                      )}
                    </div>

                    {/* Raw JSON */}
                    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-sm text-gray-300">Raw API Response</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <pre className="text-xs bg-gray-950/60 p-4 rounded-lg overflow-auto max-h-48 text-gray-400 font-mono border border-gray-800/50">
                          {JSON.stringify(trajectory, null, 2)}
                        </pre>
                      </CardContent>
                    </Card>
                  </motion.div>
                ) : (
                  <motion.div
                    key="empty"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                  >
                    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                      <CardContent className="py-16 text-center">
                        <div className="text-5xl mb-4">🔮</div>
                        <p className="text-lg text-gray-300 mb-2">No predictions yet</p>
                        <p className="text-sm text-muted-foreground">Enter CVE IDs and run a prediction to see risk trajectory analysis</p>
                        <p className="text-xs text-muted-foreground mt-4">
                          Powered by Markov Chain & Bayesian Network models
                        </p>
                      </CardContent>
                    </Card>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </TabsContent>

        {/* Attack Chain Tab */}
        <TabsContent value="attack">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md lg:col-span-1">
              <CardHeader>
                <CardTitle className="text-lg text-gray-200">Attack Chain Simulation</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-xs text-muted-foreground block mb-1.5">Target / Scenario</label>
                  <Input
                    value={scenario}
                    onChange={(e) => setScenario(e.target.value)}
                    placeholder="e.g., web-app-prod, api-gateway, database-cluster"
                    className="bg-gray-800/50 border-gray-700/50"
                    onKeyDown={(e) => e.key === 'Enter' && runAttackSim()}
                  />
                </div>
                <Button
                  onClick={runAttackSim}
                  disabled={attackLoading || !scenario.trim()}
                  className="w-full bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white shadow-lg shadow-red-500/20"
                >
                  {attackLoading ? (
                    <span className="flex items-center gap-2"><span className="animate-spin">⚔️</span> Simulating...</span>
                  ) : '⚔️ Simulate Attack'}
                </Button>
              </CardContent>
            </Card>

            <div className="lg:col-span-2">
              <AnimatePresence mode="wait">
                {attackResult ? (
                  <motion.div
                    key="attack-result"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-4"
                  >
                    <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                      <CardHeader>
                        <CardTitle className="text-lg text-gray-200">Attack Chain Results</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-3 gap-4 mb-6">
                          <div className="text-center p-3 rounded-lg bg-gray-800/30 border border-gray-700/20">
                            <div className="text-xs text-muted-foreground mb-1">Probability</div>
                            <div className={`text-2xl font-bold ${riskColor(attackResult.probability ?? 0)}`}>
                              {Math.round((attackResult.probability ?? 0) * 100)}%
                            </div>
                          </div>
                          <div className="text-center p-3 rounded-lg bg-gray-800/30 border border-gray-700/20">
                            <div className="text-xs text-muted-foreground mb-1">Impact</div>
                            <div className="text-2xl font-bold text-orange-400">{attackResult.impact || 'Unknown'}</div>
                          </div>
                          <div className="text-center p-3 rounded-lg bg-gray-800/30 border border-gray-700/20">
                            <div className="text-xs text-muted-foreground mb-1">Steps</div>
                            <div className="text-2xl font-bold text-blue-400">{attackResult.attack_paths?.length ?? 0}</div>
                          </div>
                        </div>

                        {/* Attack path steps */}
                        {attackResult.attack_paths && attackResult.attack_paths.length > 0 && (
                          <div className="space-y-3">
                            <h3 className="text-sm font-medium text-gray-300">Attack Path</h3>
                            {attackResult.attack_paths.map((step, i) => (
                              <motion.div
                                key={i}
                                initial={{ opacity: 0, x: -20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: i * 0.1, ease: appleEase }}
                                className="flex items-start gap-3 p-3 rounded-lg bg-gray-800/30 border border-gray-700/20"
                              >
                                <div className="w-8 h-8 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center text-sm font-bold shrink-0">
                                  {step.step}
                                </div>
                                <div className="flex-1">
                                  <p className="text-sm text-gray-200">{step.description}</p>
                                  <div className="flex items-center gap-2 mt-1">
                                    <span className="text-xs text-muted-foreground">Likelihood:</span>
                                    <div className="flex-1 h-1.5 bg-gray-800 rounded-full max-w-24">
                                      <motion.div
                                        className="h-full rounded-full bg-red-500/60"
                                        initial={{ width: 0 }}
                                        animate={{ width: `${(step.likelihood ?? 0) * 100}%` }}
                                        transition={{ delay: i * 0.1 + 0.3, ease: appleEase }}
                                      />
                                    </div>
                                    <span className="text-xs text-gray-400">{Math.round((step.likelihood ?? 0) * 100)}%</span>
                                  </div>
                                </div>
                              </motion.div>
                            ))}
                          </div>
                        )}

                        {/* Mitigations */}
                        {attackResult.mitigations && attackResult.mitigations.length > 0 && (
                          <div className="mt-4 pt-4 border-t border-gray-700/30">
                            <h3 className="text-sm font-medium text-gray-300 mb-2">Recommended Mitigations</h3>
                            <div className="space-y-1.5">
                              {attackResult.mitigations.map((m, i) => (
                                <div key={i} className="flex items-start gap-2 text-sm">
                                  <span className="text-green-400">✓</span>
                                  <span className="text-gray-300">{m}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </motion.div>
                ) : (
                  <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
                    <CardContent className="py-16 text-center">
                      <div className="text-5xl mb-4">⚔️</div>
                      <p className="text-lg text-gray-300 mb-2">No simulation results</p>
                      <p className="text-sm text-muted-foreground">Enter a target and run an attack chain simulation</p>
                    </CardContent>
                  </Card>
                )}
              </AnimatePresence>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Predictions;
