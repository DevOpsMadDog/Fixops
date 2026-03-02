/**
 * Algorithmic Lab — Mission Control Space [V3]
 *
 * Advanced risk quantification using Monte Carlo FAIR simulation
 * and Causal Inference analysis. Wired to real APIs.
 *
 * API: /api/v1/predictions/risk-trajectory, /api/v1/predictions/attack-chain
 * Pillar: V3 (Decision Intelligence)
 */

import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FlaskConical,
  Dices,
  GitBranch,
  Play,
  Loader2,
  TrendingUp,
  DollarSign,
  AlertTriangle,
  Sparkles,
  BarChart3,
} from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ═══════════════════════════════════════════════════════════════════════════
// Animation
// ═══════════════════════════════════════════════════════════════════════════

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.06 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 14, scale: 0.97 },
  show: { opacity: 1, y: 0, scale: 1, transition: { ease: [0.16, 1, 0.3, 1] as const, duration: 0.5 } },
};

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface MonteCarloResult {
  expected_loss?: number;
  p95?: number;
  p99?: number;
  median?: number;
  simulations?: number;
  confidence_interval?: [number, number];
  risk_distribution?: Record<string, number>;
  trajectories?: Array<{ cve_id: string; risk_score: number; trend: string }>;
  [key: string]: unknown;
}

interface CausalResult {
  root_causes?: Array<{ name: string; impact: string | number; confidence?: number }>;
  attack_chains?: Array<{ path: string[]; probability: number; impact: string }>;
  recommendations?: string[];
  [key: string]: unknown;
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

function formatCurrency(val: number | undefined): string {
  if (val == null) return 'N/A';
  if (val >= 1_000_000) return `$${(val / 1_000_000).toFixed(2)}M`;
  if (val >= 1_000) return `$${(val / 1_000).toFixed(1)}K`;
  return `$${val.toLocaleString()}`;
}

// ═══════════════════════════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════════════════════════

export default function AlgorithmicLab() {
  const [cveInput, setCveInput] = useState('CVE-2024-3094, CVE-2024-21762');
  const [monteCarloResult, setMonteCarloResult] = useState<MonteCarloResult | null>(null);
  const [causalResult, setCausalResult] = useState<CausalResult | null>(null);

  // Parse CVE IDs from input
  const getCveIds = () =>
    cveInput
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

  // ── Monte Carlo FAIR mutation ──────────────────────────────────────────
  const monteCarloMutation = useMutation({
    mutationFn: async (cveIds: string[]) => {
      const res = await api.post('/api/v1/predictions/risk-trajectory', {
        cve_ids: cveIds,
        simulations: 10_000,
      });
      return res.data as MonteCarloResult;
    },
    onSuccess: (data) => {
      setMonteCarloResult(data);
      toast.success('Monte Carlo FAIR simulation completed');
    },
    onError: (err: Error) => {
      toast.error(`Monte Carlo failed: ${err.message}`);
    },
  });

  // ── Causal Analysis mutation ───────────────────────────────────────────
  const causalMutation = useMutation({
    mutationFn: async (cveIds: string[]) => {
      const res = await api.post('/api/v1/predictions/attack-chain', {
        target: cveIds[0],
        finding_ids: cveIds,
      });
      return res.data as CausalResult;
    },
    onSuccess: (data) => {
      setCausalResult(data);
      toast.success('Causal inference analysis completed');
    },
    onError: (err: Error) => {
      toast.error(`Causal analysis failed: ${err.message}`);
    },
  });

  const isRunning = monteCarloMutation.isPending || causalMutation.isPending;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* ═══ Header ═══ */}
      <motion.div variants={itemVariants} className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 shadow-lg shadow-violet-500/20">
            <FlaskConical className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight bg-gradient-to-r from-violet-400 to-purple-400 bg-clip-text text-transparent">
              Algorithmic Lab
            </h1>
            <p className="text-sm text-muted-foreground">
              Advanced risk quantification with Monte Carlo FAIR and Causal Inference
            </p>
          </div>
        </div>
        <Badge variant="outline" className="border-violet-500/30 text-violet-400 bg-violet-500/10">
          <Sparkles className="w-3 h-3 mr-1" />
          V3 Decision Intelligence
        </Badge>
      </motion.div>

      {/* ═══ Input Section ═══ */}
      <motion.div variants={itemVariants}>
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-3">
            <CardTitle className="text-base font-semibold flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-violet-400" />
              Analysis Input
            </CardTitle>
            <CardDescription>Enter CVE IDs or finding identifiers to analyze</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-3">
              <Input
                value={cveInput}
                onChange={(e) => setCveInput(e.target.value)}
                placeholder="CVE-2024-1234, CVE-2024-5678"
                className="flex-1 bg-gray-800/40 border-gray-700/40 font-mono text-sm"
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !isRunning) {
                    monteCarloMutation.mutate(getCveIds());
                  }
                }}
              />
            </div>
            <div className="flex gap-3">
              <Button
                onClick={() => monteCarloMutation.mutate(getCveIds())}
                disabled={isRunning || !cveInput.trim()}
                className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white gap-2"
              >
                {monteCarloMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Dices className="w-4 h-4" />
                )}
                Run Monte Carlo FAIR
              </Button>
              <Button
                onClick={() => causalMutation.mutate(getCveIds())}
                disabled={isRunning || !cveInput.trim()}
                variant="outline"
                className="border-violet-500/30 text-violet-400 hover:bg-violet-500/10 gap-2"
              >
                {causalMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <GitBranch className="w-4 h-4" />
                )}
                Run Causal Analysis
              </Button>
              <Button
                onClick={() => {
                  monteCarloMutation.mutate(getCveIds());
                  causalMutation.mutate(getCveIds());
                }}
                disabled={isRunning || !cveInput.trim()}
                variant="outline"
                className="border-gray-700/40 text-gray-400 hover:text-gray-200 gap-2"
              >
                <Play className="w-4 h-4" />
                Run Both
              </Button>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ═══ Results Grid ═══ */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── Monte Carlo FAIR Results ── */}
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Dices className="w-4 h-4 text-blue-400" />
                Monte Carlo FAIR Simulation
              </CardTitle>
              <CardDescription>10,000 simulations for risk quantification</CardDescription>
            </CardHeader>
            <CardContent>
              {monteCarloMutation.isPending ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    {[1, 2, 3, 4].map((i) => (
                      <Skeleton key={i} className="h-20 rounded-lg" />
                    ))}
                  </div>
                  <Skeleton className="h-32 rounded-lg" />
                </div>
              ) : monteCarloResult ? (
                <div className="space-y-4">
                  {/* Key Metrics */}
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      {
                        label: 'Expected Loss',
                        value: formatCurrency(monteCarloResult.expected_loss),
                        icon: DollarSign,
                        color: 'text-red-400',
                        bg: 'bg-red-500/10 border-red-500/20',
                      },
                      {
                        label: '95th Percentile',
                        value: formatCurrency(monteCarloResult.p95),
                        icon: TrendingUp,
                        color: 'text-orange-400',
                        bg: 'bg-orange-500/10 border-orange-500/20',
                      },
                      {
                        label: '99th Percentile',
                        value: formatCurrency(monteCarloResult.p99),
                        icon: AlertTriangle,
                        color: 'text-yellow-400',
                        bg: 'bg-yellow-500/10 border-yellow-500/20',
                      },
                      {
                        label: 'Median Loss',
                        value: formatCurrency(monteCarloResult.median),
                        icon: BarChart3,
                        color: 'text-cyan-400',
                        bg: 'bg-cyan-500/10 border-cyan-500/20',
                      },
                    ].map(({ label, value, icon: Icon, color, bg }) => (
                      <div key={label} className={`p-3 rounded-lg border ${bg}`}>
                        <div className="flex items-center gap-1.5 mb-1">
                          <Icon className={`w-3.5 h-3.5 ${color}`} />
                          <span className="text-xs text-muted-foreground">{label}</span>
                        </div>
                        <span className={`text-lg font-bold ${color}`}>{value}</span>
                      </div>
                    ))}
                  </div>

                  {/* Trajectories */}
                  {monteCarloResult.trajectories && monteCarloResult.trajectories.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
                        Risk Trajectories
                      </h4>
                      {monteCarloResult.trajectories.map((t, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between p-2.5 rounded-lg border border-gray-700/20 bg-gray-800/20"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm text-blue-300">{t.cve_id}</span>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                t.trend === 'increasing'
                                  ? 'border-red-500/30 text-red-400'
                                  : t.trend === 'decreasing'
                                  ? 'border-green-500/30 text-green-400'
                                  : 'border-gray-600 text-gray-400'
                              }`}
                            >
                              {t.trend}
                            </Badge>
                          </div>
                          <span className="text-sm font-medium tabular-nums">
                            Score: {typeof t.risk_score === 'number' ? t.risk_score.toFixed(2) : t.risk_score}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Raw JSON (collapsed) */}
                  <details className="group">
                    <summary className="text-xs text-muted-foreground cursor-pointer hover:text-gray-300 transition-colors">
                      View raw JSON response
                    </summary>
                    <pre className="text-xs bg-gray-950/60 border border-gray-700/30 p-3 rounded-lg mt-2 overflow-auto max-h-48 text-gray-400">
                      {JSON.stringify(monteCarloResult, null, 2)}
                    </pre>
                  </details>
                </div>
              ) : (
                <div className="text-center py-12">
                  <Dices className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">
                    Run Monte Carlo FAIR to quantify financial risk exposure
                  </p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    Simulates 10,000 scenarios using FAIR methodology
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* ── Causal Inference Results ── */}
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-violet-400" />
                Causal Inference Analysis
              </CardTitle>
              <CardDescription>Root cause identification and attack chain analysis</CardDescription>
            </CardHeader>
            <CardContent>
              {causalMutation.isPending ? (
                <div className="space-y-3">
                  {[1, 2, 3].map((i) => (
                    <Skeleton key={i} className="h-16 rounded-lg" />
                  ))}
                </div>
              ) : causalResult ? (
                <div className="space-y-4">
                  {/* Root Causes */}
                  {causalResult.root_causes && causalResult.root_causes.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
                        Root Causes
                      </h4>
                      {causalResult.root_causes.map((cause, idx) => (
                        <motion.div
                          key={idx}
                          initial={{ opacity: 0, x: -8 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: idx * 0.05 }}
                          className="p-3 rounded-lg border border-violet-500/20 bg-violet-500/5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium text-gray-200">
                              {cause.name || String(cause)}
                            </span>
                            <Badge className="bg-violet-500/20 text-violet-400 border-violet-500/30 border text-xs">
                              Impact: {cause.impact || 'Unknown'}
                            </Badge>
                          </div>
                          {cause.confidence != null && (
                            <div className="flex items-center gap-2 mt-2">
                              <span className="text-xs text-muted-foreground">Confidence:</span>
                              <div className="flex-1 h-1.5 bg-gray-800/50 rounded-full overflow-hidden">
                                <motion.div
                                  initial={{ width: 0 }}
                                  animate={{ width: `${(cause.confidence as number) * 100}%` }}
                                  transition={{ delay: 0.3, duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
                                  className="h-full rounded-full bg-violet-500"
                                />
                              </div>
                              <span className="text-xs text-muted-foreground tabular-nums">
                                {((cause.confidence as number) * 100).toFixed(0)}%
                              </span>
                            </div>
                          )}
                        </motion.div>
                      ))}
                    </div>
                  )}

                  {/* Attack Chains */}
                  {causalResult.attack_chains && causalResult.attack_chains.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
                        Attack Chains
                      </h4>
                      {causalResult.attack_chains.map((chain, idx) => (
                        <div
                          key={idx}
                          className="p-3 rounded-lg border border-gray-700/20 bg-gray-800/20"
                        >
                          <div className="flex items-center gap-2 text-xs text-gray-400 font-mono mb-1.5">
                            {chain.path.map((step, si) => (
                              <span key={si} className="flex items-center gap-1">
                                <span className="text-gray-300">{step}</span>
                                {si < chain.path.length - 1 && <span className="text-gray-600">→</span>}
                              </span>
                            ))}
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-[10px] border-gray-600 text-gray-400">
                              P: {(chain.probability * 100).toFixed(0)}%
                            </Badge>
                            <Badge
                              variant="outline"
                              className={`text-[10px] ${
                                chain.impact === 'critical'
                                  ? 'border-red-500/30 text-red-400'
                                  : chain.impact === 'high'
                                  ? 'border-orange-500/30 text-orange-400'
                                  : 'border-gray-600 text-gray-400'
                              }`}
                            >
                              {chain.impact}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Recommendations */}
                  {causalResult.recommendations && causalResult.recommendations.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
                        Recommendations
                      </h4>
                      {causalResult.recommendations.map((rec, idx) => (
                        <div
                          key={idx}
                          className="flex items-start gap-2 p-2.5 rounded-lg border border-emerald-500/15 bg-emerald-500/5"
                        >
                          <Sparkles className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                          <span className="text-sm text-gray-300">{rec}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Raw JSON (collapsed) */}
                  <details className="group">
                    <summary className="text-xs text-muted-foreground cursor-pointer hover:text-gray-300 transition-colors">
                      View raw JSON response
                    </summary>
                    <pre className="text-xs bg-gray-950/60 border border-gray-700/30 p-3 rounded-lg mt-2 overflow-auto max-h-48 text-gray-400">
                      {JSON.stringify(causalResult, null, 2)}
                    </pre>
                  </details>
                </div>
              ) : (
                <div className="text-center py-12">
                  <GitBranch className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">
                    Run Causal Analysis to identify root causes
                  </p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    Maps attack chains and identifies causal relationships
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ═══ Methodology Info ═══ */}
      <AnimatePresence>
        {!monteCarloResult && !causalResult && (
          <motion.div
            variants={itemVariants}
            exit={{ opacity: 0, y: -10 }}
          >
            <Card className="border-gray-700/30 bg-gradient-to-r from-violet-900/10 to-blue-900/10 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <Dices className="w-4 h-4 text-blue-400" />
                      <h4 className="text-sm font-semibold text-gray-200">Monte Carlo FAIR</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Factor Analysis of Information Risk (FAIR) combined with Monte Carlo simulation
                      to quantify financial exposure. Runs 10,000 scenarios varying threat event frequency,
                      vulnerability, and loss magnitude distributions to produce probabilistic risk estimates.
                    </p>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <GitBranch className="w-4 h-4 text-violet-400" />
                      <h4 className="text-sm font-semibold text-gray-200">Causal Inference</h4>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      Identifies root causes behind vulnerability clusters using causal DAGs
                      (Directed Acyclic Graphs). Maps attack chains from initial access to impact,
                      computing conditional probabilities at each step to prioritize the most
                      likely and impactful paths.
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
