/**
 * Self-Learning Feedback Loop Demo — AI Engine Space [V8]
 *
 * DEMO-012: Interactive demo showing all 5 feedback loops:
 * 1. Decision Outcome Loop  — AI decisions improve over time
 * 2. MPTE Result Loop       — Exploitability predictions sharpen
 * 3. False Positive Loop    — Noisy scanners/rules auto-suppressed
 * 4. Remediation Success    — Fix recommendations improve
 * 5. Policy Violation Loop  — Over-strict policies auto-relaxed
 *
 * Flow: Reset → Baseline Score → Submit Feedback → Learn → Re-Score → Show Delta
 *
 * API: /api/v1/self-learning/* (all endpoints verified 200)
 * Pillar: V8 (Self-Learning Intelligence)
 */

import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import {
  Brain,
  RefreshCw,
  Play,
  Zap,
  Target,
  ShieldAlert,
  TrendingUp,
  TrendingDown,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Loader2,
  BarChart3,
  Lightbulb,
  Scale,
  Bug,
  Wrench,
  FileWarning,
  ChevronRight,
  Activity,
  Gauge,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { Progress } from '../../components/ui/progress';
import { Skeleton } from '../../components/ui/skeleton';
import { selfLearningApi } from '../../lib/api';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface DemoStep {
  id: number;
  title: string;
  description: string;
  status: 'pending' | 'running' | 'done' | 'error';
  result?: Record<string, unknown>;
}

interface ScoreResult {
  baseline_score: number;
  adjusted_score: number;
  delta: number;
  delta_percent: number;
  adjustments_applied: number;
  adjustments: Array<{
    source: string;
    factor: string;
    weight: number;
    effect: string;
  }>;
  learning_active: boolean;
}

interface Adjustment {
  id: string;
  loop: string;
  target: string;
  metric: string;
  old_value: number;
  new_value: number;
  delta: number;
  sample_count: number;
  confidence: number;
  reasoning: string;
  applied: boolean;
}

interface Insight {
  loop: string;
  severity: string;
  insight: string;
  action?: string;
  target?: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// Animation
// ═══════════════════════════════════════════════════════════════════════════

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { ease: [0.16, 1, 0.3, 1], duration: 0.4 } },
};

// ═══════════════════════════════════════════════════════════════════════════
// Loop metadata
// ═══════════════════════════════════════════════════════════════════════════

const LOOP_META = [
  {
    id: 'decision_outcome',
    name: 'Decision Outcome',
    icon: Scale,
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    description: 'Tracks if AI triage decisions were correct, adjusts scanner confidence weights',
  },
  {
    id: 'mpte_result',
    name: 'MPTE Result',
    icon: Bug,
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    description: 'Tracks if exploitability predictions matched reality, refines MPTE thresholds',
  },
  {
    id: 'false_positive',
    name: 'False Positive',
    icon: XCircle,
    color: 'text-amber-400',
    bgColor: 'bg-amber-500/10',
    description: 'Tracks FP rates per scanner/rule, auto-suppresses noisy rules',
  },
  {
    id: 'remediation_success',
    name: 'Remediation Success',
    icon: Wrench,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-500/10',
    description: 'Tracks if fixes actually resolved vulnerabilities, optimizes fix recommendations',
  },
  {
    id: 'policy_violation',
    name: 'Policy Violation',
    icon: FileWarning,
    color: 'text-purple-400',
    bgColor: 'bg-purple-500/10',
    description: 'Tracks justified violations, auto-relaxes over-strict policies',
  },
];

// ═══════════════════════════════════════════════════════════════════════════
// Score Gauge Component
// ═══════════════════════════════════════════════════════════════════════════

function ScoreGauge({ label, score, color }: { label: string; score: number; color: string }) {
  const pct = Math.round(score * 100);
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="42" fill="none" stroke="hsl(217.2 32.6% 17.5%)" strokeWidth="8" />
          <circle
            cx="50" cy="50" r="42" fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${pct * 2.64} ${264 - pct * 2.64}`}
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-2xl font-bold tabular-nums">{pct}%</span>
        </div>
      </div>
      <span className="text-xs text-gray-400 font-medium">{label}</span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════════

export default function SelfLearningDemo() {
  const queryClient = useQueryClient();

  // Demo state
  const [demoRunning, setDemoRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [baselineScore, setBaselineScore] = useState<ScoreResult | null>(null);
  const [adjustedScore, setAdjustedScore] = useState<ScoreResult | null>(null);
  const [adjustments, setAdjustments] = useState<Adjustment[]>([]);
  const [seedResult, setSeedResult] = useState<Record<string, unknown> | null>(null);
  const [analysisResult, setAnalysisResult] = useState<Record<string, unknown> | null>(null);
  const [insightsList, setInsightsList] = useState<Insight[]>([]);
  const [demoComplete, setDemoComplete] = useState(false);

  // Queries
  const statusQuery = useQuery({
    queryKey: ['self-learning-status'],
    queryFn: selfLearningApi.status,
    refetchInterval: demoRunning ? 2000 : 30000,
  });

  const weightsQuery = useQuery({
    queryKey: ['self-learning-weights'],
    queryFn: selfLearningApi.getWeights,
    enabled: demoComplete,
  });

  // Sample finding for demo
  const sampleFinding = {
    cvss_score: 7.5,
    epss_score: 0.35,
    in_kev: false,
    asset_criticality: 0.7,
    scanner: 'zap',
    rule_id: '10016-xss',
    fix_type: 'CODE_PATCH',
  };

  // Step-by-step demo runner
  const runDemo = useCallback(async () => {
    setDemoRunning(true);
    setDemoComplete(false);
    setCurrentStep(0);
    setBaselineScore(null);
    setAdjustedScore(null);
    setAdjustments([]);
    setSeedResult(null);
    setAnalysisResult(null);
    setInsightsList([]);

    try {
      // Step 1: Reset
      setCurrentStep(1);
      toast.info('Step 1/7: Resetting learning data...');
      await selfLearningApi.resetDemo();
      await new Promise(r => setTimeout(r, 500));

      // Step 2: Baseline score
      setCurrentStep(2);
      toast.info('Step 2/7: Computing baseline score (no learning)...');
      const baseline = await selfLearningApi.scoreWithLearning(sampleFinding);
      setBaselineScore(baseline);
      await new Promise(r => setTimeout(r, 700));

      // Step 3: Seed feedback data
      setCurrentStep(3);
      toast.info('Step 3/7: Submitting 98 feedback records across 5 loops...');
      const seed = await selfLearningApi.seedDemo();
      setSeedResult(seed);
      await new Promise(r => setTimeout(r, 700));

      // Step 4: Analyze
      setCurrentStep(4);
      toast.info('Step 4/7: Analyzing all 5 feedback loops...');
      const analysis = await selfLearningApi.analyze();
      setAnalysisResult(analysis);
      await new Promise(r => setTimeout(r, 500));

      // Step 5: Compute adjustments (learning step)
      setCurrentStep(5);
      toast.info('Step 5/7: Computing weight adjustments (the brain learns)...');
      const adjResult = await selfLearningApi.computeAdjustments();
      setAdjustments(adjResult.adjustments || []);
      await new Promise(r => setTimeout(r, 700));

      // Step 6: Re-score with learning
      setCurrentStep(6);
      toast.info('Step 6/7: Re-scoring with learned weights...');
      const adjusted = await selfLearningApi.scoreWithLearning(sampleFinding);
      setAdjustedScore(adjusted);
      await new Promise(r => setTimeout(r, 500));

      // Step 7: Get insights
      setCurrentStep(7);
      toast.info('Step 7/7: Generating learning insights...');
      const insights = await selfLearningApi.insights();
      setInsightsList(insights.insights || []);

      // Refresh queries
      queryClient.invalidateQueries({ queryKey: ['self-learning-status'] });
      queryClient.invalidateQueries({ queryKey: ['self-learning-weights'] });

      setDemoComplete(true);
      toast.success('Demo complete! The system learned from 98 feedback records.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      toast.error(`Demo failed at step ${currentStep}: ${msg}`);
    } finally {
      setDemoRunning(false);
    }
  }, [queryClient]);

  // Quick feedback submission (individual loops)
  const submitFeedbackMutation = useMutation({
    mutationFn: async (loop: string) => {
      switch (loop) {
        case 'decision':
          return selfLearningApi.feedbackDecision({
            decision_id: `DEC-LIVE-${Date.now()}`,
            finding_id: `VULN-LIVE-${Date.now()}`,
            predicted_action: 'FIX',
            actual_outcome: 'FIX',
            confidence: 0.9,
            context: { scanner: 'semgrep', live_demo: true },
          });
        case 'mpte':
          return selfLearningApi.feedbackMpte({
            finding_id: `MPTE-LIVE-${Date.now()}`,
            predicted_exploitable: true,
            actual_exploitable: true,
            mpte_confidence: 0.85,
            context: { scanner: 'zap', live_demo: true },
          });
        case 'fp':
          return selfLearningApi.feedbackFalsePositive({
            finding_id: `FP-LIVE-${Date.now()}`,
            scanner: 'bandit',
            rule_id: 'B101-assert',
            is_false_positive: true,
            context: { live_demo: true },
          });
        case 'remediation':
          return selfLearningApi.feedbackRemediation({
            finding_id: `REM-LIVE-${Date.now()}`,
            fix_type: 'CODE_PATCH',
            fix_applied: 'Applied parameterized query fix',
            resolved: true,
            time_to_fix_hours: 2.5,
            context: { live_demo: true },
          });
        case 'policy':
          return selfLearningApi.feedbackPolicy({
            policy_id: 'POL-MEDIUM-90D',
            rule_id: 'rule-live',
            violated: true,
            was_justified: true,
            context: { live_demo: true },
          });
        default:
          throw new Error(`Unknown loop: ${loop}`);
      }
    },
    onSuccess: (data, loop) => {
      toast.success(`Feedback recorded for ${loop} loop`);
      queryClient.invalidateQueries({ queryKey: ['self-learning-status'] });
    },
    onError: (err: Error) => {
      toast.error(`Feedback failed: ${err.message}`);
    },
  });

  const delta = baselineScore && adjustedScore
    ? adjustedScore.adjusted_score - baselineScore.baseline_score
    : 0;
  const deltaPct = baselineScore && baselineScore.baseline_score > 0
    ? (delta / baselineScore.baseline_score) * 100
    : 0;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6 p-6"
    >
      {/* Header */}
      <motion.div variants={itemVariants} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight flex items-center gap-3">
            <Brain className="w-8 h-8 text-violet-400" />
            Self-Learning Feedback Loop
          </h1>
          <p className="text-gray-400 mt-1">
            Watch the system learn from 5 feedback loops and adjust risk scoring in real-time
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge
            variant="outline"
            className={statusQuery.data?.status === 'operational'
              ? 'border-emerald-500/30 text-emerald-400'
              : 'border-amber-500/30 text-amber-400'}
          >
            <Activity className="w-3 h-3 mr-1" />
            {statusQuery.data?.status || 'loading'}
          </Badge>
          <Badge variant="outline" className="border-violet-500/30 text-violet-400">
            {statusQuery.data?.total_feedback || 0} feedback records
          </Badge>
          <Button
            onClick={runDemo}
            disabled={demoRunning}
            className="bg-violet-600 hover:bg-violet-700 text-white"
          >
            {demoRunning ? (
              <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Running Demo...</>
            ) : (
              <><Play className="w-4 h-4 mr-2" /> Run Full Demo</>
            )}
          </Button>
        </div>
      </motion.div>

      {/* Progress Bar (during demo) */}
      {demoRunning && (
        <motion.div variants={itemVariants}>
          <Card className="border-violet-500/20 bg-violet-500/5">
            <CardContent className="pt-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-violet-300">
                  Demo Progress: Step {currentStep} of 7
                </span>
                <span className="text-sm text-gray-400">
                  {['', 'Resetting...', 'Baseline scoring...', 'Seeding feedback...', 'Analyzing loops...', 'Computing adjustments...', 'Re-scoring...', 'Generating insights...'][currentStep]}
                </span>
              </div>
              <Progress value={(currentStep / 7) * 100} className="h-2" />
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* 5 Feedback Loop Cards */}
      <motion.div variants={itemVariants}>
        <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
          <Zap className="w-5 h-5 text-amber-400" />
          5 Feedback Loops
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {LOOP_META.map((loop) => {
            const Icon = loop.icon;
            const loopKey = loop.id === 'false_positive' ? 'fp'
              : loop.id === 'decision_outcome' ? 'decision'
              : loop.id === 'mpte_result' ? 'mpte'
              : loop.id === 'remediation_success' ? 'remediation'
              : 'policy';

            return (
              <Card key={loop.id} className={`${loop.bgColor} border-gray-700/30`}>
                <CardContent className="pt-5 pb-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <Icon className={`w-5 h-5 ${loop.color}`} />
                    <span className="text-sm font-semibold">{loop.name}</span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">{loop.description}</p>
                  <Button
                    size="sm"
                    variant="outline"
                    className="w-full text-xs"
                    disabled={submitFeedbackMutation.isPending}
                    onClick={() => submitFeedbackMutation.mutate(loopKey)}
                  >
                    {submitFeedbackMutation.isPending ? (
                      <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                    ) : (
                      <ChevronRight className="w-3 h-3 mr-1" />
                    )}
                    Submit Feedback
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </motion.div>

      {/* Score Comparison */}
      {(baselineScore || adjustedScore) && (
        <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Baseline */}
          <Card className="border-gray-700/30">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Target className="w-4 h-4 text-gray-400" />
                Baseline Score
              </CardTitle>
              <CardDescription>Before learning (raw formula)</CardDescription>
            </CardHeader>
            <CardContent>
              {baselineScore ? (
                <div className="flex flex-col items-center">
                  <ScoreGauge
                    label="Risk Score"
                    score={baselineScore.baseline_score}
                    color="hsl(217 91% 60%)"
                  />
                  <div className="mt-2 text-xs text-gray-500">
                    {baselineScore.adjustments_applied} adjustments
                  </div>
                </div>
              ) : (
                <Skeleton className="h-32 w-full" />
              )}
            </CardContent>
          </Card>

          {/* Arrow + Delta */}
          <Card className={`border-gray-700/30 flex items-center justify-center ${
            demoComplete ? (delta < 0 ? 'bg-emerald-500/5 border-emerald-500/20' : delta > 0 ? 'bg-red-500/5 border-red-500/20' : '') : ''
          }`}>
            <CardContent className="text-center py-6">
              {demoComplete ? (
                <>
                  <div className="flex items-center justify-center gap-3 mb-3">
                    <ArrowRight className={`w-8 h-8 ${delta < 0 ? 'text-emerald-400' : delta > 0 ? 'text-red-400' : 'text-gray-400'}`} />
                  </div>
                  <div className={`text-3xl font-bold tabular-nums ${
                    delta < 0 ? 'text-emerald-400' : delta > 0 ? 'text-red-400' : 'text-gray-400'
                  }`}>
                    {deltaPct > 0 ? '+' : ''}{deltaPct.toFixed(1)}%
                  </div>
                  <div className="text-sm text-gray-400 mt-1">
                    {delta < 0 ? 'Risk Reduced' : delta > 0 ? 'Risk Increased' : 'No Change'}
                  </div>
                  <div className="text-xs text-gray-500 mt-2">
                    {adjustments.length} weight adjustments applied
                  </div>
                </>
              ) : (
                <div className="text-gray-500 text-sm">
                  {demoRunning ? (
                    <Loader2 className="w-6 h-6 animate-spin mx-auto" />
                  ) : (
                    'Run demo to see learning effect'
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Adjusted */}
          <Card className="border-gray-700/30">
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Brain className="w-4 h-4 text-violet-400" />
                Adjusted Score
              </CardTitle>
              <CardDescription>After learning from feedback</CardDescription>
            </CardHeader>
            <CardContent>
              {adjustedScore ? (
                <div className="flex flex-col items-center">
                  <ScoreGauge
                    label="Risk Score"
                    score={adjustedScore.adjusted_score}
                    color={delta < 0 ? 'hsl(142 71% 45%)' : delta > 0 ? 'hsl(0 84% 60%)' : 'hsl(217 91% 60%)'}
                  />
                  <div className="mt-2 text-xs text-gray-500">
                    {adjustedScore.adjustments_applied} adjustments
                  </div>
                </div>
              ) : (
                <Skeleton className="h-32 w-full" />
              )}
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Adjustments Detail */}
      {adjustments.length > 0 && (
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-blue-400" />
                Weight Adjustments ({adjustments.length})
              </CardTitle>
              <CardDescription>
                How the brain adjusted internal weights based on feedback analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {adjustments.map((adj) => {
                  const loopMeta = LOOP_META.find(l => l.id === adj.loop);
                  const LoopIcon = loopMeta?.icon || Activity;
                  return (
                    <div
                      key={adj.id}
                      className="flex items-center gap-3 p-3 rounded-lg bg-gray-800/30 border border-gray-700/20"
                    >
                      <LoopIcon className={`w-4 h-4 ${loopMeta?.color || 'text-gray-400'} shrink-0`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium truncate">{adj.target}</span>
                          <Badge variant="outline" className="text-xs shrink-0">
                            {adj.loop}
                          </Badge>
                        </div>
                        <p className="text-xs text-gray-400 mt-0.5">{adj.reasoning}</p>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="flex items-center gap-1 text-sm tabular-nums">
                          <span className="text-gray-400">{adj.old_value.toFixed(4)}</span>
                          <ArrowRight className="w-3 h-3 text-gray-500" />
                          <span className={adj.delta < 0 ? 'text-emerald-400' : adj.delta > 0 ? 'text-red-400' : 'text-gray-300'}>
                            {adj.new_value.toFixed(4)}
                          </span>
                        </div>
                        <div className="text-xs text-gray-500">
                          {adj.sample_count} samples, {(adj.confidence * 100).toFixed(0)}% conf
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Analysis Results */}
      {analysisResult && (
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Gauge className="w-4 h-4 text-cyan-400" />
                Loop Analysis
              </CardTitle>
              <CardDescription>Performance metrics for each feedback loop</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
                {/* Decision Accuracy */}
                <div className="text-center p-3 rounded-lg bg-blue-500/5 border border-blue-500/10">
                  <Scale className="w-5 h-5 text-blue-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-blue-300 tabular-nums">
                    {(analysisResult as Record<string, Record<string, number>>).decision_outcomes?.accuracy ?? 0}%
                  </div>
                  <div className="text-xs text-gray-400 mt-1">Decision Accuracy</div>
                </div>
                {/* MPTE F1 */}
                <div className="text-center p-3 rounded-lg bg-red-500/5 border border-red-500/10">
                  <Bug className="w-5 h-5 text-red-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-red-300 tabular-nums">
                    {(analysisResult as Record<string, Record<string, number>>).mpte_results?.f1_score ?? 0}%
                  </div>
                  <div className="text-xs text-gray-400 mt-1">MPTE F1 Score</div>
                </div>
                {/* FP Rate */}
                <div className="text-center p-3 rounded-lg bg-amber-500/5 border border-amber-500/10">
                  <XCircle className="w-5 h-5 text-amber-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-amber-300 tabular-nums">
                    {(analysisResult as Record<string, Record<string, number>>).false_positives?.overall_fp_rate ?? 0}%
                  </div>
                  <div className="text-xs text-gray-400 mt-1">FP Rate</div>
                </div>
                {/* Remediation */}
                <div className="text-center p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/10">
                  <Wrench className="w-5 h-5 text-emerald-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-emerald-300 tabular-nums">
                    {(analysisResult as Record<string, Record<string, number>>).remediation_success?.success_rate ?? 0}%
                  </div>
                  <div className="text-xs text-gray-400 mt-1">Remediation Success</div>
                </div>
                {/* Policy */}
                <div className="text-center p-3 rounded-lg bg-purple-500/5 border border-purple-500/10">
                  <FileWarning className="w-5 h-5 text-purple-400 mx-auto mb-2" />
                  <div className="text-2xl font-bold text-purple-300 tabular-nums">
                    {(analysisResult as Record<string, Record<string, number>>).policy_violations?.justified_rate ?? 0}%
                  </div>
                  <div className="text-xs text-gray-400 mt-1">Justified Violations</div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Insights */}
      {insightsList.length > 0 && (
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Lightbulb className="w-4 h-4 text-amber-400" />
                Learning Insights ({insightsList.length})
              </CardTitle>
              <CardDescription>
                Actionable recommendations from the self-learning engine
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {insightsList.map((insight, i) => (
                  <div
                    key={i}
                    className={`flex items-start gap-3 p-3 rounded-lg border ${
                      insight.severity === 'high'
                        ? 'bg-red-500/5 border-red-500/20'
                        : insight.severity === 'medium'
                        ? 'bg-amber-500/5 border-amber-500/20'
                        : 'bg-emerald-500/5 border-emerald-500/20'
                    }`}
                  >
                    {insight.severity === 'high' ? (
                      <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    ) : insight.severity === 'medium' ? (
                      <TrendingUp className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={
                            insight.severity === 'high' ? 'border-red-500/30 text-red-400 text-xs' :
                            insight.severity === 'medium' ? 'border-amber-500/30 text-amber-400 text-xs' :
                            'border-emerald-500/30 text-emerald-400 text-xs'
                          }
                        >
                          {insight.severity.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          {insight.loop}
                        </Badge>
                      </div>
                      <p className="text-sm text-gray-300 mt-1">{insight.insight}</p>
                      {insight.action && (
                        <p className="text-xs text-gray-500 mt-1">
                          Recommended: <span className="text-gray-400">{insight.action}</span>
                          {insight.target && <> on <span className="text-gray-400">{insight.target}</span></>}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Learned Weights */}
      {weightsQuery.data?.weights && Object.keys(weightsQuery.data.weights).length > 0 && (
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Scale className="w-4 h-4 text-indigo-400" />
                Learned Weights ({weightsQuery.data.count})
              </CardTitle>
              <CardDescription>
                Internal weights modified by self-learning. Values &lt; 1.0 reduce scores, &gt; 1.0 increase.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {Object.entries(weightsQuery.data.weights as Record<string, { value: number; update_count: number }>).map(([key, data]) => (
                  <div
                    key={key}
                    className="flex items-center justify-between p-2 rounded bg-gray-800/30 border border-gray-700/20"
                  >
                    <span className="text-xs font-mono text-gray-400 truncate mr-2">{key}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className={`text-sm font-bold tabular-nums ${
                        data.value < 0.8 ? 'text-emerald-400' :
                        data.value > 1.2 ? 'text-red-400' : 'text-gray-300'
                      }`}>
                        {data.value.toFixed(4)}
                      </span>
                      <span className="text-xs text-gray-600">
                        ({data.update_count}x)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Sample Finding Details (always visible) */}
      <motion.div variants={itemVariants}>
        <Card className="border-gray-700/30 bg-gray-900/30">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Target className="w-4 h-4 text-gray-400" />
              Sample Finding (Used for Scoring)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-gray-500 text-xs">CVSS</span>
                <div className="font-bold text-orange-400">{sampleFinding.cvss_score}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">EPSS</span>
                <div className="font-bold text-blue-400">{sampleFinding.epss_score}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">Scanner</span>
                <div className="font-bold">{sampleFinding.scanner}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">Rule</span>
                <div className="font-bold font-mono text-xs">{sampleFinding.rule_id}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">In KEV</span>
                <div className="font-bold">{sampleFinding.in_kev ? 'Yes' : 'No'}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">Asset Criticality</span>
                <div className="font-bold">{sampleFinding.asset_criticality}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">Fix Type</span>
                <div className="font-bold">{sampleFinding.fix_type}</div>
              </div>
              <div>
                <span className="text-gray-500 text-xs">Formula</span>
                <div className="font-mono text-xs text-gray-400">
                  min((cvss/10*0.4 + epss*0.3 + 0.3) * kev * asset, 1.0)
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
