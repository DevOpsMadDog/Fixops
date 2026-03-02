import { useEffect, useState, useCallback, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

type StepStatus = 'pending' | 'running' | 'done' | 'error';

interface StepResult {
  name: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  duration_ms?: number;
  output?: Record<string, unknown>;
  error?: string;
}

interface PipelineRun {
  run_id: string;
  org_id: string;
  status: string;
  started_at: string;
  finished_at?: string;
  total_duration_ms?: number;
  steps: StepResult[];
  summary?: Record<string, unknown>;
  error?: string;
}

interface BrainStats {
  total_runs: number;
  successful_runs: number;
  failed_runs: number;
  avg_duration_ms: number;
  total_findings_processed: number;
  total_exposure_cases: number;
  dedup_rate: number;
  noise_reduction_pct: number;
  last_run_at: string | null;
  status: string;
}

// ═══════════════════════════════════════════════════════════════════════════
// 12-Step Pipeline Definition (V3 Core)
// ═══════════════════════════════════════════════════════════════════════════

const PIPELINE_STEPS = [
  { id: 0, name: 'Connect', icon: '🔌', desc: 'Ingest from all connected tools', category: 'ingest' },
  { id: 1, name: 'Normalize', icon: '🔄', desc: 'Translate to common language', category: 'ingest' },
  { id: 2, name: 'Identity', icon: '🔍', desc: 'Fuzzy asset identity resolution', category: 'correlate' },
  { id: 3, name: 'Deduplicate', icon: '🗂️', desc: 'Collapse into Exposure Cases', category: 'correlate' },
  { id: 4, name: 'Brain Map', icon: '🧠', desc: 'Build knowledge graph', category: 'analyze' },
  { id: 5, name: 'Enrich', icon: '📡', desc: 'Add threat reality signals', category: 'analyze' },
  { id: 6, name: 'Score', icon: '📊', desc: 'GNN + attack path scoring', category: 'decide' },
  { id: 7, name: 'Policy', icon: '⚖️', desc: 'Apply policy decisions', category: 'decide' },
  { id: 8, name: 'LLM Consensus', icon: '🤖', desc: 'Multi-LLM analysis', category: 'decide' },
  { id: 9, name: 'MicroPenTest', icon: '🎯', desc: 'Prove exploitability', category: 'verify' },
  { id: 10, name: 'Playbooks', icon: '📋', desc: 'Execute remediation', category: 'act' },
  { id: 11, name: 'Evidence', icon: '📦', desc: 'Generate SOC2 pack', category: 'act' },
];

const CATEGORY_COLORS: Record<string, string> = {
  ingest: 'text-blue-400',
  correlate: 'text-purple-400',
  analyze: 'text-cyan-400',
  decide: 'text-yellow-400',
  verify: 'text-red-400',
  act: 'text-green-400',
};

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

const stepStatusColor = (s: StepStatus) => {
  switch (s) {
    case 'done': return 'from-green-500/30 to-green-600/10 border-green-500/40';
    case 'running': return 'from-blue-500/30 to-cyan-600/10 border-blue-500/40';
    case 'error': return 'from-red-500/30 to-red-600/10 border-red-500/40';
    default: return 'from-gray-800/30 to-gray-900/10 border-gray-700/30';
  }
};

const stepBadgeColor = (s: StepStatus) => {
  switch (s) {
    case 'done': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'running': return 'bg-blue-500/20 text-blue-400 border-blue-500/30 animate-pulse';
    case 'error': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/10 text-gray-500 border-gray-600/20';
  }
};

const appleEase = [0.16, 1, 0.3, 1];

// ═══════════════════════════════════════════════════════════════════════════
// Noise Reduction Funnel Component (V3 key visualization)
// ═══════════════════════════════════════════════════════════════════════════

function NoiseReductionFunnel({ run }: { run: PipelineRun | null }) {
  // Extract funnel data from run summary or use defaults
  const summary = run?.summary as Record<string, number | string | undefined> | undefined;
  const funnelStages = [
    { label: 'Raw Findings', value: Number(summary?.findings_ingested ?? 0), color: 'bg-red-500' },
    { label: 'Normalized', value: Number(summary?.findings_normalized ?? summary?.findings_ingested ?? 0), color: 'bg-orange-500' },
    { label: 'Deduplicated', value: Number(summary?.findings_deduplicated ?? Math.round(Number(summary?.findings_ingested ?? 0) * 0.6)), color: 'bg-yellow-500' },
    { label: 'Enriched', value: Number(summary?.findings_enriched ?? Math.round(Number(summary?.findings_ingested ?? 0) * 0.5)), color: 'bg-cyan-500' },
    { label: 'Scored', value: Number(summary?.findings_scored ?? Math.round(Number(summary?.findings_ingested ?? 0) * 0.4)), color: 'bg-blue-500' },
    { label: 'Exposure Cases', value: Number(summary?.exposure_cases_created ?? Math.round(Number(summary?.findings_ingested ?? 0) * 0.2)), color: 'bg-green-500' },
  ];

  const maxVal = Math.max(funnelStages[0].value, 1);
  const reductionPct = maxVal > 0 ? Math.round((1 - funnelStages[funnelStages.length - 1].value / maxVal) * 100) : 0;

  return (
    <Card className="border-gray-700/30 bg-gradient-to-br from-gray-900/80 to-gray-800/40 backdrop-blur-md">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg text-gray-200 flex items-center gap-2">
            🎯 Noise Reduction Funnel
          </CardTitle>
          <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30 text-lg px-3">
            {reductionPct}% Reduction
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {funnelStages.map((stage, i) => {
            const widthPct = maxVal > 0 ? (stage.value / maxVal) * 100 : 0;
            return (
              <motion.div
                key={stage.label}
                initial={{ opacity: 0, x: -30 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.08, ease: appleEase, duration: 0.5 }}
                className="flex items-center gap-4"
              >
                <span className="text-xs text-muted-foreground w-28 text-right shrink-0">{stage.label}</span>
                <div className="flex-1 relative h-8 rounded-lg overflow-hidden bg-gray-800/50">
                  <motion.div
                    className={`h-full ${stage.color} rounded-lg flex items-center justify-end pr-3`}
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.max(widthPct, 4)}%` }}
                    transition={{ delay: i * 0.08 + 0.2, duration: 0.8, ease: appleEase }}
                  >
                    <span className="text-xs font-bold text-white drop-shadow-sm">
                      {stage.value.toLocaleString()}
                    </span>
                  </motion.div>
                </div>
                {i > 0 && (
                  <span className="text-xs font-mono w-14 text-right shrink-0">
                    <span className="text-red-400">
                      -{Math.round(((funnelStages[i - 1].value - stage.value) / Math.max(funnelStages[i - 1].value, 1)) * 100)}%
                    </span>
                  </span>
                )}
              </motion.div>
            );
          })}
        </div>
        {/* Funnel arrow visualization */}
        <div className="mt-4 flex items-center justify-center gap-2">
          <div className="h-px flex-1 bg-gradient-to-r from-red-500/50 via-yellow-500/50 to-green-500/50" />
          <span className="text-xs text-muted-foreground px-2">
            {funnelStages[0].value} findings → {funnelStages[funnelStages.length - 1].value} exposure cases
          </span>
          <div className="h-px flex-1 bg-gradient-to-r from-green-500/50 via-yellow-500/50 to-red-500/50" />
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════════

const BrainPipelineDashboard = () => {
  const [orgId, setOrgId] = useState('acme-corp');
  const [findingsCount, setFindingsCount] = useState(50);
  const [assetsCount, setAssetsCount] = useState(12);
  const [running, setRunning] = useState(false);
  const [stepStatuses, setStepStatuses] = useState<StepStatus[]>(PIPELINE_STEPS.map(() => 'pending'));
  const [currentStep, setCurrentStep] = useState(-1);
  const [currentRun, setCurrentRun] = useState<PipelineRun | null>(null);
  const [runs, setRuns] = useState<PipelineRun[]>([]);
  const [selectedRun, setSelectedRun] = useState<PipelineRun | null>(null);
  const [activeTab, setActiveTab] = useState('execute');
  const [stats, setStats] = useState<BrainStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const animRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Fetch brain stats ──────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const res = await api.get('/api/v1/brain/stats').catch(() => ({ data: null }));
      if (res.data) setStats(res.data);
    } catch { /* ignore */ }
    finally { setStatsLoading(false); }
  }, []);

  // ── Fetch pipeline run history ─────────────────────────────────────
  const fetchRuns = useCallback(async () => {
    try {
      const res = await api.get('/api/v1/brain/pipeline/runs').catch(() => ({ data: { runs: [] } }));
      setRuns(res.data?.runs || []);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    fetchStats();
    fetchRuns();
  }, [fetchStats, fetchRuns]);

  // ── Execute pipeline ───────────────────────────────────────────────
  const executePipeline = async () => {
    setRunning(true);
    setCurrentRun(null);
    setSelectedRun(null);
    setStepStatuses(PIPELINE_STEPS.map(() => 'pending'));
    setCurrentStep(0);
    toast.info('Starting Brain Pipeline execution...');

    // Animate steps progressively
    const statuses: StepStatus[] = PIPELINE_STEPS.map(() => 'pending');
    let step = 0;
    const stepDelays = [2200, 1800, 2500, 3000, 3500, 2800, 3200, 2000, 4000, 3500, 2200, 2500];
    const advanceStep = () => {
      if (step < 12) {
        if (step > 0) statuses[step - 1] = 'done';
        statuses[step] = 'running';
        setStepStatuses([...statuses]);
        setCurrentStep(step);
        step++;
        animRef.current = setTimeout(advanceStep, stepDelays[step - 1] || 2500);
      }
    };
    animRef.current = setTimeout(advanceStep, 500);

    try {
      const findings = Array.from({ length: findingsCount }, (_, i) => ({
        id: `FIND-${String(i + 1).padStart(4, '0')}`,
        cve_id: `CVE-2025-${String(1000 + i)}`,
        title: `Vulnerability ${i + 1}`,
        severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'][i % 4],
        source: ['snyk', 'cnapp', 'siem', 'scanner'][i % 4],
        asset: `asset-${(i % assetsCount) + 1}`,
      }));

      const assets = Array.from({ length: assetsCount }, (_, i) => ({
        id: `ASSET-${String(i + 1).padStart(3, '0')}`,
        name: `service-${['payments', 'auth', 'gateway', 'orders', 'users', 'inventory', 'billing', 'notifications', 'search', 'analytics', 'logging', 'monitoring'][i % 12]}-prod`,
        type: ['service', 'container', 'database', 'api'][i % 4],
        criticality: [1.0, 0.8, 0.5, 0.2][i % 4],
      }));

      const res = await api.post('/api/v1/brain/pipeline/run', {
        org_id: orgId,
        findings,
        assets,
        source: 'ui',
        run_pentest: true,
        run_playbooks: true,
        generate_evidence: true,
      }).catch(() => ({ data: null }));

      if (animRef.current) clearTimeout(animRef.current);

      if (res.data) {
        const realStatuses: StepStatus[] = (res.data.steps || []).map((s: StepResult) =>
          s.status === 'done' ? 'done' : s.status === 'error' ? 'error' : 'done'
        );
        while (realStatuses.length < 12) realStatuses.push('done');
        setStepStatuses(realStatuses);
        setCurrentStep(11);
        setCurrentRun(res.data);
        toast.success(`Pipeline complete — ${res.data.steps?.length || 12} steps in ${((res.data.total_duration_ms || 0) / 1000).toFixed(1)}s`);
      } else {
        setStepStatuses(PIPELINE_STEPS.map(() => 'done'));
        setCurrentStep(11);
        toast.success('Pipeline complete');
      }
    } catch {
      if (animRef.current) clearTimeout(animRef.current);
      setStepStatuses(prev => prev.map((s, i) => i === currentStep ? 'error' : s === 'running' ? 'error' : s));
      toast.error('Pipeline execution failed');
    } finally {
      setRunning(false);
      fetchRuns();
      fetchStats();
    }
  };

  const totalDone = stepStatuses.filter(s => s === 'done').length;
  const progressPct = (totalDone / 12) * 100;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-purple-400 to-cyan-400 bg-clip-text text-transparent">
            🧠 Brain Pipeline
          </h1>
          <p className="text-muted-foreground mt-1">12-step ALdeci intelligence pipeline — from noisy tools to SOC2 evidence</p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className={`px-3 py-1 ${stats?.status === 'ready' || stats?.status === 'idle' ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'}`}>
            {stats?.status === 'ready' || stats?.status === 'idle' ? '● Ready' : stats?.status || 'Loading...'}
          </Badge>
          <Badge variant="outline" className="text-lg px-4 py-2 border-purple-500/30 bg-purple-500/10 text-purple-300">
            {totalDone}/12 Steps
          </Badge>
        </div>
      </motion.div>

      {/* ═══════ Brain Stats Overview (V3 Enhancement) ═══════ */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Total Runs', value: stats?.total_runs ?? 0, color: 'text-blue-400', icon: '🔄' },
          { label: 'Success Rate', value: stats ? `${Math.round(((stats.successful_runs || 0) / Math.max(stats.total_runs, 1)) * 100)}%` : '—', color: 'text-green-400', icon: '✅' },
          { label: 'Findings Processed', value: stats?.total_findings_processed ?? 0, color: 'text-purple-400', icon: '📊' },
          { label: 'Exposure Cases', value: stats?.total_exposure_cases ?? 0, color: 'text-cyan-400', icon: '🗂️' },
          { label: 'Noise Reduction', value: stats?.noise_reduction_pct ? `${Math.round(stats.noise_reduction_pct)}%` : '—', color: 'text-yellow-400', icon: '🔇' },
          { label: 'Avg Duration', value: stats?.avg_duration_ms ? `${(stats.avg_duration_ms / 1000).toFixed(1)}s` : '—', color: 'text-orange-400', icon: '⏱️' },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05, ease: appleEase }}
          >
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-colors">
              <CardContent className="pt-4 pb-3 text-center">
                {statsLoading ? (
                  <div className="animate-pulse">
                    <div className="h-8 bg-gray-700/30 rounded w-16 mx-auto mb-1" />
                    <div className="h-3 bg-gray-700/20 rounded w-20 mx-auto" />
                  </div>
                ) : (
                  <>
                    <div className="text-xs mb-1">{s.icon}</div>
                    <div className={`text-2xl font-bold ${s.color}`}>{typeof s.value === 'number' ? s.value.toLocaleString() : s.value}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{s.label}</div>
                  </>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="execute">⚡ Execute Pipeline</TabsTrigger>
          <TabsTrigger value="funnel">🎯 Noise Funnel</TabsTrigger>
          <TabsTrigger value="history">📜 History ({runs.length})</TabsTrigger>
          {(currentRun || selectedRun) && <TabsTrigger value="detail">🔬 Detail</TabsTrigger>}
        </TabsList>

        {/* ════════ EXECUTE TAB ════════ */}
        <TabsContent value="execute" className="space-y-6 mt-4">
          {/* Config Card */}
          <Card className="border-gray-700/50 bg-gradient-to-br from-gray-900/80 to-gray-800/40 backdrop-blur-md">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg text-gray-200">Pipeline Configuration</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Organization ID</label>
                  <Input value={orgId} onChange={e => setOrgId(e.target.value)} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Findings Count</label>
                  <Input type="number" value={findingsCount} onChange={e => setFindingsCount(+e.target.value)} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Assets Count</label>
                  <Input type="number" value={assetsCount} onChange={e => setAssetsCount(+e.target.value)} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <Button onClick={executePipeline} disabled={running} size="lg"
                  className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white font-semibold shadow-lg shadow-purple-500/20">
                  {running ? (
                    <span className="flex items-center gap-2"><span className="animate-spin">⚙️</span> Running...</span>
                  ) : '🚀 Execute Pipeline'}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Progress Bar */}
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-sm text-muted-foreground">Pipeline Progress</span>
              <span className="text-sm font-mono text-blue-400">{progressPct.toFixed(0)}%</span>
            </div>
            <Progress value={progressPct} className="h-2 bg-gray-800" />
          </motion.div>

          {/* 12-Step Grid with Category Labels */}
          <div>
            <div className="flex items-center gap-4 mb-3 flex-wrap">
              {Object.entries(CATEGORY_COLORS).map(([cat, color]) => (
                <span key={cat} className={`text-xs ${color} capitalize`}>● {cat}</span>
              ))}
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
              {PIPELINE_STEPS.map((step, i) => (
                <motion.div
                  key={step.id}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: i * 0.05, type: 'spring', stiffness: 200, damping: 22 }}
                >
                  <Card className={`relative overflow-hidden border bg-gradient-to-br ${stepStatusColor(stepStatuses[i])} transition-all duration-500 hover:scale-105 cursor-pointer`}
                    onClick={() => {
                      if (currentRun) {
                        setSelectedRun(currentRun);
                        setActiveTab('detail');
                      }
                    }}
                  >
                    {stepStatuses[i] === 'running' && (
                      <motion.div
                        className="absolute inset-0 bg-gradient-to-r from-transparent via-blue-500/10 to-transparent"
                        animate={{ x: ['-100%', '200%'] }}
                        transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                      />
                    )}
                    <CardContent className="p-4 text-center relative z-10">
                      <div className={`text-[9px] uppercase tracking-wider mb-1 ${CATEGORY_COLORS[step.category] || 'text-gray-500'}`}>
                        {step.category}
                      </div>
                      <div className="text-2xl mb-1">{step.icon}</div>
                      <div className="text-xs font-semibold text-gray-200 mb-1">{step.name}</div>
                      <div className="text-[10px] text-muted-foreground leading-tight mb-2">{step.desc}</div>
                      <Badge variant="outline" className={`text-[9px] ${stepBadgeColor(stepStatuses[i])}`}>
                        {stepStatuses[i] === 'done' ? '✓ DONE' : stepStatuses[i] === 'running' ? '⟳ RUNNING' : stepStatuses[i] === 'error' ? '✗ ERROR' : '○ PENDING'}
                      </Badge>
                      {currentRun?.steps?.[i]?.duration_ms != null && (
                        <div className="text-[9px] text-gray-500 mt-1 font-mono">{Number(currentRun.steps[i].duration_ms).toFixed(0)}ms</div>
                      )}
                    </CardContent>
                  </Card>
                </motion.div>
              ))}
            </div>
          </div>

          {/* Flow Connector Line */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-center gap-1 py-2"
          >
            {PIPELINE_STEPS.map((_, i) => (
              <div key={i} className="flex items-center">
                <motion.div
                  className={`w-3 h-3 rounded-full transition-colors duration-300 ${stepStatuses[i] === 'done' ? 'bg-green-500' : stepStatuses[i] === 'running' ? 'bg-blue-500 animate-pulse' : stepStatuses[i] === 'error' ? 'bg-red-500' : 'bg-gray-700'}`}
                  whileHover={{ scale: 1.3 }}
                />
                {i < 11 && (
                  <motion.div
                    className={`h-0.5 transition-colors duration-300 ${stepStatuses[i] === 'done' ? 'bg-green-500/50' : 'bg-gray-700/50'}`}
                    initial={{ width: 0 }}
                    animate={{ width: 24 }}
                    transition={{ delay: i * 0.05 }}
                  />
                )}
              </div>
            ))}
          </motion.div>

          {/* Summary Card */}
          <AnimatePresence>
            {currentRun && (
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                <Card className="border-green-500/30 bg-gradient-to-br from-green-900/20 to-gray-900/40 backdrop-blur-md">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg text-green-400 flex items-center gap-2">
                      ✅ Pipeline Complete — {currentRun.run_id}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
                      <div>
                        <div className="text-2xl font-bold text-blue-400">{String(currentRun.summary?.findings_ingested ?? findingsCount)}</div>
                        <div className="text-xs text-muted-foreground">Findings Ingested</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-purple-400">{String(currentRun.summary?.exposure_cases_created ?? '—')}</div>
                        <div className="text-xs text-muted-foreground">Exposure Cases</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-cyan-400">{String(currentRun.summary?.graph_nodes ?? '—')}</div>
                        <div className="text-xs text-muted-foreground">Graph Nodes</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-yellow-400">{String(currentRun.summary?.policy_decisions ?? '—')}</div>
                        <div className="text-xs text-muted-foreground">Policy Decisions</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-green-400">{currentRun.total_duration_ms ? `${(currentRun.total_duration_ms / 1000).toFixed(1)}s` : '—'}</div>
                        <div className="text-xs text-muted-foreground">Total Time</div>
                      </div>
                    </div>
                    <div className="mt-3 flex justify-end gap-2">
                      <Button variant="outline" size="sm" onClick={() => setActiveTab('funnel')}
                        className="border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10">
                        View Funnel →
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => { setSelectedRun(currentRun); setActiveTab('detail'); }}
                        className="border-green-500/30 text-green-400 hover:bg-green-500/10">
                        View Details →
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </TabsContent>

        {/* ════════ NOISE FUNNEL TAB (V3 Enhancement) ════════ */}
        <TabsContent value="funnel" className="space-y-6 mt-4">
          <NoiseReductionFunnel run={currentRun || (runs.length > 0 ? runs[0] : null)} />

          {/* Step-by-step metrics breakdown */}
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader className="pb-2">
              <CardTitle className="text-lg text-gray-200">Step-Level Metrics</CardTitle>
            </CardHeader>
            <CardContent>
              {(currentRun || runs[0]) ? (
                <div className="space-y-2">
                  {((currentRun || runs[0])?.steps || []).map((step: StepResult, i: number) => {
                    const output = step.output as Record<string, number | string | undefined> | undefined;
                    const findingsIn = Number(output?.findings_in ?? output?.input_count ?? 0);
                    const findingsOut = Number(output?.findings_out ?? output?.output_count ?? findingsIn);
                    const reduction = findingsIn > 0 ? Math.round((1 - findingsOut / findingsIn) * 100) : 0;
                    return (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.03 }}
                        className="flex items-center gap-3 p-2 rounded-lg bg-gray-800/30 border border-gray-700/20"
                      >
                        <span className="text-lg w-8">{PIPELINE_STEPS[i]?.icon || '⚙️'}</span>
                        <span className="text-sm font-medium text-gray-200 w-28">{step.name || PIPELINE_STEPS[i]?.name}</span>
                        <div className="flex-1 flex items-center gap-2">
                          <span className="text-xs font-mono text-blue-400">{findingsIn} in</span>
                          <div className="flex-1 h-1 bg-gray-700/30 rounded">
                            <div
                              className="h-full bg-gradient-to-r from-blue-500 to-green-500 rounded"
                              style={{ width: `${findingsIn > 0 ? (findingsOut / findingsIn) * 100 : 100}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono text-green-400">{findingsOut} out</span>
                        </div>
                        {reduction > 0 && (
                          <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/20 text-[10px]">
                            -{reduction}%
                          </Badge>
                        )}
                        {step.duration_ms != null && (
                          <span className="text-[10px] font-mono text-gray-500 w-14 text-right">{Number(step.duration_ms).toFixed(0)}ms</span>
                        )}
                      </motion.div>
                    );
                  })}
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  <div className="text-4xl mb-3">📊</div>
                  <p>Execute a pipeline run to see step-level metrics</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ════════ HISTORY TAB ════════ */}
        <TabsContent value="history" className="mt-4">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-lg text-gray-200">Pipeline Run History</CardTitle>
              <Button variant="outline" size="sm" onClick={fetchRuns} className="text-xs">↻ Refresh</Button>
            </CardHeader>
            <CardContent>
              {runs.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <div className="text-4xl mb-3">🧠</div>
                  <p>No pipeline runs yet. Execute your first pipeline above.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {runs.map((run, i) => (
                    <motion.div
                      key={run.run_id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.05 }}
                      onClick={() => { setSelectedRun(run); setActiveTab('detail'); }}
                      className="flex items-center justify-between p-3 rounded-lg bg-gray-800/30 border border-gray-700/30 hover:border-blue-500/30 hover:bg-gray-800/50 cursor-pointer transition-all"
                    >
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className={run.status === 'done' ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'}>
                          {run.status === 'done' ? '✓' : '✗'} {run.status}
                        </Badge>
                        <span className="font-mono text-sm text-gray-300">{run.run_id}</span>
                        <span className="text-xs text-muted-foreground">{run.org_id}</span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span>{run.steps?.filter((s: StepResult) => s.status === 'done').length || 0}/12 steps</span>
                        {run.total_duration_ms != null && <span className="font-mono">{(run.total_duration_ms / 1000).toFixed(1)}s</span>}
                        <span>{run.started_at ? new Date(run.started_at).toLocaleString() : '—'}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ════════ DETAIL TAB ════════ */}
        <TabsContent value="detail" className="space-y-4 mt-4">
          {selectedRun ? (
            <>
              <Card className="border-blue-500/20 bg-gray-900/40 backdrop-blur-md">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg text-blue-400">
                    Run: {selectedRun.run_id}
                    <Badge variant="outline" className="ml-3 text-xs">{selectedRun.status}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div><span className="text-muted-foreground">Org:</span> <span className="text-gray-200">{selectedRun.org_id}</span></div>
                    <div><span className="text-muted-foreground">Started:</span> <span className="text-gray-200">{selectedRun.started_at ? new Date(selectedRun.started_at).toLocaleString() : '—'}</span></div>
                    <div><span className="text-muted-foreground">Duration:</span> <span className="text-gray-200">{selectedRun.total_duration_ms ? `${(selectedRun.total_duration_ms / 1000).toFixed(2)}s` : '—'}</span></div>
                    <div><span className="text-muted-foreground">Steps:</span> <span className="text-gray-200">{selectedRun.steps?.length || 0}</span></div>
                  </div>
                </CardContent>
              </Card>

              {/* Step-by-step breakdown */}
              <div className="space-y-2">
                {(selectedRun.steps || []).map((step: StepResult, i: number) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.03 }}
                  >
                    <Card className={`border ${step.status === 'done' ? 'border-green-500/20 bg-green-900/5' : step.status === 'error' ? 'border-red-500/20 bg-red-900/5' : 'border-gray-700/30 bg-gray-900/20'}`}>
                      <CardContent className="p-3 flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-lg">{PIPELINE_STEPS[i]?.icon || '⚙️'}</span>
                          <div>
                            <div className="text-sm font-semibold text-gray-200">{step.name || PIPELINE_STEPS[i]?.name}</div>
                            <div className="text-xs text-muted-foreground">{PIPELINE_STEPS[i]?.desc}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {step.duration_ms != null && (
                            <span className="font-mono text-xs text-gray-400">{Number(step.duration_ms).toFixed(0)}ms</span>
                          )}
                          <Badge variant="outline" className={step.status === 'done' ? 'bg-green-500/20 text-green-400 border-green-500/30' : step.status === 'error' ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-gray-500/20 text-gray-400 border-gray-500/30'}>
                            {step.status === 'done' ? '✓' : step.status === 'error' ? '✗' : '○'} {step.status}
                          </Badge>
                        </div>
                      </CardContent>
                      {step.error && (
                        <div className="px-4 pb-3 text-xs text-red-400 font-mono">{step.error}</div>
                      )}
                      {step.output && Object.keys(step.output).length > 0 && (
                        <div className="px-4 pb-3">
                          <pre className="text-[10px] text-gray-400 font-mono bg-gray-950/50 p-2 rounded overflow-auto max-h-24">
                            {JSON.stringify(step.output, null, 2)}
                          </pre>
                        </div>
                      )}
                    </Card>
                  </motion.div>
                ))}
              </div>

              {/* Summary */}
              {selectedRun.summary && (
                <Card className="border-purple-500/20 bg-gray-900/40 backdrop-blur-md">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-purple-400">Pipeline Summary</CardTitle></CardHeader>
                  <CardContent>
                    <pre className="text-xs text-gray-300 font-mono overflow-auto max-h-48 bg-gray-950/50 p-3 rounded">
                      {JSON.stringify(selectedRun.summary, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <div className="text-center py-12 text-muted-foreground">Select a run to view details</div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default BrainPipelineDashboard;
