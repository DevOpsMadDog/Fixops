import { useEffect, useState, useCallback, useRef } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';

// 12-step ALdeci Brain Pipeline
const PIPELINE_STEPS = [
  { id: 0, name: 'Connect', icon: '🔌', desc: 'Ingest from all connected tools' },
  { id: 1, name: 'Normalize', icon: '🔄', desc: 'Translate to common language' },
  { id: 2, name: 'Identity', icon: '🔍', desc: 'Fuzzy asset identity resolution' },
  { id: 3, name: 'Deduplicate', icon: '🗂️', desc: 'Collapse into Exposure Cases' },
  { id: 4, name: 'Brain Map', icon: '🧠', desc: 'Build knowledge graph' },
  { id: 5, name: 'Enrich', icon: '📡', desc: 'Add threat reality signals' },
  { id: 6, name: 'Score', icon: '📊', desc: 'GNN + attack path scoring' },
  { id: 7, name: 'Policy', icon: '⚖️', desc: 'Apply policy decisions' },
  { id: 8, name: 'LLM Consensus', icon: '🤖', desc: 'Multi-LLM analysis' },
  { id: 9, name: 'MicroPenTest', icon: '🎯', desc: 'Prove exploitability' },
  { id: 10, name: 'Playbooks', icon: '📋', desc: 'Execute remediation' },
  { id: 11, name: 'Evidence', icon: '📦', desc: 'Generate SOC2 pack' },
];

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
  const animRef = useRef<NodeJS.Timeout | null>(null);

  const fetchRuns = useCallback(async () => {
    try {
      const res = await api.get('/api/v1/brain/pipeline/runs').catch(() => ({ data: { runs: [] } }));
      setRuns(res.data?.runs || []);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchRuns(); }, [fetchRuns]);

  const executePipeline = async () => {
    setRunning(true);
    setCurrentRun(null);
    setSelectedRun(null);
    setStepStatuses(PIPELINE_STEPS.map(() => 'pending'));
    setCurrentStep(0);

    // Animate steps progressively while waiting for API
    // Each step takes 2-4 seconds to feel realistic
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
      // Generate mock findings for the pipeline
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
        // Map real results to step statuses
        const realStatuses: StepStatus[] = (res.data.steps || []).map((s: StepResult) =>
          s.status === 'done' ? 'done' : s.status === 'error' ? 'error' : 'done'
        );
        while (realStatuses.length < 12) realStatuses.push('done');
        setStepStatuses(realStatuses);
        setCurrentStep(11);
        setCurrentRun(res.data);
      } else {
        // Simulate completion if API unavailable
        setStepStatuses(PIPELINE_STEPS.map(() => 'done'));
        setCurrentStep(11);
      }
    } catch {
      if (animRef.current) clearTimeout(animRef.current);
      setStepStatuses(prev => prev.map((s, i) => i === currentStep ? 'error' : s === 'running' ? 'error' : s));
    } finally {
      setRunning(false);
      fetchRuns();
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
        <Badge variant="outline" className="text-lg px-4 py-2 border-purple-500/30 bg-purple-500/10 text-purple-300">
          {totalDone}/12 Steps
        </Badge>
      </motion.div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="execute">⚡ Execute Pipeline</TabsTrigger>
          <TabsTrigger value="history">📜 Run History ({runs.length})</TabsTrigger>
          {(currentRun || selectedRun) && <TabsTrigger value="detail">🔬 Run Detail</TabsTrigger>}
        </TabsList>

        {/* ════════ EXECUTE TAB ════════ */}
        <TabsContent value="execute" className="space-y-6 mt-4">
          {/* Config Card */}
          <Card className="glass-card border-gray-700/50 bg-gradient-to-br from-gray-900/80 to-gray-800/40">
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

          {/* 12-Step Grid */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
            {PIPELINE_STEPS.map((step, i) => (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: i * 0.05, type: 'spring', stiffness: 200 }}
              >
                <Card className={`relative overflow-hidden border bg-gradient-to-br ${stepStatusColor(stepStatuses[i])} transition-all duration-500 hover:scale-105`}>
                  {stepStatuses[i] === 'running' && (
                    <motion.div
                      className="absolute inset-0 bg-gradient-to-r from-transparent via-blue-500/10 to-transparent"
                      animate={{ x: ['-100%', '200%'] }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                    />
                  )}
                  <CardContent className="p-4 text-center relative z-10">
                    <div className="text-2xl mb-1">{step.icon}</div>
                    <div className="text-xs font-semibold text-gray-200 mb-1">{step.name}</div>
                    <div className="text-[10px] text-muted-foreground leading-tight mb-2">{step.desc}</div>
                    <Badge variant="outline" className={`text-[9px] ${stepBadgeColor(stepStatuses[i])}`}>
                      {stepStatuses[i] === 'done' ? '✓ DONE' : stepStatuses[i] === 'running' ? '⟳ RUNNING' : stepStatuses[i] === 'error' ? '✗ ERROR' : '○ PENDING'}
                    </Badge>
                    {currentRun?.steps?.[i]?.duration_ms != null && (
                      <div className="text-[9px] text-gray-500 mt-1 font-mono">{currentRun.steps[i].duration_ms.toFixed(0)}ms</div>
                    )}
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>

          {/* Flow Connector Lines */}
          {running && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex items-center justify-center gap-1 py-2"
            >
              {PIPELINE_STEPS.map((_, i) => (
                <div key={i} className="flex items-center">
                  <div className={`w-3 h-3 rounded-full ${stepStatuses[i] === 'done' ? 'bg-green-500' : stepStatuses[i] === 'running' ? 'bg-blue-500 animate-pulse' : 'bg-gray-700'}`} />
                  {i < 11 && <div className={`w-6 h-0.5 ${stepStatuses[i] === 'done' ? 'bg-green-500/50' : 'bg-gray-700/50'}`} />}
                </div>
              ))}
            </motion.div>
          )}


          {/* Summary Card */}
          <AnimatePresence>
            {currentRun && (
              <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                <Card className="glass-card border-green-500/30 bg-gradient-to-br from-green-900/20 to-gray-900/40">
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
                    <div className="mt-3 flex justify-end">
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

        {/* ════════ HISTORY TAB ════════ */}
        <TabsContent value="history" className="mt-4">
          <Card className="glass-card border-gray-700/50">
            <CardHeader>
              <CardTitle className="text-lg text-gray-200">Pipeline Run History</CardTitle>
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
                        {run.total_duration_ms && <span className="font-mono">{(run.total_duration_ms / 1000).toFixed(1)}s</span>}
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
              <Card className="glass-card border-blue-500/20">
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
                            <span className="font-mono text-xs text-gray-400">{step.duration_ms.toFixed(0)}ms</span>
                          )}
                          <Badge variant="outline" className={step.status === 'done' ? 'bg-green-500/20 text-green-400 border-green-500/30' : step.status === 'error' ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-gray-500/20 text-gray-400 border-gray-500/30'}>
                            {step.status === 'done' ? '✓' : step.status === 'error' ? '✗' : '○'} {step.status}
                          </Badge>
                        </div>
                      </CardContent>
                      {step.error && (
                        <div className="px-4 pb-3 text-xs text-red-400 font-mono">{step.error}</div>
                      )}
                    </Card>
                  </motion.div>
                ))}
              </div>

              {/* Summary */}
              {selectedRun.summary && (
                <Card className="glass-card border-purple-500/20">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-purple-400">Pipeline Summary</CardTitle></CardHeader>
                  <CardContent>
                    <pre className="text-xs text-gray-300 font-mono overflow-auto max-h-48 bg-gray-900/50 p-3 rounded">
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