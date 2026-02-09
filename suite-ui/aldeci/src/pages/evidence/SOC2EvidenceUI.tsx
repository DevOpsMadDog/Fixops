import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';

const TSC_LABELS: Record<string, string> = {
  CC3: 'Risk Assessment', CC4: 'Monitoring', CC5: 'Control Activities',
  CC6: 'Access Control', CC7: 'System Operations', CC8: 'Change Management',
  A1: 'Availability', C1: 'Confidentiality',
};

const TSC_COLORS: Record<string, string> = {
  CC3: 'from-purple-500 to-purple-600', CC4: 'from-cyan-500 to-cyan-600',
  CC5: 'from-indigo-500 to-indigo-600', CC6: 'from-blue-500 to-blue-600',
  CC7: 'from-emerald-500 to-emerald-600', CC8: 'from-amber-500 to-amber-600',
  A1: 'from-green-500 to-green-600', C1: 'from-red-500 to-red-600',
};

interface ControlAssessment {
  control_id: string; title: string; tsc: string;
  status: string; checks_passed: number; checks_total: number;
  evidence_items: { check: string; passed: boolean; detail: string }[];
  findings: string[]; tested_at: string;
}

interface EvidencePack {
  pack_id: string; org_id: string; generated_at: string;
  timeframe_start: string; timeframe_end: string; timeframe_days: number;
  overall_score: number; overall_status: string;
  controls_assessed: number; controls_effective: number;
  controls_needing_improvement: number; controls_not_effective: number;
  assessments: ControlAssessment[];
  summary: { tsc_breakdown: Record<string, { score_pct: number; effective: number; total: number }> };
}

const statusBadge = (s: string) => {
  switch (s) {
    case 'qualified': return 'bg-green-500/20 text-green-400 border-green-500/40';
    case 'qualified_with_exceptions': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
    case 'not_qualified': return 'bg-red-500/20 text-red-400 border-red-500/40';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/40';
  }
};

const controlStatusColor = (s: string) => {
  switch (s) {
    case 'effective': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'needs_improvement': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'not_effective': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const SOC2EvidenceUI = () => {
  const [orgId, setOrgId] = useState('acme-corp');
  const [timeframeDays, setTimeframeDays] = useState(90);
  const [generating, setGenerating] = useState(false);
  const [currentPack, setCurrentPack] = useState<EvidencePack | null>(null);
  const [packs, setPacks] = useState<EvidencePack[]>([]);
  const [selectedPack, setSelectedPack] = useState<EvidencePack | null>(null);
  const [activeTab, setActiveTab] = useState('generate');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);

  const fetchPacks = useCallback(async () => {
    try {
      const res = await api.get('/api/v1/pipeline/evidence/packs').catch(() => ({ data: { packs: [] } }));
      setPacks(res.data?.packs || []);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { fetchPacks(); }, [fetchPacks]);

  const generatePack = async () => {
    setGenerating(true);
    try {
      const res = await api.post('/api/v1/pipeline/evidence/generate', {
        org_id: orgId,
        timeframe_days: timeframeDays,
      }).catch(() => ({ data: null }));
      if (res.data) {
        setCurrentPack(res.data);
        setSelectedPack(res.data);
        setActiveTab('result');
        fetchPacks();
      }
    } catch { /* ignore */ }
    setGenerating(false);
  };

  const viewPack = (pack: EvidencePack) => {
    setSelectedPack(pack);
    setActiveTab('result');
  };

  const activePack = selectedPack || currentPack;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 via-emerald-400 to-cyan-400 bg-clip-text text-transparent">
            🛡️ SOC2 Type II Evidence
          </h1>
          <p className="text-muted-foreground mt-1">Generate compliance evidence packs — 22 controls across 8 Trust Service Criteria</p>
        </div>
        <Badge variant="outline" className="text-lg px-4 py-2 border-green-500/30 bg-green-500/10 text-green-300">
          {packs.length} Packs
        </Badge>
      </motion.div>


      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="generate">🏗️ Generate Pack</TabsTrigger>
          <TabsTrigger value="history">📜 Evidence Packs ({packs.length})</TabsTrigger>
          {activePack && <TabsTrigger value="result">📊 Evidence Report</TabsTrigger>}
        </TabsList>

        {/* ════════ GENERATE TAB ════════ */}
        <TabsContent value="generate" className="space-y-6 mt-4">
          <Card className="glass-card border-gray-700/50 bg-gradient-to-br from-gray-900/80 to-gray-800/40">
            <CardHeader>
              <CardTitle className="text-lg text-gray-200">Generate SOC2 Type II Evidence Pack</CardTitle>
              <CardDescription>Assess your platform against 22 SOC2 controls and generate a downloadable evidence pack</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Organization ID</label>
                  <Input value={orgId} onChange={e => setOrgId(e.target.value)} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Audit Period (days)</label>
                  <Input type="number" value={timeframeDays} onChange={e => setTimeframeDays(+e.target.value)} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <Button onClick={generatePack} disabled={generating} size="lg"
                  className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white font-semibold shadow-lg shadow-green-500/20">
                  {generating ? <span className="flex items-center gap-2"><span className="animate-spin">⚙️</span> Generating...</span> : '📦 Generate Evidence Pack'}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* TSC Overview cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(TSC_LABELS).map(([tsc, label]) => (
              <motion.div key={tsc} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.05 }}>
                <Card className="border border-gray-700/30 bg-gray-900/40 hover:bg-gray-800/40 transition-colors">
                  <CardContent className="p-4 text-center">
                    <div className={`text-xs font-bold bg-gradient-to-r ${TSC_COLORS[tsc]} bg-clip-text text-transparent mb-1`}>{tsc}</div>
                    <div className="text-sm text-gray-300">{label}</div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </TabsContent>

        {/* ════════ HISTORY TAB ════════ */}
        <TabsContent value="history" className="mt-4">
          <Card className="glass-card border-gray-700/50">
            <CardContent className="p-4">
              {packs.length === 0 ? (
                <div className="text-center py-16 text-muted-foreground">
                  <div className="text-4xl mb-3">🛡️</div>
                  <p>No evidence packs yet. Generate your first pack above.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {packs.map((pack, i) => (
                    <motion.div key={pack.pack_id} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.03 }}
                      onClick={() => viewPack(pack)}
                      className="flex items-center justify-between p-4 rounded-lg bg-gray-800/30 border border-gray-700/30 hover:border-green-500/30 hover:bg-gray-800/50 cursor-pointer transition-all">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className={statusBadge(pack.overall_status)}>{pack.overall_status}</Badge>
                        <span className="font-mono text-sm text-gray-300">{pack.pack_id}</span>
                      </div>
                      <div className="flex items-center gap-4 text-xs text-muted-foreground">
                        <span className="font-bold text-lg text-green-400">{(pack.overall_score * 100).toFixed(0)}%</span>
                        <span>{pack.controls_assessed} controls</span>
                        <span>{pack.timeframe_days}d period</span>
                        <span>{new Date(pack.generated_at).toLocaleDateString()}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ════════ RESULT TAB ════════ */}
        <TabsContent value="result" className="space-y-6 mt-4">
          {activePack ? (
            <>
              {/* Overall Score Hero */}
              <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
                <Card className={`border ${activePack.overall_score >= 0.9 ? 'border-green-500/30 bg-gradient-to-br from-green-900/20 to-emerald-900/10' : activePack.overall_score >= 0.7 ? 'border-yellow-500/30 bg-gradient-to-br from-yellow-900/20 to-amber-900/10' : 'border-red-500/30 bg-gradient-to-br from-red-900/20 to-rose-900/10'}`}>
                  <CardContent className="p-8">
                    <div className="flex items-center justify-between">
                      <div>
                        <h2 className="text-2xl font-bold text-gray-200">SOC2 Type II Evidence Pack</h2>
                        <p className="text-sm text-muted-foreground mt-1">
                          {activePack.org_id} · {activePack.timeframe_days}-day audit period · Generated {new Date(activePack.generated_at).toLocaleString()}
                        </p>
                        <div className="flex items-center gap-3 mt-3">
                          <Badge variant="outline" className={`text-sm ${statusBadge(activePack.overall_status)}`}>
                            {activePack.overall_status?.replace(/_/g, ' ').toUpperCase()}
                          </Badge>
                          <span className="text-xs text-muted-foreground font-mono">{activePack.pack_id}</span>
                        </div>
                      </div>
                      <div className="text-center">
                        <div className={`text-6xl font-black ${activePack.overall_score >= 0.9 ? 'text-green-400' : activePack.overall_score >= 0.7 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {(activePack.overall_score * 100).toFixed(0)}%
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {activePack.controls_effective}/{activePack.controls_assessed} effective
                        </div>
                        <Progress value={activePack.overall_score * 100} className="w-32 mt-2 h-2" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>

              {/* TSC Breakdown */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {activePack.summary?.tsc_breakdown && Object.entries(activePack.summary.tsc_breakdown).map(([tsc, info], i) => (
                  <motion.div key={tsc} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
                    <Card className="border border-gray-700/30 bg-gray-900/40">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between mb-2">
                          <span className={`text-xs font-bold bg-gradient-to-r ${TSC_COLORS[tsc] || 'from-gray-400 to-gray-500'} bg-clip-text text-transparent`}>{tsc}</span>
                          <span className={`text-sm font-bold ${info.score_pct >= 90 ? 'text-green-400' : info.score_pct >= 70 ? 'text-yellow-400' : 'text-red-400'}`}>
                            {info.score_pct?.toFixed(0)}%
                          </span>
                        </div>
                        <div className="text-xs text-gray-400 mb-2">{TSC_LABELS[tsc]}</div>
                        <Progress value={info.score_pct || 0} className="h-1.5" />
                        <div className="text-[10px] text-muted-foreground mt-1">{info.effective}/{info.total} effective</div>
                      </CardContent>
                    </Card>
                  </motion.div>
                ))}
              </div>

              {/* Control Assessments */}
              <Card className="glass-card border-gray-700/50">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-gray-400">Control Assessments ({activePack.assessments?.length || 0})</CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <div className="divide-y divide-gray-800/50">
                    {(activePack.assessments || []).map((ctrl, i) => (
                      <motion.div key={ctrl.control_id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.02 }}>
                        <div
                          onClick={() => setExpandedControl(expandedControl === ctrl.control_id ? null : ctrl.control_id)}
                          className="flex items-center justify-between p-4 hover:bg-gray-800/20 cursor-pointer transition-colors"
                        >
                          <div className="flex items-center gap-3">
                            <Badge variant="outline" className={`text-[10px] ${controlStatusColor(ctrl.status)}`}>
                              {ctrl.status?.replace(/_/g, ' ')}
                            </Badge>
                            <span className="font-mono text-xs text-gray-500">{ctrl.control_id}</span>
                            <span className="text-sm text-gray-200">{ctrl.title}</span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground">
                            <span className={`font-bold ${ctrl.checks_passed === ctrl.checks_total ? 'text-green-400' : 'text-yellow-400'}`}>
                              {ctrl.checks_passed}/{ctrl.checks_total}
                            </span>
                            <span className={`text-xs font-bold bg-gradient-to-r ${TSC_COLORS[ctrl.tsc] || 'from-gray-400 to-gray-500'} bg-clip-text text-transparent`}>
                              {ctrl.tsc}
                            </span>
                            <span className="text-gray-600">{expandedControl === ctrl.control_id ? '▲' : '▼'}</span>
                          </div>
                        </div>
                        <AnimatePresence>
                          {expandedControl === ctrl.control_id && (
                            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                              className="overflow-hidden">
                              <div className="px-6 pb-4 space-y-2">
                                {(ctrl.evidence_items || []).map((ev, j) => (
                                  <div key={j} className="flex items-start gap-2 text-xs">
                                    <span className={ev.passed ? 'text-green-400' : 'text-red-400'}>{ev.passed ? '✓' : '✗'}</span>
                                    <span className="text-gray-400 font-mono w-40">{ev.check}</span>
                                    <span className="text-gray-300">{ev.detail}</span>
                                  </div>
                                ))}
                              </div>
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </motion.div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Summary Stats */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Card className="border border-green-500/20 bg-green-900/10"><CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-green-400">{activePack.controls_effective}</div>
                  <div className="text-xs text-muted-foreground">Effective</div>
                </CardContent></Card>
                <Card className="border border-yellow-500/20 bg-yellow-900/10"><CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-yellow-400">{activePack.controls_needing_improvement}</div>
                  <div className="text-xs text-muted-foreground">Needs Improvement</div>
                </CardContent></Card>
                <Card className="border border-red-500/20 bg-red-900/10"><CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-red-400">{activePack.controls_not_effective}</div>
                  <div className="text-xs text-muted-foreground">Not Effective</div>
                </CardContent></Card>
                <Card className="border border-blue-500/20 bg-blue-900/10"><CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-blue-400">{activePack.controls_assessed}</div>
                  <div className="text-xs text-muted-foreground">Total Controls</div>
                </CardContent></Card>
              </div>
            </>
          ) : (
            <div className="text-center py-16 text-muted-foreground">
              <div className="text-4xl mb-3">📊</div>
              <p>Generate or select an evidence pack to view the report</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SOC2EvidenceUI;