import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Brain, Activity, Shield, Zap, CheckCircle2,
  ArrowRight, Radio, Loader2, Network, TrendingUp,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Progress } from '../components/ui/progress';
import { nerveCenterApi } from '../lib/api';
import { toast } from 'sonner';

const statusColor: Record<string, string> = {
  healthy: 'text-green-400', degraded: 'text-yellow-400', offline: 'text-red-400',
};

const actionStatusBadge: Record<string, string> = {
  completed: 'bg-green-500/20 text-green-400', executing: 'bg-blue-500/20 text-blue-400',
  pending: 'bg-yellow-500/20 text-yellow-400', blocked: 'bg-red-500/20 text-red-400',
};

export default function NerveCenter() {
  const [remediateModal, setRemediateModal] = useState(false);

  // Real-time state — refresh every 5s
  const { data: state, isLoading } = useQuery({
    queryKey: ['nerve-center-state'],
    queryFn: nerveCenterApi.getState,
    refetchInterval: 5000,
  });

  const { data: intelligenceMap } = useQuery({
    queryKey: ['intelligence-map'],
    queryFn: nerveCenterApi.getIntelligenceMap,
  });

  const remediateMutation = useMutation({
    mutationFn: nerveCenterApi.triggerRemediation,
    onSuccess: (data) => {
      toast.success(data.message);
      setRemediateModal(false);
    },
    onError: () => toast.error('Remediation failed'),
  });

  const pulse = state?.threat_pulse;
  const suites = state?.suites || [];
  const links = state?.intelligence_links || [];
  const actions = state?.recent_actions || [];
  const pipeline = state?.pipeline_throughput || {};
  const decision = state?.decision_engine || {};
  const compliance = state?.compliance_posture || {};
  const nodes = intelligenceMap?.nodes || [];
  const edges = intelligenceMap?.edges || [];

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-12 h-12 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Brain className="w-8 h-8 text-primary" />
            Nerve Center
            <Badge variant="outline" className="text-xs animate-pulse border-primary text-primary">LIVE</Badge>
          </h1>
          <p className="text-muted-foreground mt-1">Unified intelligence command center — all suites connected</p>
        </div>
        <Button onClick={() => setRemediateModal(!remediateModal)} className="gap-2">
          <Zap className="w-4 h-4" /> Auto-Remediate
        </Button>
      </div>

      {/* Threat Pulse */}
      {pulse && (
        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}>
          <Card className="glass-card border-primary/30 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-primary/5 animate-pulse" />
            <CardContent className="p-6 relative">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-6">
                  {/* Animated Pulse Ring */}
                  <div className="relative w-24 h-24">
                    <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
                      <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="4" className="text-muted/20" />
                      <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="4"
                        className={pulse.score > 70 ? 'text-red-500' : pulse.score > 40 ? 'text-yellow-500' : 'text-green-500'}
                        strokeDasharray={`${pulse.score * 2.64} 264`} strokeLinecap="round" />
                    </svg>
                    <div className="absolute inset-0 flex flex-col items-center justify-center">
                      <span className="text-2xl font-bold">{pulse.score}</span>
                      <span className="text-[10px] text-muted-foreground uppercase">{pulse.level}</span>
                    </div>
                  </div>
                  <div className="space-y-1">
                    <h2 className="text-xl font-semibold">Threat Pulse</h2>
                    <p className="text-sm text-muted-foreground">Platform-wide threat assessment score</p>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-8 text-center">
                  <div>
                    <p className="text-2xl font-bold text-red-400">{pulse.active_incidents}</p>
                    <p className="text-xs text-muted-foreground">Active Incidents</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-green-400">{pulse.auto_blocked}</p>
                    <p className="text-xs text-muted-foreground">Auto-Blocked</p>
                  </div>
                  <div>
                    <p className="text-2xl font-bold text-yellow-400">{pulse.pending_decisions}</p>
                    <p className="text-xs text-muted-foreground">Pending Decisions</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Suite Status Grid */}
      <div className="grid grid-cols-4 gap-4">
        {suites.map((s: any, i: number) => (
          <motion.div key={s.suite} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
            <Card className="glass-card">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-medium text-sm">{s.suite.replace('suite-', '').toUpperCase()}</h3>
                  <div className={`flex items-center gap-1 text-xs ${statusColor[s.status] || 'text-gray-400'}`}>
                    <Radio className="w-3 h-3" /> {s.status}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div><span className="text-muted-foreground">Endpoints:</span> <span className="font-mono">{s.endpoints}</span></div>
                  <div><span className="text-muted-foreground">Latency:</span> <span className="font-mono">{s.latency_ms}ms</span></div>
                  <div><span className="text-muted-foreground">Active:</span> <span className="font-mono">{s.active_tasks}</span></div>
                  <div><span className="text-muted-foreground">Health:</span> <CheckCircle2 className="w-3 h-3 inline text-green-400" /></div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-3 gap-4">
        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><Activity className="w-4 h-4 text-primary" /> Pipeline Throughput</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Findings/hour</span><span className="font-mono font-bold">{pipeline.findings_per_hour?.toLocaleString()}</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Avg processing</span><span className="font-mono">{pipeline.avg_processing_ms}ms</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Queue depth</span><span className="font-mono">{pipeline.queue_depth}</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Dedup rate</span><span className="font-mono text-green-400">{((pipeline.dedup_rate || 0) * 100).toFixed(0)}%</span></div>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><Brain className="w-4 h-4 text-purple-400" /> Decision Engine</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Consensus accuracy</span><span className="font-mono font-bold text-green-400">{((decision.consensus_accuracy || 0) * 100).toFixed(0)}%</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Active models</span><span className="font-mono">{decision.models_active}</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Decisions today</span><span className="font-mono">{decision.decisions_today}</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Avg confidence</span><span className="font-mono">{((decision.avg_confidence || 0) * 100).toFixed(0)}%</span></div>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><Shield className="w-4 h-4 text-blue-400" /> Compliance Posture</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Frameworks</span><span className="font-mono">{compliance.frameworks_tracked}</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Passing</span><span className="font-mono text-green-400">{compliance.controls_passing}</span></div>
            <div className="flex justify-between text-sm"><span className="text-muted-foreground">Failing</span><span className="font-mono text-red-400">{compliance.controls_failing}</span></div>
            <div className="mt-1">
              <div className="flex justify-between text-xs mb-1"><span>Coverage</span><span>{compliance.coverage_pct}%</span></div>
              <Progress value={compliance.coverage_pct || 0} className="h-2" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Intelligence Flow Graph */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Network className="w-5 h-5 text-primary" /> Intelligence Flow Map</CardTitle>
          <CardDescription>How data flows between all system nodes — {nodes.length} nodes, {edges.length} connections</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-5 gap-3">
            {nodes.map((node: any) => (
              <div key={node.id} className="p-3 rounded-lg border border-border bg-card/50 hover:border-primary/50 transition-colors cursor-pointer">
                <div className="flex items-center gap-2 mb-2">
                  <div className={`w-2 h-2 rounded-full ${node.type === 'brain' ? 'bg-purple-500 animate-pulse' : node.type === 'entry' ? 'bg-blue-500' : node.type === 'processor' ? 'bg-green-500' : node.type === 'verifier' ? 'bg-red-500' : node.type === 'assessor' ? 'bg-yellow-500' : node.type === 'store' ? 'bg-cyan-500' : node.type === 'enricher' ? 'bg-orange-500' : node.type === 'connector' ? 'bg-pink-500' : node.type === 'automator' ? 'bg-indigo-500' : 'bg-slate-500'}`} />
                  <span className="text-xs font-medium truncate">{node.label}</span>
                </div>
                <p className="text-[10px] text-muted-foreground mb-1">{node.suite}</p>
                <div className="flex flex-wrap gap-1">
                  {node.apis?.slice(0, 3).map((a: string) => (
                    <Badge key={a} variant="outline" className="text-[9px] px-1 py-0 h-4">{a}</Badge>
                  ))}
                  {node.apis?.length > 3 && <Badge variant="outline" className="text-[9px] px-1 py-0 h-4">+{node.apis.length - 3}</Badge>}
                </div>
              </div>
            ))}
          </div>
          {/* Connection lines summary */}
          <div className="mt-4 grid grid-cols-4 gap-2">
            {edges.slice(0, 8).map((edge: any, i: number) => (
              <div key={i} className="flex items-center gap-1 text-xs text-muted-foreground">
                <span className="font-mono text-primary">{edge.from}</span>
                <ArrowRight className="w-3 h-3 text-muted-foreground/50" />
                <span className="font-mono text-primary">{edge.to}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Data Flow Links + Recent Actions */}
      <div className="grid grid-cols-2 gap-4">
        {/* Live Data Flows */}
        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><TrendingUp className="w-4 h-4" /> Live Data Flows</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {links.map((link: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-2 rounded border border-border/50 hover:bg-accent/30 transition-colors">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <Badge variant="outline" className="text-[10px] shrink-0">{link.source_suite.replace('suite-', '')}</Badge>
                  <ArrowRight className="w-3 h-3 text-muted-foreground/50 shrink-0" />
                  <Badge variant="outline" className="text-[10px] shrink-0">{link.target_suite.replace('suite-', '')}</Badge>
                  <span className="text-xs text-muted-foreground truncate ml-1">{link.data_flow}</span>
                </div>
                <span className="text-xs font-mono text-primary ml-2">{link.events_per_min}/min</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Recent Actions */}
        <Card className="glass-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2"><Zap className="w-4 h-4 text-yellow-400" /> Recent Auto-Remediation</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {actions.map((action: any) => (
              <div key={action.id} className="p-2 rounded border border-border/50 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium truncate max-w-[70%]">{action.trigger}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full ${actionStatusBadge[action.status] || ''}`}>{action.status}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                  <span>Action: <span className="text-foreground">{action.action_type}</span></span>
                  <span>Target: <span className="font-mono text-foreground">{action.target}</span></span>
                  <span>Confidence: <span className="font-mono text-green-400">{(action.confidence * 100).toFixed(0)}%</span></span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Remediation Modal */}
      {remediateModal && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={() => setRemediateModal(false)}>
          <motion.div initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} className="bg-card border border-border rounded-xl p-6 w-[500px] max-w-[90vw]" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-bold mb-4 flex items-center gap-2"><Zap className="w-5 h-5 text-primary" /> Trigger Auto-Remediation</h3>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-muted-foreground">Action</label>
                <div className="flex gap-2 mt-1">
                  {['block', 'quarantine', 'patch', 'escalate', 'notify'].map((action) => (
                    <Button key={action} variant="outline" size="sm" className="text-xs capitalize" onClick={() => {
                      remediateMutation.mutate({ finding_ids: ['demo-finding-1'], action, reason: 'Manual trigger from Nerve Center' });
                    }}>
                      {action}
                    </Button>
                  ))}
                </div>
              </div>
              <p className="text-xs text-muted-foreground">This will queue an auto-remediation action through the decision engine with full audit trail.</p>
            </div>
            <div className="flex justify-end mt-6">
              <Button variant="ghost" onClick={() => setRemediateModal(false)}>Cancel</Button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
}

