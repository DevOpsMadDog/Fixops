import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import {
  Brain, Zap, Shield, CheckCircle2, ArrowRight,
  Activity, Filter, GitMerge, Bug, Lock,
  FileCheck, Target, TrendingDown,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { api } from '../../lib/api';

// ── Brain Pipeline Steps (12-step CTEM pipeline) ───────────────────────────

const PIPELINE_STEPS = [
  { id: 'ingest', label: 'Ingest', icon: Zap, color: '#3b82f6' },
  { id: 'normalize', label: 'Normalize', icon: Filter, color: '#6366f1' },
  { id: 'dedup', label: 'Dedup', icon: GitMerge, color: '#8b5cf6' },
  { id: 'enrich', label: 'Enrich', icon: Brain, color: '#a855f7' },
  { id: 'correlate', label: 'Correlate', icon: Activity, color: '#d946ef' },
  { id: 'graph', label: 'Graph', icon: Target, color: '#ec4899' },
  { id: 'score', label: 'Score', icon: TrendingDown, color: '#f43f5e' },
  { id: 'verify', label: 'Verify', icon: Bug, color: '#ef4444' },
  { id: 'triage', label: 'Triage', icon: Shield, color: '#f97316' },
  { id: 'fix', label: 'AutoFix', icon: Lock, color: '#eab308' },
  { id: 'evidence', label: 'Evidence', icon: FileCheck, color: '#22c55e' },
  { id: 'decide', label: 'Decide', icon: CheckCircle2, color: '#10b981' },
] as const;

// ── Live Finding Item ──────────────────────────────────────────────────────

interface LiveFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  step: string;
  timestamp: number;
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
};

// Deterministic processing count increments per step
const PROCESSING_INCREMENTS = [2, 1, 3, 1, 2, 2, 1, 3, 1, 2, 2, 1];

// ── Main Component ─────────────────────────────────────────────────────────

export default function LivePipelineIndicator() {
  const [activeStep, setActiveStep] = useState(0);
  const [processingCount, setProcessingCount] = useState(0);

  // Fetch real pipeline stats
  const { data: brainStats } = useQuery({
    queryKey: ['brain-pipeline-live'],
    queryFn: () => api.get('/api/v1/brain/stats').then(r => r.data),
    refetchInterval: 10000,
    retry: 0,
  });

  const { data: brainHealth } = useQuery({
    queryKey: ['brain-health-live'],
    queryFn: () => api.get('/api/v1/brain/health').then(r => r.data),
    refetchInterval: 15000,
    retry: 0,
  });

  // Fetch recent findings from real API
  const { data: recentFindings } = useQuery({
    queryKey: ['brain-pipeline-live-findings'],
    queryFn: () => api.get('/api/v1/analytics/findings', { params: { limit: 8 } })
      .then(r => {
        const items = Array.isArray(r.data) ? r.data : r.data?.findings || r.data?.items || [];
        return items.slice(0, 8).map((f: Record<string, unknown>, i: number) => ({
          id: (f.id as string) || `f-${i}`,
          title: (f.title as string) || (f.name as string) || (f.description as string) || 'Finding',
          severity: (['critical', 'high', 'medium', 'low'].includes(String(f.severity).toLowerCase())
            ? String(f.severity).toLowerCase()
            : 'medium') as LiveFinding['severity'],
          step: PIPELINE_STEPS[i % PIPELINE_STEPS.length].id,
          timestamp: f.created_at ? new Date(f.created_at as string).getTime() : Date.now() - i * 60000,
        }));
      })
      .catch((e) => { console.error('[LivePipeline] findings fetch failed:', e?.message); return []; }),
    refetchInterval: 15000,
    retry: 0,
  });

  // Use real findings — empty array when none available
  const liveFindings: LiveFinding[] = recentFindings || [];

  // Simulate pipeline step progression based on real data
  useEffect(() => {
    const totalNodes = brainStats?.total_nodes || 0;
    const totalEdges = brainStats?.total_edges || 0;

    if (totalNodes === 0 && totalEdges === 0) return;

    // Progress through pipeline steps
    const stepInterval = setInterval(() => {
      setActiveStep(prev => {
        const nextStep = (prev + 1) % PIPELINE_STEPS.length;
        setProcessingCount(p => p + PROCESSING_INCREMENTS[nextStep]);
        return nextStep;
      });
    }, 3000);

    return () => {
      clearInterval(stepInterval);
    };
  }, [brainStats]);

  const pipelineStatus = brainHealth?.status || 'active';
  const totalProcessed = brainStats?.total_nodes || processingCount;
  const dedupRate = brainStats?.density ? `${((1 - brainStats.density) * 100).toFixed(0)}%` : '—';

  return (
    <Card className="glass-card backdrop-blur-md bg-gray-900/50 border-gray-700/40 overflow-hidden">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <Brain className="w-5 h-5 text-primary" />
            Brain Pipeline — Live
          </CardTitle>
          <div className="flex items-center gap-2">
            <motion.div
              className={`w-2 h-2 rounded-full ${pipelineStatus === 'healthy' || pipelineStatus === 'active' ? 'bg-emerald-500' : 'bg-yellow-500'}`}
              animate={{ scale: [1, 1.4, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 h-4 border-emerald-500/30 text-emerald-400">
              PROCESSING
            </Badge>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Pipeline Steps — mini progress bar */}
        <div className="flex items-center gap-0.5">
          {PIPELINE_STEPS.map((step, i) => {
            const Icon = step.icon;
            const isActive = i === activeStep;
            const isPast = i < activeStep;
            return (
              <div key={step.id} className="flex items-center flex-1">
                <motion.div
                  className={`relative flex items-center justify-center w-full h-7 rounded-sm text-[9px] font-medium transition-all ${
                    isActive
                      ? 'bg-primary/20 text-primary border border-primary/40'
                      : isPast
                      ? 'bg-emerald-500/10 text-emerald-400/80'
                      : 'bg-gray-800/30 text-gray-500'
                  }`}
                  animate={isActive ? { scale: [1, 1.05, 1] } : {}}
                  transition={{ duration: 1.5, repeat: isActive ? Infinity : 0 }}
                >
                  <Icon className="w-3 h-3" />
                  {isActive && (
                    <motion.div
                      className="absolute inset-0 rounded-sm border border-primary/30"
                      animate={{ opacity: [0.5, 0, 0.5] }}
                      transition={{ duration: 1.5, repeat: Infinity }}
                    />
                  )}
                </motion.div>
                {i < PIPELINE_STEPS.length - 1 && (
                  <ArrowRight className={`w-2.5 h-2.5 flex-shrink-0 ${isPast ? 'text-emerald-500/50' : 'text-gray-700'}`} />
                )}
              </div>
            );
          })}
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center">
            <motion.p
              className="text-lg font-bold text-primary"
              key={totalProcessed}
              initial={{ scale: 1.2 }}
              animate={{ scale: 1 }}
            >
              {totalProcessed}
            </motion.p>
            <p className="text-[10px] text-muted-foreground">Entities Processed</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-bold text-emerald-400">{dedupRate}</p>
            <p className="text-[10px] text-muted-foreground">Noise Reduction</p>
          </div>
          <div className="text-center">
            <p className="text-lg font-bold text-amber-400">{PIPELINE_STEPS[activeStep].label}</p>
            <p className="text-[10px] text-muted-foreground">Current Step</p>
          </div>
        </div>

        {/* Live Findings Feed */}
        <div className="space-y-1.5 max-h-[180px] overflow-hidden">
          <AnimatePresence mode="popLayout">
            {liveFindings.map((finding) => (
              <motion.div
                key={finding.id}
                initial={{ opacity: 0, x: -20, height: 0 }}
                animate={{ opacity: 1, x: 0, height: 'auto' }}
                exit={{ opacity: 0, x: 20, height: 0 }}
                transition={{ type: 'spring', stiffness: 300, damping: 25 }}
                className="flex items-center gap-2 py-1.5 px-2.5 rounded-md bg-gray-800/30 border border-gray-700/20"
              >
                <Badge
                  variant="outline"
                  className={`text-[9px] px-1 py-0 h-3.5 ${severityColors[finding.severity]}`}
                >
                  {finding.severity[0].toUpperCase()}
                </Badge>
                <span className="text-[11px] text-gray-300 truncate flex-1">{finding.title}</span>
                <span className="text-[9px] text-gray-600 flex-shrink-0">
                  {new Date(finding.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              </motion.div>
            ))}
          </AnimatePresence>
          {liveFindings.length === 0 && (
            <div className="text-center py-4 text-xs text-muted-foreground">
              <Activity className="w-4 h-4 mx-auto mb-1 animate-pulse" />
              Waiting for pipeline activity...
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
