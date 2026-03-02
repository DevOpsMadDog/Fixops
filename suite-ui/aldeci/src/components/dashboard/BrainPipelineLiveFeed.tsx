/**
 * BrainPipelineLiveFeed — Real-time activity feed for the 12-step Brain Pipeline [V3]
 *
 * Shows live pipeline processing activity: findings flowing through steps,
 * deduplication rates, enrichment status, and FAIL scoring in real-time.
 *
 * API: brainPipelineApi.listRuns(), api.get('/api/v1/brain/stats')
 */
import { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from '@tanstack/react-query';
import {
  Brain,
  Activity,
  Zap,
  CheckCircle2,
  Clock,
  ArrowRight,
  Filter,
  Layers,
  BarChart3,
  RefreshCw,
  Pause,
  Play,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { Card, CardHeader, CardTitle, CardContent } from '../ui/card';
import { ScrollArea } from '../ui/scroll-area';
import { brainPipelineApi, api } from '../../lib/api';

// ── Pipeline Step Definitions (12 steps from brain_pipeline.py) ───────────

const PIPELINE_STEPS = [
  { id: 1, name: 'Ingest', icon: Layers, color: 'text-blue-400' },
  { id: 2, name: 'Normalize', icon: Filter, color: 'text-cyan-400' },
  { id: 3, name: 'Deduplicate', icon: Zap, color: 'text-purple-400' },
  { id: 4, name: 'Enrich', icon: Brain, color: 'text-indigo-400' },
  { id: 5, name: 'Correlate', icon: Activity, color: 'text-teal-400' },
  { id: 6, name: 'Graph Build', icon: BarChart3, color: 'text-emerald-400' },
  { id: 7, name: 'Risk Score', icon: Zap, color: 'text-orange-400' },
  { id: 8, name: 'FAIL Score', icon: Brain, color: 'text-red-400' },
  { id: 9, name: 'Prioritize', icon: ArrowRight, color: 'text-amber-400' },
  { id: 10, name: 'Cluster', icon: Layers, color: 'text-violet-400' },
  { id: 11, name: 'Evidence', icon: CheckCircle2, color: 'text-green-400' },
  { id: 12, name: 'Decide', icon: Brain, color: 'text-rose-400' },
];

// ── Types ─────────────────────────────────────────────────────────────────

interface PipelineRun {
  run_id: string;
  org_id?: string;
  status: string;
  started_at?: string;
  completed_at?: string;
  total_findings?: number;
  processed_findings?: number;
  current_step?: number;
  steps_completed?: number;
  dedup_rate?: number;
  enrichment_rate?: number;
  duration_ms?: number;
}

interface FeedEvent {
  id: string;
  timestamp: number;
  step: number;
  stepName: string;
  message: string;
  severity: 'info' | 'success' | 'warning' | 'error';
  findingsCount?: number;
}

interface BrainPipelineLiveFeedProps {
  maxEvents?: number;
  compact?: boolean;
  showStepIndicators?: boolean;
}

// ── Component ─────────────────────────────────────────────────────────────

export default function BrainPipelineLiveFeed({
  maxEvents = 50,
  compact = false,
  showStepIndicators = true,
}: BrainPipelineLiveFeedProps) {
  const [paused, setPaused] = useState(false);
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [showAll, setShowAll] = useState(false);
  const feedRef = useRef<HTMLDivElement>(null);

  // Fetch pipeline runs from API
  const { data: pipelineRuns, isLoading, refetch } = useQuery({
    queryKey: ['brain-pipeline-runs'],
    queryFn: () => brainPipelineApi.listRuns(),
    refetchInterval: paused ? false : 5000,
  });

  // Fetch brain stats for live metrics
  const { data: brainStats } = useQuery({
    queryKey: ['brain-stats'],
    queryFn: () => api.get('/api/v1/brain/stats').then(r => r.data),
    refetchInterval: paused ? false : 10000,
  });

  // Derive runs array from API response
  const runs: PipelineRun[] = useMemo(() => {
    if (!pipelineRuns) return [];
    if (Array.isArray(pipelineRuns)) return pipelineRuns;
    if (pipelineRuns.runs) return pipelineRuns.runs;
    if (pipelineRuns.items) return pipelineRuns.items;
    return [];
  }, [pipelineRuns]);

  // Generate feed events from pipeline run data
  useEffect(() => {
    if (paused || runs.length === 0) return;

    const newEvents: FeedEvent[] = [];
    const now = Date.now();

    for (const run of runs.slice(0, 5)) {
      const stepsCompleted = run.steps_completed || run.current_step || 0;
      const totalFindings = run.total_findings || run.processed_findings || 0;

      // Create events for completed steps
      for (let step = 1; step <= Math.min(stepsCompleted, 12); step++) {
        const stepDef = PIPELINE_STEPS[step - 1];
        let message = '';
        let severity: FeedEvent['severity'] = 'info';

        switch (step) {
          case 1: message = `Ingested ${totalFindings} findings`; severity = 'info'; break;
          case 2: message = `Normalized to unified schema`; severity = 'info'; break;
          case 3: {
            const rate = run.dedup_rate || 0;
            message = `Deduplicated ${(rate * 100).toFixed(0)}% duplicates`;
            severity = rate > 0.3 ? 'warning' : 'success';
            break;
          }
          case 4: {
            const enrichRate = run.enrichment_rate || 0;
            message = `Enriched with CVE/CWE/EPSS data (${(enrichRate * 100).toFixed(0)}%)`;
            severity = 'info';
            break;
          }
          case 5: message = `Correlated across data sources`; severity = 'info'; break;
          case 6: message = `Built knowledge graph relationships`; severity = 'info'; break;
          case 7: message = `Calculated risk scores`; severity = 'info'; break;
          case 8: message = `FAIL scoring complete`; severity = 'success'; break;
          case 9: message = `Prioritized by exploitability`; severity = 'info'; break;
          case 10: message = `Clustered into exposure cases`; severity = 'info'; break;
          case 11: message = `Generated compliance evidence`; severity = 'success'; break;
          case 12: message = `Decision: ${run.status === 'completed' ? 'pipeline complete' : 'processing'}`; severity = 'success'; break;
        }

        newEvents.push({
          id: `${run.run_id}-step-${step}`,
          timestamp: now - (12 - step) * 1000,
          step,
          stepName: stepDef.name,
          message,
          severity,
          findingsCount: step === 1 ? totalFindings : undefined,
        });
      }

      // If run is in progress, add a "currently processing" event
      if (run.status === 'running' || run.status === 'processing') {
        const currentStep = Math.min((stepsCompleted || 0) + 1, 12);
        const stepDef = PIPELINE_STEPS[currentStep - 1];
        newEvents.push({
          id: `${run.run_id}-active-${currentStep}`,
          timestamp: now,
          step: currentStep,
          stepName: stepDef.name,
          message: `Processing step ${currentStep}: ${stepDef.name}...`,
          severity: 'info',
        });
      }
    }

    // Sort by timestamp descending and limit
    newEvents.sort((a, b) => b.timestamp - a.timestamp);
    setEvents(prev => {
      const merged = [...newEvents];
      // Add old events that aren't in new set
      for (const old of prev) {
        if (!merged.find(e => e.id === old.id)) {
          merged.push(old);
        }
      }
      return merged.slice(0, maxEvents);
    });
  }, [runs, paused, maxEvents]);

  // Auto-scroll to top on new events
  useEffect(() => {
    if (!paused && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
  }, [events, paused]);

  // ── Metrics derived from real data ──────────────────────────────────────
  const metrics = useMemo(() => {
    const activeRuns = runs.filter(r => r.status === 'running' || r.status === 'processing');
    const completedRuns = runs.filter(r => r.status === 'completed');
    const totalFindings = runs.reduce((acc, r) => acc + (r.total_findings || 0), 0);
    const avgDuration = completedRuns.length > 0
      ? completedRuns.reduce((acc, r) => acc + (r.duration_ms || 0), 0) / completedRuns.length
      : 0;

    return {
      activeRuns: activeRuns.length,
      completedRuns: completedRuns.length,
      totalFindings,
      avgDuration: Math.round(avgDuration),
      totalRuns: runs.length,
      // From brain stats API
      pipelineHealth: brainStats?.pipeline_health || brainStats?.status || 'unknown',
      totalProcessed: brainStats?.total_processed || brainStats?.findings_processed || totalFindings,
      dedupRate: brainStats?.dedup_rate || brainStats?.deduplication_rate || 0,
    };
  }, [runs, brainStats]);

  const severityColor = (severity: FeedEvent['severity']) => {
    switch (severity) {
      case 'success': return 'text-green-400';
      case 'warning': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      default: return 'text-blue-400';
    }
  };

  const severityDot = (severity: FeedEvent['severity']) => {
    switch (severity) {
      case 'success': return 'bg-green-500';
      case 'warning': return 'bg-yellow-500';
      case 'error': return 'bg-red-500';
      default: return 'bg-blue-500';
    }
  };

  // ── Skeleton loading state ──────────────────────────────────────────────
  if (isLoading) {
    return (
      <Card className="border-gray-700/30 bg-gray-900/40">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="h-6 w-48 bg-gray-700/30 rounded animate-pulse" />
            <div className="h-6 w-16 bg-gray-700/30 rounded-full animate-pulse" />
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Step indicators skeleton */}
          <div className="flex gap-1">
            {Array.from({ length: 12 }).map((_, i) => (
              <div key={i} className="flex-1 h-1.5 bg-gray-700/30 rounded-full animate-pulse" />
            ))}
          </div>
          {/* Metrics skeleton */}
          <div className="grid grid-cols-4 gap-3">
            {[1, 2, 3, 4].map(i => (
              <div key={i} className="text-center">
                <div className="h-6 w-8 mx-auto bg-gray-700/30 rounded animate-pulse mb-1" />
                <div className="h-3 w-12 mx-auto bg-gray-700/20 rounded animate-pulse" />
              </div>
            ))}
          </div>
          {/* Events skeleton */}
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} className="flex items-start gap-3 py-2">
              <div className="w-2 h-2 rounded-full bg-gray-700/30 animate-pulse mt-1.5" />
              <div className="flex-1 space-y-1">
                <div className="h-3 w-32 bg-gray-700/30 rounded animate-pulse" />
                <div className="h-3 w-48 bg-gray-700/20 rounded animate-pulse" />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    );
  }

  const displayEvents = showAll ? events : events.slice(0, compact ? 5 : 10);

  return (
    <Card className="border-gray-700/30 bg-gray-900/40">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-base">
            <Activity className="w-4 h-4 text-primary" />
            Pipeline Live Feed
            {metrics.activeRuns > 0 && (
              <span className="relative flex h-2 w-2 ml-1">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
              </span>
            )}
          </CardTitle>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPaused(!paused)}
              className="h-7 w-7 p-0"
            >
              {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => refetch()}
              className="h-7 w-7 p-0"
            >
              <RefreshCw className="w-3 h-3" />
            </Button>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {/* 12-Step Pipeline Indicator */}
        {showStepIndicators && (
          <div className="flex gap-0.5">
            {PIPELINE_STEPS.map((step) => {
              // Determine step status from latest run
              const latestRun = runs[0];
              const stepsCompleted = latestRun?.steps_completed || latestRun?.current_step || 0;
              const isCompleted = step.id <= stepsCompleted;
              const isActive = step.id === stepsCompleted + 1 && (latestRun?.status === 'running' || latestRun?.status === 'processing');

              return (
                <div
                  key={step.id}
                  className="flex-1 group relative"
                  title={`Step ${step.id}: ${step.name}`}
                >
                  <div className={`h-1.5 rounded-full transition-all duration-300 ${
                    isActive ? 'bg-primary animate-pulse' :
                    isCompleted ? 'bg-green-500' :
                    'bg-gray-700/40'
                  }`} />
                  {/* Tooltip on hover */}
                  <div className="absolute -top-8 left-1/2 -translate-x-1/2 hidden group-hover:block">
                    <span className="bg-gray-800 text-[10px] text-gray-300 px-1.5 py-0.5 rounded whitespace-nowrap border border-gray-700/30">
                      {step.name}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Metrics Bar */}
        <div className="grid grid-cols-4 gap-2 text-center">
          <div>
            <p className="text-lg font-bold text-gray-200">{metrics.activeRuns}</p>
            <p className="text-[10px] text-muted-foreground">Active</p>
          </div>
          <div>
            <p className="text-lg font-bold text-gray-200">{metrics.completedRuns}</p>
            <p className="text-[10px] text-muted-foreground">Complete</p>
          </div>
          <div>
            <p className="text-lg font-bold text-gray-200">{metrics.totalProcessed.toLocaleString()}</p>
            <p className="text-[10px] text-muted-foreground">Findings</p>
          </div>
          <div>
            <p className="text-lg font-bold text-gray-200">
              {metrics.avgDuration > 0 ? `${(metrics.avgDuration / 1000).toFixed(1)}s` : '—'}
            </p>
            <p className="text-[10px] text-muted-foreground">Avg Time</p>
          </div>
        </div>

        {/* Event Feed */}
        <ScrollArea className={compact ? 'h-40' : 'h-60'} ref={feedRef}>
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Brain className="w-10 h-10 text-muted-foreground/30 mb-3" />
              <p className="text-sm text-muted-foreground">No pipeline activity yet</p>
              <p className="text-xs text-muted-foreground/70 mt-1">
                Run a pipeline to see real-time events
              </p>
            </div>
          ) : (
            <AnimatePresence mode="popLayout">
              {displayEvents.map((event) => {
                const stepDef = PIPELINE_STEPS[event.step - 1];
                const StepIcon = stepDef?.icon || Activity;

                return (
                  <motion.div
                    key={event.id}
                    initial={{ opacity: 0, x: -10, height: 0 }}
                    animate={{ opacity: 1, x: 0, height: 'auto' }}
                    exit={{ opacity: 0, x: 10, height: 0 }}
                    transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
                    className="flex items-start gap-2.5 py-1.5 border-b border-gray-700/10 last:border-0"
                  >
                    {/* Step indicator dot */}
                    <div className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${severityDot(event.severity)}`} />

                    {/* Icon */}
                    <StepIcon className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${stepDef?.color || 'text-gray-400'}`} />

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className={`text-[9px] py-0 px-1 h-4 ${stepDef?.color || ''} border-current/20`}
                        >
                          S{event.step}
                        </Badge>
                        <span className={`text-xs font-medium ${severityColor(event.severity)}`}>
                          {event.stepName}
                        </span>
                      </div>
                      <p className="text-[11px] text-muted-foreground truncate mt-0.5">
                        {event.message}
                      </p>
                    </div>

                    {/* Timestamp */}
                    <span className="text-[10px] text-muted-foreground/60 flex-shrink-0 mt-0.5">
                      {new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          )}
        </ScrollArea>

        {/* Show more/less */}
        {events.length > (compact ? 5 : 10) && (
          <button
            onClick={() => setShowAll(!showAll)}
            className="w-full text-xs text-muted-foreground hover:text-gray-300 transition-colors flex items-center justify-center gap-1 pt-1"
          >
            {showAll ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            {showAll ? 'Show less' : `Show all ${events.length} events`}
          </button>
        )}

        {/* Pipeline health badge */}
        {metrics.pipelineHealth !== 'unknown' && (
          <div className="flex items-center justify-center gap-2 pt-1">
            <Badge
              variant="outline"
              className={`text-[10px] ${
                metrics.pipelineHealth === 'healthy' || metrics.pipelineHealth === 'operational'
                  ? 'border-green-500/30 text-green-400'
                  : metrics.pipelineHealth === 'degraded'
                    ? 'border-yellow-500/30 text-yellow-400'
                    : 'border-gray-600/30 text-gray-400'
              }`}
            >
              <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                metrics.pipelineHealth === 'healthy' || metrics.pipelineHealth === 'operational'
                  ? 'bg-green-500' : 'bg-yellow-500'
              }`} />
              Pipeline {metrics.pipelineHealth}
            </Badge>
            {metrics.dedupRate > 0 && (
              <Badge variant="outline" className="text-[10px] border-purple-500/30 text-purple-400">
                {(metrics.dedupRate * 100).toFixed(0)}% dedup
              </Badge>
            )}
          </div>
        )}

        {/* Paused indicator */}
        {paused && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center text-xs text-yellow-400/70 py-1"
          >
            <Clock className="w-3 h-3 inline mr-1" />
            Feed paused — click play to resume
          </motion.div>
        )}
      </CardContent>
    </Card>
  );
}
