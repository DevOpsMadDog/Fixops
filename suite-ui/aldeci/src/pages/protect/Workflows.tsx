import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Workflow, Plus, RefreshCw, Play, Pause, CheckCircle2,
  AlertTriangle, Clock, Search, Filter,
  Zap, Loader2, ArrowRight, BarChart3,
  Shield, Bug,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { workflowsApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface WorkflowItem {
  id: string;
  name: string;
  description: string;
  trigger: string;
  trigger_type?: string;
  enabled: boolean;
  status?: string;
  steps?: WorkflowStep[];
  last_run?: string;
  run_count?: number;
  created_at?: string;
  updated_at?: string;
  tags?: string[];
}

interface WorkflowStep {
  id: string;
  name: string;
  type: string;
  config?: Record<string, unknown>;
}

// ============================================================================
// Constants
// ============================================================================

const triggerIcons: Record<string, typeof Shield> = {
  finding: Bug,
  scan: Shield,
  schedule: Clock,
  manual: Play,
  webhook: Zap,
  threshold: BarChart3,
};

const statusColors: Record<string, string> = {
  active: 'bg-green-500/20 text-green-400 border-green-500/30',
  running: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  paused: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  failed: 'bg-red-500/20 text-red-400 border-red-500/30',
  disabled: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const WORKFLOW_TEMPLATES = [
  {
    name: 'Auto-Triage Critical Findings',
    description: 'Automatically assign critical findings to on-call and create Jira tickets',
    trigger: 'finding',
    steps: [{ id: '1', name: 'Filter Critical', type: 'filter' }, { id: '2', name: 'Create Ticket', type: 'jira' }, { id: '3', name: 'Notify Slack', type: 'slack' }],
  },
  {
    name: 'Nightly Security Scan',
    description: 'Run full SAST+DAST+Secrets scan on main branch every night',
    trigger: 'schedule',
    steps: [{ id: '1', name: 'SAST Scan', type: 'scan' }, { id: '2', name: 'DAST Scan', type: 'scan' }, { id: '3', name: 'Generate Report', type: 'report' }],
  },
  {
    name: 'AutoFix Pipeline',
    description: 'Generate and apply fixes for high-confidence vulnerabilities',
    trigger: 'finding',
    steps: [{ id: '1', name: 'Generate Fix', type: 'autofix' }, { id: '2', name: 'Validate', type: 'test' }, { id: '3', name: 'Create PR', type: 'github' }],
  },
  {
    name: 'Compliance Evidence Collection',
    description: 'Weekly evidence bundle generation for SOC2/PCI-DSS audits',
    trigger: 'schedule',
    steps: [{ id: '1', name: 'Collect Evidence', type: 'evidence' }, { id: '2', name: 'Sign Bundle', type: 'crypto' }, { id: '3', name: 'Archive', type: 'storage' }],
  },
];

// ============================================================================
// Animation Variants
// ============================================================================

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function WorkflowSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3].map(i => (
        <div key={i} className="p-4 rounded-lg border border-gray-700/30 bg-gray-800/30 animate-pulse">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-lg bg-gray-700/50" />
            <div className="flex-1 space-y-2">
              <div className="h-4 w-1/3 bg-gray-700/50 rounded" />
              <div className="h-3 w-1/2 bg-gray-700/30 rounded" />
            </div>
            <div className="h-8 w-20 bg-gray-700/30 rounded" />
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Step Pipeline Visualization
// ============================================================================

function StepPipeline({ steps }: { steps: WorkflowStep[] }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div className="flex items-center gap-1 mt-3">
      {steps.map((step, i) => (
        <div key={step.id || i} className="flex items-center gap-1">
          <div className="px-2 py-1 rounded bg-gray-800/50 border border-gray-700/30 text-xs text-gray-400">
            {step.name}
          </div>
          {i < steps.length - 1 && <ArrowRight className="w-3 h-3 text-gray-600" />}
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Workflow Card
// ============================================================================

function WorkflowCard({
  workflow,
  onExecute,
  executing,
}: {
  workflow: WorkflowItem;
  onExecute: (id: string) => void;
  executing: boolean;
}) {
  const TriggerIcon = triggerIcons[workflow.trigger || workflow.trigger_type || 'manual'] || Workflow;
  const status = workflow.enabled ? (workflow.status || 'active') : 'disabled';

  return (
    <motion.div variants={itemVariants} layout
      className="group p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 hover:border-gray-600/40 transition-all duration-200"
    >
      <div className="flex items-start gap-4">
        {/* Icon */}
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${
          workflow.enabled ? 'bg-primary/10' : 'bg-gray-800/50'
        }`}>
          <TriggerIcon className={`w-5 h-5 ${workflow.enabled ? 'text-primary' : 'text-gray-500'}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-100">{workflow.name}</span>
            <Badge className={`border text-[10px] ${statusColors[status] || statusColors.disabled}`}>
              {status}
            </Badge>
          </div>
          <p className="text-sm text-gray-400 mt-1">{workflow.description || 'No description'}</p>
          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Zap className="w-3 h-3" /> Trigger: {workflow.trigger || workflow.trigger_type || 'manual'}
            </span>
            {workflow.run_count !== undefined && (
              <span className="flex items-center gap-1">
                <BarChart3 className="w-3 h-3" /> {workflow.run_count} runs
              </span>
            )}
            {workflow.last_run && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" /> Last: {new Date(workflow.last_run).toLocaleDateString()}
              </span>
            )}
          </div>
          {workflow.steps && <StepPipeline steps={workflow.steps} />}
          {workflow.tags && workflow.tags.length > 0 && (
            <div className="flex gap-1 mt-2">
              {workflow.tags.map(tag => (
                <Badge key={tag} variant="outline" className="text-[10px] border-gray-700/40 text-gray-500">{tag}</Badge>
              ))}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <Button
            variant="outline"
            size="sm"
            onClick={() => onExecute(workflow.id)}
            disabled={executing || !workflow.enabled}
            className="border-gray-600/50 hover:border-green-500/50 hover:bg-green-500/5"
          >
            {executing ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <><Play className="w-4 h-4 mr-1" /> Run</>
            )}
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

// ============================================================================
// Main Workflows Page [V3]
// ============================================================================

export default function Workflows() {
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTrigger, setFilterTrigger] = useState('all');
  const [showTemplates, setShowTemplates] = useState(false);
  const [executingId, setExecutingId] = useState<string | null>(null);

  // Fetch workflows from real API
  const { data: workflows = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['workflows'],
    queryFn: () => workflowsApi.list(),
    refetchInterval: 15000,
  });

  // Execute workflow mutation
  const executeMutation = useMutation({
    mutationFn: (id: string) => workflowsApi.execute(id, {}),
    onSuccess: () => {
      toast.success('Workflow executed successfully');
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
      setExecutingId(null);
    },
    onError: () => {
      toast.error('Workflow execution failed');
      setExecutingId(null);
    },
  });

  // Create workflow mutation
  const createMutation = useMutation({
    mutationFn: (template: typeof WORKFLOW_TEMPLATES[0]) =>
      workflowsApi.create({
        name: template.name,
        description: template.description,
        steps: template.steps,
        triggers: { type: template.trigger },
      }),
    onSuccess: () => {
      toast.success('Workflow created');
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
      setShowTemplates(false);
    },
    onError: () => toast.error('Failed to create workflow'),
  });

  const handleExecute = useCallback((id: string) => {
    setExecutingId(id);
    executeMutation.mutate(id);
  }, [executeMutation]);

  // Filter and search
  const filteredWorkflows = useMemo(() => {
    let result = Array.isArray(workflows) ? workflows as WorkflowItem[] : [];
    if (filterTrigger !== 'all') {
      result = result.filter(w => (w.trigger || w.trigger_type || '') === filterTrigger);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(w =>
        w.name.toLowerCase().includes(q) ||
        (w.description || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [workflows, filterTrigger, searchQuery]);

  // Stats
  const stats = useMemo(() => {
    const arr = Array.isArray(workflows) ? workflows as WorkflowItem[] : [];
    return {
      total: arr.length,
      active: arr.filter(w => w.enabled).length,
      disabled: arr.filter(w => !w.enabled).length,
      totalRuns: arr.reduce((sum, w) => sum + (w.run_count || 0), 0),
    };
  }, [workflows]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 via-amber-400 to-yellow-400 bg-clip-text text-transparent">
            Automation Workflows
          </h1>
          <p className="text-gray-400 mt-1">Orchestrate security operations with automated pipelines</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} className="border-gray-600/50 hover:border-primary/50">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowTemplates(!showTemplates)} className="bg-primary hover:bg-primary/90">
            <Plus className="w-4 h-4 mr-2" /> Create Workflow
          </Button>
        </div>
      </motion.div>

      {/* Stats Row */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Workflows', value: stats.total, icon: Workflow, color: 'text-blue-400' },
          { label: 'Active', value: stats.active, icon: CheckCircle2, color: 'text-green-400' },
          { label: 'Disabled', value: stats.disabled, icon: Pause, color: 'text-gray-400' },
          { label: 'Total Runs', value: stats.totalRuns, icon: BarChart3, color: 'text-purple-400' },
        ].map(stat => (
          <Card key={stat.label} className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                  <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
                </div>
                <stat.icon className={`w-5 h-5 ${stat.color} opacity-60`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </motion.div>

      {/* Template Gallery */}
      <AnimatePresence>
        {showTemplates && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <Card className="border-primary/30 bg-gray-900/60 backdrop-blur-md">
              <CardHeader>
                <CardTitle className="text-lg">Workflow Templates</CardTitle>
                <CardDescription>Start from a pre-built template or create from scratch</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {WORKFLOW_TEMPLATES.map((template, i) => {
                    const TIcon = triggerIcons[template.trigger] || Workflow;
                    return (
                      <motion.button
                        key={i}
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ delay: i * 0.05 }}
                        onClick={() => createMutation.mutate(template)}
                        disabled={createMutation.isPending}
                        className="p-4 rounded-lg border border-gray-700/30 bg-gray-800/30 hover:border-primary/40 hover:bg-primary/5 transition-all text-left"
                      >
                        <div className="flex items-start gap-3">
                          <TIcon className="w-5 h-5 text-primary mt-0.5" />
                          <div>
                            <p className="font-medium text-sm text-gray-200">{template.name}</p>
                            <p className="text-xs text-gray-500 mt-1">{template.description}</p>
                            <div className="flex gap-1 mt-2">
                              {template.steps.map((step, si) => (
                                <Badge key={si} variant="outline" className="text-[10px] border-gray-700/30">{step.name}</Badge>
                              ))}
                            </div>
                          </div>
                        </div>
                      </motion.button>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Search & Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <Input
            placeholder="Search workflows..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="pl-10 bg-gray-900/40 border-gray-700/40"
          />
        </div>
        <div className="flex items-center gap-1">
          <Filter className="w-4 h-4 text-gray-500 mr-1" />
          {['all', 'finding', 'scan', 'schedule', 'manual', 'webhook'].map(trigger => (
            <button
              key={trigger}
              onClick={() => setFilterTrigger(trigger)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                filterTrigger === trigger
                  ? 'bg-primary/20 text-primary border border-primary/30'
                  : 'text-gray-400 hover:text-gray-300 hover:bg-gray-800/40'
              }`}
            >
              {trigger === 'all' ? 'All' : trigger.charAt(0).toUpperCase() + trigger.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Workflow List */}
      <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Workflow className="w-5 h-5 text-primary" />
            Configured Workflows
          </CardTitle>
          <CardDescription>
            {filteredWorkflows.length} workflow{filteredWorkflows.length !== 1 ? 's' : ''}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <WorkflowSkeleton />
          ) : isError ? (
            <div className="text-center py-12">
              <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-60" />
              <p className="text-gray-300 font-medium">Failed to load workflows</p>
              <p className="text-sm text-gray-500 mt-1">Check your API connection and try again</p>
              <Button variant="outline" size="sm" onClick={() => refetch()} className="mt-4 border-gray-600/50">
                <RefreshCw className="w-4 h-4 mr-2" /> Retry
              </Button>
            </div>
          ) : filteredWorkflows.length === 0 ? (
            <div className="text-center py-12">
              <Workflow className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 font-medium">No workflows configured</p>
              <p className="text-sm text-gray-500 mt-1">
                {searchQuery ? 'Try a different search term' : 'Create your first automation workflow'}
              </p>
              {!searchQuery && (
                <Button size="sm" onClick={() => setShowTemplates(true)} className="mt-4">
                  <Plus className="w-4 h-4 mr-2" /> Use Template
                </Button>
              )}
            </div>
          ) : (
            <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-3">
              {filteredWorkflows.map(workflow => (
                <WorkflowCard
                  key={workflow.id}
                  workflow={workflow}
                  onExecute={handleExecute}
                  executing={executingId === workflow.id}
                />
              ))}
            </motion.div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
