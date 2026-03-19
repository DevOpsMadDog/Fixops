import { useState, useMemo, useCallback, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Wrench, RefreshCw, Search, Filter, CheckCircle2, Clock,
  AlertTriangle, XCircle, User, Shield, Bug,
  Loader2, GitPullRequest, ExternalLink,
} from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface RemediationTask {
  id: string;
  task_id?: string;
  title: string;
  description?: string;
  status: string;
  severity: string;
  priority?: string;
  assignee?: string;
  assignee_email?: string;
  cve_id?: string;
  finding_id?: string;
  fix_type?: string;
  created_at?: string;
  updated_at?: string;
  due_date?: string;
  sla_remaining_ms?: number;
  pr_url?: string;
  org_id?: string;
  app_id?: string;
}

// ============================================================================
// Constants
// ============================================================================

const statusConfig: Record<string, { color: string; bgColor: string; icon: typeof CheckCircle2 }> = {
  open: { color: 'text-red-400', bgColor: 'bg-red-500/20 border-red-500/30', icon: AlertTriangle },
  in_progress: { color: 'text-blue-400', bgColor: 'bg-blue-500/20 border-blue-500/30', icon: Loader2 },
  pending_review: { color: 'text-yellow-400', bgColor: 'bg-yellow-500/20 border-yellow-500/30', icon: Clock },
  resolved: { color: 'text-green-400', bgColor: 'bg-green-500/20 border-green-500/30', icon: CheckCircle2 },
  closed: { color: 'text-gray-400', bgColor: 'bg-gray-500/20 border-gray-500/30', icon: XCircle },
  wont_fix: { color: 'text-gray-500', bgColor: 'bg-gray-600/20 border-gray-600/30', icon: XCircle },
};

const severityConfig: Record<string, { color: string; label: string }> = {
  critical: { color: 'bg-red-500/20 text-red-400 border-red-500/30', label: 'CRITICAL' },
  high: { color: 'bg-orange-500/20 text-orange-400 border-orange-500/30', label: 'HIGH' },
  medium: { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', label: 'MEDIUM' },
  low: { color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', label: 'LOW' },
  info: { color: 'bg-gray-500/20 text-gray-400 border-gray-500/30', label: 'INFO' },
};

// ============================================================================
// Animation Variants
// ============================================================================

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function TaskSkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3, 4, 5].map(i => (
        <div key={i} className="p-4 rounded-lg border border-gray-700/30 bg-gray-800/30 animate-pulse">
          <div className="flex items-start gap-4">
            <div className="w-2 h-16 rounded bg-gray-700/40" />
            <div className="flex-1 space-y-2">
              <div className="h-4 w-1/3 bg-gray-700/40 rounded" />
              <div className="h-3 w-2/3 bg-gray-700/30 rounded" />
              <div className="h-3 w-1/4 bg-gray-700/20 rounded" />
            </div>
            <div className="h-6 w-20 bg-gray-700/30 rounded-full" />
          </div>
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// Task Card
// ============================================================================

function TaskCard({
  task,
  onTransition,
}: {
  task: RemediationTask;
  onTransition: (taskId: string, status: string) => void;
}) {
  const status = statusConfig[task.status] || statusConfig.open;
  const severity = severityConfig[(task.severity || 'medium').toLowerCase()] || severityConfig.medium;
  const StatusIcon = status.icon;

  const slaHours = task.sla_remaining_ms ? Math.round(task.sla_remaining_ms / 3600000) : null;

  return (
    <motion.div variants={itemVariants} layout
      className="group p-4 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 hover:border-gray-600/40 transition-all duration-200"
    >
      <div className="flex items-start gap-3">
        {/* Severity Bar */}
        <div className={`w-1.5 self-stretch rounded-full ${
          task.severity === 'critical' ? 'bg-red-500' :
          task.severity === 'high' ? 'bg-orange-500' :
          task.severity === 'medium' ? 'bg-yellow-500' :
          'bg-blue-500'
        }`} />

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-100 truncate">
              {task.title || task.cve_id || 'Untitled Task'}
            </span>
            <Badge className={`border text-[10px] ${severity.color}`}>{severity.label}</Badge>
            <Badge className={`border text-[10px] flex items-center gap-1 ${status.bgColor}`}>
              <StatusIcon className={`w-3 h-3 ${task.status === 'in_progress' ? 'animate-spin' : ''}`} />
              {task.status?.replace(/_/g, ' ')}
            </Badge>
          </div>

          {task.description && (
            <p className="text-sm text-gray-400 mt-1 line-clamp-2">{task.description}</p>
          )}

          <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
            {task.cve_id && (
              <span className="flex items-center gap-1 font-mono">
                <Bug className="w-3 h-3" /> {task.cve_id}
              </span>
            )}
            {task.assignee && (
              <span className="flex items-center gap-1">
                <User className="w-3 h-3" /> {task.assignee}
              </span>
            )}
            {task.fix_type && (
              <span className="flex items-center gap-1">
                <Wrench className="w-3 h-3" /> {task.fix_type}
              </span>
            )}
            {slaHours !== null && (
              <span className={`flex items-center gap-1 ${slaHours < 24 ? 'text-red-400' : slaHours < 72 ? 'text-yellow-400' : ''}`}>
                <Clock className="w-3 h-3" /> {slaHours}h SLA
              </span>
            )}
            {task.pr_url && (
              <a href={task.pr_url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-blue-400 hover:underline">
                <GitPullRequest className="w-3 h-3" /> PR
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
            {task.created_at && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" /> {new Date(task.created_at).toLocaleDateString()}
              </span>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
          {task.status === 'open' && (
            <Button variant="outline" size="sm" onClick={() => onTransition(task.id || task.task_id || '', 'in_progress')}
              className="text-xs border-gray-600/50 hover:border-blue-500/50">
              Start
            </Button>
          )}
          {task.status === 'in_progress' && (
            <Button variant="outline" size="sm" onClick={() => onTransition(task.id || task.task_id || '', 'resolved')}
              className="text-xs border-gray-600/50 hover:border-green-500/50">
              Resolve
            </Button>
          )}
          {task.status === 'pending_review' && (
            <Button variant="outline" size="sm" onClick={() => onTransition(task.id || task.task_id || '', 'resolved')}
              className="text-xs border-gray-600/50 hover:border-green-500/50">
              Approve
            </Button>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// ============================================================================
// Main Remediation Center Page [V3]
// ============================================================================

export default function Remediation() {
  const queryClient = useQueryClient();
  const [searchParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [activeTab, setActiveTab] = useState('all');

  // Apply URL search params as initial filters (deep-link support)
  useEffect(() => {
    const severity = searchParams.get('severity');
    const status = searchParams.get('status');
    const cve = searchParams.get('cve_id');
    if (severity && severity !== 'all') setFilterSeverity(severity.toLowerCase());
    if (status && status !== 'all') setActiveTab(status.toLowerCase());
    if (cve) setSearchQuery(cve);
  }, [searchParams]);

  // Fetch tasks from real API
  const { data: rawTasks = [], isLoading, isError, refetch } = useQuery({
    queryKey: ['remediation-tasks'],
    queryFn: () => api.get('/api/v1/remediation/tasks', { params: { org_id: 'default' } }).then(r => r.data?.tasks || r.data || []),
    refetchInterval: 15000,
  });

  const tasks = useMemo(() => (Array.isArray(rawTasks) ? rawTasks : []) as RemediationTask[], [rawTasks]);

  // Transition mutation
  const transitionMutation = useMutation({
    mutationFn: ({ taskId, status }: { taskId: string; status: string }) =>
      api.put(`/api/v1/remediation/tasks/${taskId}/status`, { status }),
    onSuccess: () => {
      toast.success('Task status updated');
      queryClient.invalidateQueries({ queryKey: ['remediation-tasks'] });
    },
    onError: () => toast.error('Failed to update task status'),
  });

  const handleTransition = useCallback((taskId: string, status: string) => {
    transitionMutation.mutate({ taskId, status });
  }, [transitionMutation]);

  // Filter and search
  const filteredTasks = useMemo(() => {
    let result = tasks;
    if (activeTab !== 'all') {
      result = result.filter(t => t.status === activeTab);
    }
    if (filterSeverity !== 'all') {
      result = result.filter(t => (t.severity || '').toLowerCase() === filterSeverity);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(t =>
        (t.title || '').toLowerCase().includes(q) ||
        (t.cve_id || '').toLowerCase().includes(q) ||
        (t.assignee || '').toLowerCase().includes(q) ||
        (t.description || '').toLowerCase().includes(q)
      );
    }
    return result;
  }, [tasks, activeTab, filterSeverity, searchQuery]);

  // Stats from real data
  const stats = useMemo(() => ({
    total: tasks.length,
    open: tasks.filter(t => t.status === 'open').length,
    inProgress: tasks.filter(t => t.status === 'in_progress').length,
    resolved: tasks.filter(t => t.status === 'resolved' || t.status === 'closed').length,
    critical: tasks.filter(t => (t.severity || '').toLowerCase() === 'critical').length,
  }), [tasks]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 via-emerald-400 to-teal-400 bg-clip-text text-transparent">
            Remediation Center
          </h1>
          <p className="text-gray-400 mt-1">Track, assign, and resolve security vulnerabilities</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()} className="border-gray-600/50 hover:border-primary/50">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <motion.div variants={containerVariants} initial="hidden" animate="visible"
        className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {[
          { label: 'Total Tasks', value: stats.total, icon: Wrench, color: 'text-blue-400' },
          { label: 'Open', value: stats.open, icon: AlertTriangle, color: 'text-red-400' },
          { label: 'In Progress', value: stats.inProgress, icon: Loader2, color: 'text-yellow-400' },
          { label: 'Resolved', value: stats.resolved, icon: CheckCircle2, color: 'text-green-400' },
          { label: 'Critical', value: stats.critical, icon: Shield, color: 'text-red-500' },
        ].map((stat) => (
          <motion.div key={stat.label} variants={itemVariants}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
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
          </motion.div>
        ))}
      </motion.div>

      {/* Resolution Progress Bar */}
      {stats.total > 0 && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}>
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="py-4 px-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-300">Resolution Progress</span>
                <span className="text-sm text-gray-400">
                  {stats.resolved}/{stats.total} ({Math.round((stats.resolved / stats.total) * 100)}%)
                </span>
              </div>
              <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
                <motion.div
                  className="h-full bg-gradient-to-r from-green-500 to-emerald-500 rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${(stats.resolved / stats.total) * 100}%` }}
                  transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
                />
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Tabs + Search/Filter */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <TabsList className="bg-gray-900/60">
            <TabsTrigger value="all">All ({stats.total})</TabsTrigger>
            <TabsTrigger value="open">Open ({stats.open})</TabsTrigger>
            <TabsTrigger value="in_progress">In Progress ({stats.inProgress})</TabsTrigger>
            <TabsTrigger value="resolved">Resolved ({stats.resolved})</TabsTrigger>
          </TabsList>

          <div className="flex items-center gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <Input
                placeholder="Search tasks, CVEs..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="pl-10 w-64 bg-gray-900/40 border-gray-700/40"
              />
            </div>
            <div className="flex items-center gap-1">
              <Filter className="w-4 h-4 text-gray-500 mr-1" />
              {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                <button
                  key={sev}
                  onClick={() => setFilterSeverity(sev)}
                  className={`px-2 py-1 rounded text-xs font-medium transition-all ${
                    filterSeverity === sev
                      ? 'bg-primary/20 text-primary border border-primary/30'
                      : 'text-gray-400 hover:text-gray-300 hover:bg-gray-800/40'
                  }`}
                >
                  {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Task List */}
        <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
          <CardContent className="p-4">
            {isLoading ? (
              <TaskSkeleton />
            ) : isError ? (
              <div className="text-center py-12">
                <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-60" />
                <p className="text-gray-300 font-medium">Failed to load remediation tasks</p>
                <p className="text-sm text-gray-500 mt-1">Check your API connection and try again</p>
                <Button variant="outline" size="sm" onClick={() => refetch()} className="mt-4 border-gray-600/50">
                  <RefreshCw className="w-4 h-4 mr-2" /> Retry
                </Button>
              </div>
            ) : filteredTasks.length === 0 ? (
              <div className="text-center py-12">
                <CheckCircle2 className="w-12 h-12 text-green-500/40 mx-auto mb-4" />
                <p className="text-gray-400 font-medium">
                  {activeTab !== 'all' ? `No ${activeTab.replace('_', ' ')} tasks` : 'No remediation tasks'}
                </p>
                <p className="text-sm text-gray-500 mt-1">
                  {searchQuery ? 'Try a different search term' : 'Run a scan to generate remediation tasks'}
                </p>
              </div>
            ) : (
              <motion.div variants={containerVariants} initial="hidden" animate="visible" className="space-y-2">
                {filteredTasks.map(task => (
                  <TaskCard
                    key={task.id || task.task_id}
                    task={task}
                    onTransition={handleTransition}
                  />
                ))}
              </motion.div>
            )}
          </CardContent>
        </Card>
      </Tabs>
    </div>
  );
}
