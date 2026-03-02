import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Wrench,
  Code,
  GitPullRequest,
  CheckCircle2,
  Clock,
  Copy,
  ExternalLink,
  Play,
  Loader2,
  RefreshCw,
  FileCode,
  Package,
  AlertTriangle,
  TrendingDown,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { ScrollArea } from '../components/ui/scroll-area';
import { Progress } from '../components/ui/progress';
import { remediationApi, api } from '../lib/api';
import { toast } from 'sonner';

// ── Animation ───────────────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.06 } },
};
const itemVariants = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring' as const, stiffness: 260, damping: 22 } },
};

// ── Interfaces ──────────────────────────────────────────────────────────────

interface RemediationTask {
  id: string;
  cve?: string;
  cve_id?: string;
  title?: string;
  name?: string;
  status: string;
  severity?: string;
  priority?: string;
  fix?: string;
  pr_url?: string;
  prUrl?: string;
  assignee?: string;
  created_at?: string;
  updated_at?: string;
  sla_deadline?: string;
}

interface LocalRemediation {
  id: string;
  cve?: string;
  title: string;
  status: 'pending' | 'in-progress' | 'completed' | 'failed';
  severity: string;
  fix?: string;
  prUrl?: string;
}

// ── Skeleton ────────────────────────────────────────────────────────────────

function RemediationSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
        {[1, 2, 3, 4, 5, 6].map(i => (
          <Card key={i} className="border-gray-700/30 bg-gray-900/40">
            <CardContent className="pt-6">
              <div className="h-6 w-6 bg-gray-700/40 rounded animate-pulse mb-3" />
              <div className="h-8 w-16 bg-gray-700/30 rounded animate-pulse mb-1" />
              <div className="h-3 w-20 bg-gray-700/20 rounded animate-pulse" />
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────────────

export default function RemediationCenter() {
  const [selectedCve, setSelectedCve] = useState('');
  const [localRemediations, setLocalRemediations] = useState<LocalRemediation[]>([]);
  const queryClient = useQueryClient();

  // ── Data Fetching (from real API) ─────────────────────────────────────────

  const { data: tasksRaw, isLoading: tasksLoading, refetch: refetchTasks } = useQuery({
    queryKey: ['remediation-tasks'],
    queryFn: () => remediationApi.getTasks(),
    refetchInterval: 30000,
  });

  const { data: metricsRaw, isLoading: metricsLoading } = useQuery({
    queryKey: ['remediation-metrics'],
    queryFn: remediationApi.getMetrics,
    retry: 1,
  });

  const { data: autofixStats } = useQuery({
    queryKey: ['autofix-stats'],
    queryFn: () => api.get('/api/v1/autofix/health').then(r => r.data),
    retry: 1,
  });

  // ── Normalize data ────────────────────────────────────────────────────────

  const tasks: RemediationTask[] = (() => {
    if (Array.isArray(tasksRaw)) return tasksRaw as RemediationTask[];
    const d = (tasksRaw ?? {}) as Record<string, unknown>;
    if (Array.isArray(d.tasks)) return d.tasks as RemediationTask[];
    if (Array.isArray(d.items)) return d.items as RemediationTask[];
    return [];
  })();

  const metrics = (metricsRaw ?? {}) as Record<string, number | string | undefined>;

  const allTasks: RemediationTask[] = [
    ...localRemediations.map((r): RemediationTask => ({
      id: r.id,
      cve: r.cve,
      title: r.title,
      status: r.status,
      severity: r.severity,
      fix: r.fix,
      pr_url: r.prUrl,
    })),
    ...tasks,
  ];

  // ── Stats (from real API metrics + combined tasks) ────────────────────────

  const pendingCount = Number(metrics.pending_count ?? metrics.pending ?? allTasks.filter(t => t.status === 'pending').length);
  const inProgressCount = Number(metrics.in_progress_count ?? metrics.in_progress ?? allTasks.filter(t => t.status === 'in-progress' || t.status === 'in_progress').length);
  const completedCount = Number(metrics.completed_count ?? metrics.completed ?? allTasks.filter(t => t.status === 'completed' || t.status === 'resolved').length);
  const prCount = Number(metrics.prs_created ?? allTasks.filter(t => t.pr_url || t.prUrl).length);
  const mttrHours = Number(metrics.mttr_hours ?? metrics.mttr ?? 0);
  const slaCompliance = Number(metrics.sla_compliance_pct ?? metrics.sla_compliance ?? 0);

  // ── Mutations ─────────────────────────────────────────────────────────────

  const generateMutation = useMutation({
    mutationFn: async (cve: string) => remediationApi.generateFix(cve),
    onSuccess: (data, cve) => {
      const newRemediation: LocalRemediation = {
        id: crypto.randomUUID(),
        cve,
        title: `Fix for ${cve}`,
        status: 'completed',
        severity: 'high',
        fix: data.fix || data.code || data.remediation || data.result || JSON.stringify(data, null, 2),
      };
      setLocalRemediations((prev) => [newRemediation, ...prev]);
      toast.success('Remediation generated', { description: `Fix code generated for ${cve}` });
    },
    onError: (error: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error('Failed to generate fix', { description: error.response?.data?.detail || error.message });
    },
  });

  const prMutation = useMutation({
    mutationFn: async (remediation: LocalRemediation) =>
      remediationApi.createPR({ cve: remediation.cve || '', fix: remediation.fix || '', title: remediation.title }),
    onSuccess: (data, remediation) => {
      setLocalRemediations((prev) =>
        prev.map((r) => r.id === remediation.id ? { ...r, prUrl: data.pr_url || data.url, status: 'in-progress' as const } : r)
      );
      toast.success('Pull request created', { description: 'PR opened for review' });
    },
    onError: (error: Error & { response?: { data?: { detail?: string } } }) => {
      toast.error('Failed to create PR', { description: error.response?.data?.detail || error.message });
    },
  });

  const handleGenerate = () => {
    if (!selectedCve.trim()) { toast.error('Enter a CVE ID'); return; }
    generateMutation.mutate(selectedCve.trim());
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const handleRefresh = () => {
    refetchTasks();
    queryClient.invalidateQueries({ queryKey: ['remediation-metrics'] });
    toast.success('Remediation data refreshed');
  };

  const getStatusBadge = (status: string) => {
    const variants: Record<string, 'secondary' | 'medium' | 'default' | 'critical'> = {
      pending: 'secondary', 'in-progress': 'medium', in_progress: 'medium',
      completed: 'default', resolved: 'default', failed: 'critical',
    };
    return <Badge variant={variants[status] || 'secondary'}>{status.replace('_', '-')}</Badge>;
  };

  const templates = [
    { id: 'dependency-upgrade', name: 'Dependency Upgrade', description: 'Upgrade vulnerable package to patched version', icon: Package },
    { id: 'code-fix', name: 'Code Fix', description: 'Apply secure coding pattern to fix vulnerability', icon: FileCode },
    { id: 'config-change', name: 'Configuration Change', description: 'Update security configuration settings', icon: Wrench },
  ];

  if (tasksLoading && metricsLoading) return <RemediationSkeleton />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Wrench className="w-8 h-8 text-primary" />
            Remediation Center
          </h1>
          <p className="text-muted-foreground mt-1">AI-powered fix generation and deployment — {allTasks.length} tasks tracked</p>
        </div>
        <Button variant="outline" onClick={handleRefresh} className="gap-2"><RefreshCw className="w-4 h-4" /> Refresh</Button>
      </motion.div>

      {/* Stats */}
      <motion.div variants={containerVariants} initial="hidden" animate="visible" className="grid grid-cols-1 md:grid-cols-6 gap-4">
        <motion.div variants={itemVariants}><Card className="glass-card"><CardContent className="pt-6"><Clock className="w-6 h-6 text-yellow-500 mb-2" /><h3 className="text-2xl font-bold">{pendingCount}</h3><p className="text-sm text-muted-foreground">Pending</p></CardContent></Card></motion.div>
        <motion.div variants={itemVariants}><Card className="glass-card"><CardContent className="pt-6"><Play className="w-6 h-6 text-blue-500 mb-2" /><h3 className="text-2xl font-bold">{inProgressCount}</h3><p className="text-sm text-muted-foreground">In Progress</p></CardContent></Card></motion.div>
        <motion.div variants={itemVariants}><Card className="glass-card"><CardContent className="pt-6"><CheckCircle2 className="w-6 h-6 text-green-500 mb-2" /><h3 className="text-2xl font-bold">{completedCount}</h3><p className="text-sm text-muted-foreground">Completed</p></CardContent></Card></motion.div>
        <motion.div variants={itemVariants}><Card className="glass-card"><CardContent className="pt-6"><GitPullRequest className="w-6 h-6 text-purple-500 mb-2" /><h3 className="text-2xl font-bold">{prCount}</h3><p className="text-sm text-muted-foreground">PRs Created</p></CardContent></Card></motion.div>
        <motion.div variants={itemVariants}><Card className="glass-card"><CardContent className="pt-6"><TrendingDown className="w-6 h-6 text-cyan-500 mb-2" /><h3 className="text-2xl font-bold">{mttrHours > 0 ? `${mttrHours < 24 ? `${Math.round(mttrHours)}h` : `${(mttrHours / 24).toFixed(1)}d`}` : 'N/A'}</h3><p className="text-sm text-muted-foreground">MTTR</p></CardContent></Card></motion.div>
        <motion.div variants={itemVariants}><Card className="glass-card"><CardContent className="pt-6"><AlertTriangle className="w-6 h-6 text-orange-500 mb-2" /><h3 className="text-2xl font-bold">{slaCompliance > 0 ? `${slaCompliance}%` : 'N/A'}</h3><p className="text-sm text-muted-foreground">SLA Compliance</p></CardContent></Card></motion.div>
      </motion.div>

      {/* AutoFix Engine Status */}
      {autofixStats && (
        <Card className="glass-card border-primary/20">
          <CardContent className="py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-3 h-3 rounded-full ${autofixStats.status === 'healthy' ? 'bg-green-500 animate-pulse' : 'bg-yellow-500'}`} />
                <span className="font-medium">AutoFix Engine</span>
                <Badge variant="outline" className="text-xs">{autofixStats.status || 'Unknown'}</Badge>
              </div>
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                {autofixStats.fix_types && <span>{Object.keys(autofixStats.fix_types).length} fix types</span>}
                {autofixStats.total_fixes != null && <span>{autofixStats.total_fixes} total fixes</span>}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <Tabs defaultValue="generate" className="space-y-6">
        <TabsList>
          <TabsTrigger value="generate">Generate Fix</TabsTrigger>
          <TabsTrigger value="queue">Task Queue ({allTasks.length})</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>

        {/* Generate Tab */}
        <TabsContent value="generate" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Code className="w-5 h-5 text-primary" /> AI Fix Generator</CardTitle>
              <CardDescription>Generate remediation code for vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input placeholder="Enter CVE ID (e.g., CVE-2024-3400)" value={selectedCve} onChange={(e) => setSelectedCve(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleGenerate()} className="flex-1" />
                <Button onClick={handleGenerate} disabled={generateMutation.isPending} className="gap-2">
                  {generateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Code className="w-4 h-4" />}
                  Generate Fix
                </Button>
              </div>
              <div className="flex flex-wrap gap-2">
                <span className="text-sm text-muted-foreground">Quick select:</span>
                {['CVE-2024-3400', 'CVE-2024-21887', 'CVE-2023-46805'].map((cve) => (
                  <Badge key={cve} variant="outline" className="cursor-pointer hover:bg-primary/10" onClick={() => setSelectedCve(cve)}>{cve}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>

          {localRemediations.filter(r => r.fix).length > 0 && (
            <Card className="glass-card">
              <CardHeader><CardTitle>Generated Fixes</CardTitle></CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  <div className="space-y-4">
                    {localRemediations.filter(r => r.fix).map((remediation, index) => (
                      <motion.div key={remediation.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.1 }}
                        className="p-4 rounded-lg border border-border bg-muted/30">
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h4 className="font-medium">{remediation.title}</h4>
                            {remediation.cve && <Badge variant="outline" className="mt-1">{remediation.cve}</Badge>}
                          </div>
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline" onClick={() => copyToClipboard(remediation.fix!)}><Copy className="w-3 h-3 mr-1" /> Copy</Button>
                            <Button size="sm" onClick={() => prMutation.mutate(remediation)} disabled={prMutation.isPending || !!remediation.prUrl}>
                              <GitPullRequest className="w-3 h-3 mr-1" />{remediation.prUrl ? 'PR Created' : 'Create PR'}
                            </Button>
                          </div>
                        </div>
                        <div className="rounded bg-background/50 p-3 font-mono text-sm overflow-x-auto"><pre className="whitespace-pre-wrap">{remediation.fix}</pre></div>
                        {remediation.prUrl && (
                          <div className="mt-3 flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-green-500" />
                            <a href={remediation.prUrl} target="_blank" rel="noopener noreferrer" className="text-sm text-primary hover:underline flex items-center gap-1">
                              View Pull Request <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        )}
                      </motion.div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Queue Tab */}
        <TabsContent value="queue" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Remediation Task Queue</CardTitle>
              <CardDescription>Backend tasks ({tasks.length}) + locally generated ({localRemediations.length})</CardDescription>
            </CardHeader>
            <CardContent>
              {tasksLoading ? (
                <div className="space-y-3">{[1, 2, 3].map(i => <div key={i} className="h-16 bg-gray-700/20 rounded-lg animate-pulse" />)}</div>
              ) : allTasks.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Wrench className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No remediation tasks</p>
                  <p className="text-sm">Generate a fix or create tasks via the API</p>
                </div>
              ) : (
                <ScrollArea className="h-[500px]">
                  <div className="space-y-3">
                    {allTasks.map((item, index) => (
                      <motion.div key={item.id || index} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: Math.min(index * 0.03, 0.5) }}
                        className="flex items-center justify-between p-4 rounded-lg border border-border bg-muted/30">
                        <div className="flex items-center gap-4">
                          <div className={`w-2 h-2 rounded-full ${
                            item.status === 'completed' || item.status === 'resolved' ? 'bg-green-500' :
                            item.status === 'in-progress' || item.status === 'in_progress' ? 'bg-blue-500' :
                            item.status === 'failed' ? 'bg-red-500' : 'bg-yellow-500'
                          }`} />
                          <div>
                            <p className="font-medium">{item.title || item.name || `Task ${item.id}`}</p>
                            <div className="flex items-center gap-2 mt-1">
                              {(item.cve || item.cve_id) && <Badge variant="outline" className="font-mono text-xs">{item.cve || item.cve_id}</Badge>}
                              {item.severity && <Badge variant={item.severity === 'critical' ? 'critical' : item.severity === 'high' ? 'high' : 'medium'}>{item.severity}</Badge>}
                              {item.assignee && <span className="text-xs text-muted-foreground">→ {item.assignee}</span>}
                              {item.created_at && <span className="text-xs text-muted-foreground">{new Date(item.created_at).toLocaleDateString()}</span>}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {getStatusBadge(item.status)}
                          {(item.pr_url || item.prUrl) && (
                            <a href={item.pr_url || item.prUrl} target="_blank" rel="noopener noreferrer">
                              <Button size="sm" variant="outline"><ExternalLink className="w-3 h-3" /></Button>
                            </a>
                          )}
                        </div>
                      </motion.div>
                    ))}
                  </div>
                </ScrollArea>
              )}

              {(mttrHours > 0 || slaCompliance > 0) && (
                <div className="mt-6 pt-6 border-t border-border grid grid-cols-2 gap-6">
                  {mttrHours > 0 && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm"><span className="text-muted-foreground">Mean Time to Remediate</span><span className="font-medium">{mttrHours < 24 ? `${Math.round(mttrHours)}h` : `${(mttrHours / 24).toFixed(1)}d`}</span></div>
                      <Progress value={Math.min(100, (mttrHours / 168) * 100)} className="h-2" />
                    </div>
                  )}
                  {slaCompliance > 0 && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm"><span className="text-muted-foreground">SLA Compliance</span><span className="font-medium">{slaCompliance}%</span></div>
                      <Progress value={slaCompliance} className="h-2" />
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Templates Tab */}
        <TabsContent value="templates" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Remediation Templates</CardTitle>
              <CardDescription>Pre-built fix patterns for common vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {templates.map((template, index) => {
                  const Icon = template.icon;
                  return (
                    <motion.div key={template.id} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.1 }}>
                      <Card className="glass-card hover:border-primary/30 transition-colors cursor-pointer">
                        <CardContent className="pt-6">
                          <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4"><Icon className="w-6 h-6 text-primary" /></div>
                          <h4 className="font-semibold">{template.name}</h4>
                          <p className="text-sm text-muted-foreground mt-1">{template.description}</p>
                        </CardContent>
                      </Card>
                    </motion.div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
