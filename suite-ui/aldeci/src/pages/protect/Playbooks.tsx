import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  ClipboardList,
  Play,
  Pause,
  Plus,
  RefreshCw,
  CheckCircle2,
  Clock,
  Loader2,
  Trash2,
  Copy,
  Settings,
  Zap,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { workflowsApi, automationApi } from '../../lib/api';
import { toast } from 'sonner';

interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: string;
  status: 'active' | 'paused' | 'draft';
  lastRun?: string;
  runCount: number;
  actions: string[];
}

export default function Playbooks() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);
  const [newPlaybookName, setNewPlaybookName] = useState('');
  const [newPlaybookTrigger, setNewPlaybookTrigger] = useState('critical_vulnerability');

  // Fetch workflows/playbooks
  const { data: workflowsData, isLoading, refetch } = useQuery({
    queryKey: ['workflows'],
    queryFn: workflowsApi.list,
  });

  // Fetch automation rules
  const { data: rulesData } = useQuery({
    queryKey: ['automation-rules'],
    queryFn: automationApi.getRules,
  });

  // Create playbook mutation
  const createMutation = useMutation({
    mutationFn: async (data: { name: string; trigger: string }) => {
      return workflowsApi.create({
        name: data.name,
        trigger: data.trigger,
        actions: [],
        enabled: true,
      });
    },
    onSuccess: () => {
      toast.success('Playbook created successfully!');
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
      setShowCreateModal(false);
      setNewPlaybookName('');
    },
    onError: (error) => {
      toast.error(`Failed to create playbook: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Execute playbook mutation
  const executeMutation = useMutation({
    mutationFn: async (playbookId: string) => {
      return workflowsApi.execute(playbookId);
    },
    onSuccess: (_, playbookId) => {
      toast.success(`Playbook "${playbookId}" executed!`, {
        description: 'Check the execution logs for results.',
      });
      refetch();
    },
    onError: (error) => {
      toast.error(`Execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Toggle playbook status mutation
  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      return workflowsApi.update(id, { enabled });
    },
    onSuccess: (_, { enabled }) => {
      toast.success(enabled ? 'Playbook activated' : 'Playbook paused');
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
    },
    onError: (error) => {
      toast.error(`Failed to update playbook: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Delete playbook mutation
  const deleteMutation = useMutation({
    mutationFn: async (playbookId: string) => {
      return workflowsApi.delete(playbookId);
    },
    onSuccess: () => {
      toast.success('Playbook deleted');
      queryClient.invalidateQueries({ queryKey: ['workflows'] });
    },
    onError: (error) => {
      toast.error(`Delete failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Extract playbooks from API response - zero mock data
  const rawData = workflowsData?.items || workflowsData?.workflows || (Array.isArray(workflowsData) ? workflowsData : []);
  const playbooks: Playbook[] = (Array.isArray(rawData) ? rawData : []).map((w: { id?: string; workflow_id?: string; name?: string; description?: string; trigger?: string; trigger_type?: string; status?: string; enabled?: boolean; last_run?: string; last_executed?: string; run_count?: number; execution_count?: number; actions?: string[]; steps?: { name?: string; type?: string }[] }, idx: number) => ({
    id: w.id || w.workflow_id || `pb-${idx}-${(w.name || 'playbook').slice(0, 8).replace(/\s/g, '-')}`,
    name: w.name || 'Unnamed Playbook',
    description: w.description || '',
    trigger: w.trigger || w.trigger_type || 'manual',
    status: (w.status === 'active' || w.enabled) ? 'active' : w.status === 'draft' ? 'draft' : 'paused',
    lastRun: w.last_run || w.last_executed || undefined,
    runCount: w.run_count || w.execution_count || 0,
    actions: w.actions || w.steps?.map((s) => s.name || s.type || '') || [],
  }));

  const stats = {
    total: playbooks.length,
    active: playbooks.filter(p => p.status === 'active').length,
    paused: playbooks.filter(p => p.status === 'paused').length,
    totalRuns: playbooks.reduce((sum, p) => sum + p.runCount, 0),
  };

  const triggerTypes = [
    { value: 'critical_vulnerability', label: 'Critical Vulnerability Detected' },
    { value: 'kev_detected', label: 'KEV Vulnerability Found' },
    { value: 'sbom_violation', label: 'SBOM Policy Violation' },
    { value: 'high_epss', label: 'High EPSS Score (>0.7)' },
    { value: 'new_finding', label: 'New Finding Ingested' },
    { value: 'schedule_daily', label: 'Daily Schedule' },
    { value: 'schedule_weekly', label: 'Weekly Schedule' },
    { value: 'manual', label: 'Manual Trigger Only' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <ClipboardList className="w-8 h-8 text-primary" />
            Playbooks & Campaigns
          </h1>
          <p className="text-muted-foreground mt-1">
            Automated security workflows and response playbooks
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button onClick={() => setShowCreateModal(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Create Playbook
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Playbooks</p>
                <p className="text-3xl font-bold">{stats.total}</p>
              </div>
              <ClipboardList className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-green-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active</p>
                <p className="text-3xl font-bold text-green-500">{stats.active}</p>
              </div>
              <CheckCircle2 className="w-10 h-10 text-green-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-yellow-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Paused</p>
                <p className="text-3xl font-bold text-yellow-500">{stats.paused}</p>
              </div>
              <Pause className="w-10 h-10 text-yellow-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Executions</p>
                <p className="text-3xl font-bold">{stats.totalRuns}</p>
              </div>
              <Zap className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Automation Rules Summary */}
      {rulesData && (
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Settings className="w-5 h-5" />
              Automation Rules
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold">{rulesData?.rules?.length || 0}</p>
                <p className="text-sm text-muted-foreground">Total Rules</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-green-500">
                  {rulesData?.rules?.filter((r: { enabled?: boolean }) => r.enabled)?.length || 0}
                </p>
                <p className="text-sm text-muted-foreground">Enabled</p>
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {rulesData?.executions_today || 0}
                </p>
                <p className="text-sm text-muted-foreground">Runs Today</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Playbooks List */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Your Playbooks</CardTitle>
          <CardDescription>Click to view details or use actions to manage</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : playbooks.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <ClipboardList className="w-16 h-16 text-muted-foreground/30 mb-4" />
              <h3 className="text-lg font-semibold text-muted-foreground mb-2">No Playbooks Yet</h3>
              <p className="text-sm text-muted-foreground/70 max-w-md mb-4">
                Create automated response playbooks to handle security events. Playbooks can auto-create tickets,
                send alerts, and trigger remediation workflows.
              </p>
              <Button onClick={() => setShowCreateModal(true)}>
                <Plus className="w-4 h-4 mr-2" />
                Create Your First Playbook
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              {playbooks.map((playbook) => (
                <motion.div
                  key={playbook.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-4 rounded-lg border ${
                    selectedPlaybook === playbook.id 
                      ? 'border-primary bg-primary/5' 
                      : 'border-border hover:border-primary/50'
                  } transition-all cursor-pointer`}
                  onClick={() => setSelectedPlaybook(selectedPlaybook === playbook.id ? null : playbook.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className={`w-3 h-3 rounded-full ${
                        playbook.status === 'active' ? 'bg-green-500 animate-pulse' :
                        playbook.status === 'paused' ? 'bg-yellow-500' :
                        'bg-gray-500'
                      }`} />
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{playbook.name}</p>
                          <Badge variant={playbook.status === 'active' ? 'default' : 'secondary'}>
                            {playbook.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">{playbook.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right text-sm">
                        <p>{playbook.runCount} runs</p>
                        {playbook.lastRun && (
                          <p className="text-muted-foreground text-xs flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {playbook.lastRun}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-1">
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={(e) => {
                            e.stopPropagation();
                            executeMutation.mutate(playbook.id);
                          }}
                          disabled={executeMutation.isPending}
                          title="Run now"
                        >
                          {executeMutation.isPending ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <Play className="w-4 h-4 text-green-500" />
                          )}
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleMutation.mutate({ 
                              id: playbook.id, 
                              enabled: playbook.status !== 'active' 
                            });
                          }}
                          title={playbook.status === 'active' ? 'Pause' : 'Activate'}
                        >
                          {playbook.status === 'active' ? (
                            <Pause className="w-4 h-4 text-yellow-500" />
                          ) : (
                            <Play className="w-4 h-4" />
                          )}
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigator.clipboard.writeText(JSON.stringify(playbook, null, 2));
                            toast.success('Playbook config copied to clipboard');
                          }}
                          title="Copy config"
                        >
                          <Copy className="w-4 h-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (confirm('Delete this playbook?')) {
                              deleteMutation.mutate(playbook.id);
                            }
                          }}
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </Button>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Details */}
                  {selectedPlaybook === playbook.id && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      className="mt-4 pt-4 border-t border-border"
                    >
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-sm font-medium mb-2">Trigger</p>
                          <Badge variant="outline">{playbook.trigger}</Badge>
                        </div>
                        <div>
                          <p className="text-sm font-medium mb-2">Actions</p>
                          <div className="flex flex-wrap gap-1">
                            {playbook.actions.map((action, idx) => (
                              <Badge key={idx} variant="secondary" className="text-xs">
                                {action}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation();
                            toast.info('Opening playbook editor...');
                          }}
                        >
                          <Settings className="w-3 h-3 mr-1" />
                          Edit
                        </Button>
                        <Button 
                          size="sm"
                          onClick={(e) => {
                            e.stopPropagation();
                            executeMutation.mutate(playbook.id);
                          }}
                          disabled={executeMutation.isPending}
                        >
                          <Play className="w-3 h-3 mr-1" />
                          Run Now
                        </Button>
                      </div>
                    </motion.div>
                  )}
                </motion.div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Create Playbook Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-card border border-border rounded-lg p-6 w-full max-w-md"
          >
            <h2 className="text-xl font-bold mb-4">Create New Playbook</h2>
            
            <div className="space-y-4">
              <div>
                <label className="text-sm font-medium">Playbook Name</label>
                <Input 
                  placeholder="e.g., Critical CVE Response"
                  value={newPlaybookName}
                  onChange={(e) => setNewPlaybookName(e.target.value)}
                  className="mt-1"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Trigger</label>
                <select 
                  className="w-full mt-1 p-2 rounded-md border border-border bg-background"
                  value={newPlaybookTrigger}
                  onChange={(e) => setNewPlaybookTrigger(e.target.value)}
                >
                  {triggerTypes.map((trigger) => (
                    <option key={trigger.value} value={trigger.value}>
                      {trigger.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-6">
              <Button variant="outline" onClick={() => setShowCreateModal(false)}>
                Cancel
              </Button>
              <Button 
                onClick={() => createMutation.mutate({ 
                  name: newPlaybookName, 
                  trigger: newPlaybookTrigger 
                })}
                disabled={!newPlaybookName.trim() || createMutation.isPending}
              >
                {createMutation.isPending ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Plus className="w-4 h-4 mr-2" />
                )}
                Create Playbook
              </Button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
}
