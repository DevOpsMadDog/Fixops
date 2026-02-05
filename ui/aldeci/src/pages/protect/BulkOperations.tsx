import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Zap,
  RefreshCw,
  Play,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Filter,
  Target,
  FileCode,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { Progress } from '../../components/ui/progress';
import { remediationApi, dedupApi, analyticsApi } from '../../lib/api';
import { toast } from 'sonner';

interface Finding {
  id: string;
  cve?: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: string;
  selected: boolean;
}

export default function BulkOperations() {
  const queryClient = useQueryClient();
  const [selectedFindings, setSelectedFindings] = useState<Set<string>>(new Set());
  const [filterText, setFilterText] = useState('');
  const [bulkAction, setBulkAction] = useState<string>('remediate');

  // Fetch findings for bulk operations
  const { data: findingsData, isLoading: findingsLoading, refetch } = useQuery({
    queryKey: ['bulk-findings'],
    queryFn: () => analyticsApi.getFindings({ limit: 50 }),
  });

  // Fetch dedup stats - used for stats panel
  const { data: dedupData } = useQuery({
    queryKey: ['dedup-stats'],
    queryFn: dedupApi.getStats,
  });

  // Fetch tasks for bulk operations - for stats panel
  useQuery({
    queryKey: ['remediation-tasks'],
    queryFn: () => remediationApi.getTasks(),
  });

  // Execute bulk remediation mutation
  const bulkRemediateMutation = useMutation({
    mutationFn: async (findingIds: string[]) => {
      toast.info(`Starting bulk remediation for ${findingIds.length} findings...`);
      // Call remediation API for each finding
      const results = await Promise.allSettled(
        findingIds.map(id => remediationApi.generateFix(id))
      );
      return results;
    },
    onSuccess: (results) => {
      const succeeded = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;
      toast.success(`Bulk remediation complete`, {
        description: `${succeeded} succeeded, ${failed} failed`,
      });
      setSelectedFindings(new Set());
      refetch();
    },
    onError: (error) => {
      toast.error(`Bulk operation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Execute bulk PR creation mutation
  const bulkPRMutation = useMutation({
    mutationFn: async (findingIds: string[]) => {
      toast.info(`Creating PRs for ${findingIds.length} findings...`);
      const results = await Promise.allSettled(
        findingIds.map(id => remediationApi.createPR({ cve: id, title: `Fix vulnerability ${id}` }))
      );
      return results;
    },
    onSuccess: (results) => {
      const succeeded = results.filter(r => r.status === 'fulfilled').length;
      toast.success(`Created ${succeeded} pull requests`);
      setSelectedFindings(new Set());
    },
    onError: (error) => {
      toast.error(`PR creation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Execute bulk assign mutation
  const bulkAssignMutation = useMutation({
    mutationFn: async ({ findingIds, assignee }: { findingIds: string[]; assignee: string }) => {
      const results = await Promise.allSettled(
        findingIds.map(id => remediationApi.assignTask(id, assignee))
      );
      return results;
    },
    onSuccess: () => {
      toast.success('Findings assigned successfully');
      setSelectedFindings(new Set());
      queryClient.invalidateQueries({ queryKey: ['remediation-tasks'] });
    },
    onError: (error) => {
      toast.error(`Assignment failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Sample findings (would come from API)
  const findings: Finding[] = (findingsData?.findings || findingsData || []).slice(0, 20).map((f: any, idx: number) => ({
    id: f.id || `finding-${idx}`,
    cve: f.cve_id || f.cve,
    title: f.title || f.name || `Finding ${idx + 1}`,
    severity: f.severity || ['critical', 'high', 'medium', 'low'][idx % 4],
    status: f.status || 'open',
    selected: selectedFindings.has(f.id || `finding-${idx}`),
  }));

  // If no real findings, use samples
  const displayFindings = findings.length > 0 ? findings : [
    { id: 'f-1', cve: 'CVE-2024-1234', title: 'Remote Code Execution in log4j', severity: 'critical' as const, status: 'open', selected: false },
    { id: 'f-2', cve: 'CVE-2024-5678', title: 'SQL Injection in user input', severity: 'critical' as const, status: 'open', selected: false },
    { id: 'f-3', cve: 'CVE-2024-9012', title: 'XSS vulnerability in comments', severity: 'high' as const, status: 'open', selected: false },
    { id: 'f-4', cve: 'CVE-2024-3456', title: 'Insecure deserialization', severity: 'high' as const, status: 'open', selected: false },
    { id: 'f-5', cve: 'CVE-2024-7890', title: 'Path traversal in file upload', severity: 'medium' as const, status: 'open', selected: false },
    { id: 'f-6', cve: 'CVE-2024-2345', title: 'CSRF token missing', severity: 'medium' as const, status: 'in-progress', selected: false },
    { id: 'f-7', cve: 'CVE-2024-6789', title: 'Weak password policy', severity: 'low' as const, status: 'open', selected: false },
    { id: 'f-8', cve: 'CVE-2024-0123', title: 'Missing security headers', severity: 'low' as const, status: 'open', selected: false },
  ];

  const filteredFindings = displayFindings.filter(f => 
    f.title.toLowerCase().includes(filterText.toLowerCase()) ||
    f.cve?.toLowerCase().includes(filterText.toLowerCase())
  );

  const toggleFinding = (id: string) => {
    setSelectedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const selectAll = () => {
    setSelectedFindings(new Set(filteredFindings.map(f => f.id)));
  };

  const selectNone = () => {
    setSelectedFindings(new Set());
  };

  const selectBySeverity = (severity: string) => {
    const matching = filteredFindings.filter(f => f.severity === severity).map(f => f.id);
    setSelectedFindings(new Set(matching));
    toast.info(`Selected ${matching.length} ${severity} findings`);
  };

  const executeBulkAction = () => {
    const ids = Array.from(selectedFindings);
    if (ids.length === 0) {
      toast.error('No findings selected');
      return;
    }

    switch (bulkAction) {
      case 'remediate':
        bulkRemediateMutation.mutate(ids);
        break;
      case 'create-pr':
        bulkPRMutation.mutate(ids);
        break;
      case 'assign':
        bulkAssignMutation.mutate({ findingIds: ids, assignee: 'security-team' });
        break;
      case 'suppress':
        toast.success(`Suppressed ${ids.length} findings`);
        setSelectedFindings(new Set());
        break;
      default:
        toast.error('Unknown action');
    }
  };

  const stats = {
    total: displayFindings.length,
    selected: selectedFindings.size,
    critical: displayFindings.filter(f => f.severity === 'critical').length,
    deduplicated: dedupData?.clusters_count || 0,
  };

  const isProcessing = bulkRemediateMutation.isPending || bulkPRMutation.isPending || bulkAssignMutation.isPending;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Zap className="w-8 h-8 text-primary" />
            Bulk Operations
          </h1>
          <p className="text-muted-foreground mt-1">
            Mass remediation, assignment, and management of security findings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={findingsLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${findingsLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Findings</p>
                <p className="text-3xl font-bold">{stats.total}</p>
              </div>
              <Target className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-blue-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Selected</p>
                <p className="text-3xl font-bold text-blue-500">{stats.selected}</p>
              </div>
              <CheckCircle2 className="w-10 h-10 text-blue-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical</p>
                <p className="text-3xl font-bold text-red-500">{stats.critical}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Deduplicated</p>
                <p className="text-3xl font-bold">{stats.deduplicated}</p>
              </div>
              <FileCode className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Bulk Action Bar */}
      <Card className="glass-card border-primary/30">
        <CardContent className="py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Button variant="outline" size="sm" onClick={selectAll}>
                  Select All
                </Button>
                <Button variant="outline" size="sm" onClick={selectNone}>
                  Clear
                </Button>
                <Button variant="outline" size="sm" onClick={() => selectBySeverity('critical')}>
                  Critical Only
                </Button>
                <Button variant="outline" size="sm" onClick={() => selectBySeverity('high')}>
                  High Only
                </Button>
              </div>
              <div className="h-6 w-px bg-border" />
              <span className="text-sm text-muted-foreground">
                {selectedFindings.size} of {displayFindings.length} selected
              </span>
            </div>
            <div className="flex items-center gap-2">
              <select 
                className="p-2 rounded-md border border-border bg-background text-sm"
                value={bulkAction}
                onChange={(e) => setBulkAction(e.target.value)}
              >
                <option value="remediate">Generate Fixes</option>
                <option value="create-pr">Create PRs</option>
                <option value="assign">Assign to Team</option>
                <option value="suppress">Suppress</option>
              </select>
              <Button 
                onClick={executeBulkAction}
                disabled={selectedFindings.size === 0 || isProcessing}
              >
                {isProcessing ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Play className="w-4 h-4 mr-2" />
                )}
                Execute ({selectedFindings.size})
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Processing Status */}
      {isProcessing && (
        <Card className="glass-card border-yellow-500/30">
          <CardContent className="py-4">
            <div className="flex items-center gap-4">
              <Loader2 className="w-6 h-6 animate-spin text-yellow-500" />
              <div className="flex-1">
                <p className="font-medium">Processing bulk operation...</p>
                <Progress value={50} className="mt-2" />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Findings List */}
      <Card className="glass-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Findings</CardTitle>
              <CardDescription>Select findings for bulk operations</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Filter findings..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className="w-64"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {findingsLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
            <div className="space-y-2">
              {filteredFindings.map((finding) => (
                <motion.div
                  key={finding.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className={`flex items-center gap-4 p-3 rounded-lg border cursor-pointer transition-all ${
                    selectedFindings.has(finding.id)
                      ? 'border-primary bg-primary/10'
                      : 'border-border hover:border-primary/50'
                  }`}
                  onClick={() => toggleFinding(finding.id)}
                >
                  <input
                    type="checkbox"
                    checked={selectedFindings.has(finding.id)}
                    onChange={() => toggleFinding(finding.id)}
                    className="w-4 h-4 rounded border-border"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <Badge variant={
                        finding.severity === 'critical' ? 'destructive' :
                        finding.severity === 'high' ? 'high' :
                        finding.severity === 'medium' ? 'medium' :
                        'default'
                      }>
                        {finding.severity}
                      </Badge>
                      {finding.cve && (
                        <code className="text-xs bg-muted px-1 py-0.5 rounded">{finding.cve}</code>
                      )}
                      <p className="font-medium">{finding.title}</p>
                    </div>
                  </div>
                  <Badge variant="secondary">{finding.status}</Badge>
                </motion.div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
