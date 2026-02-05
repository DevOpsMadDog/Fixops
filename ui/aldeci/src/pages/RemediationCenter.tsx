import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
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
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { ScrollArea } from '../components/ui/scroll-area';
import { remediationApi } from '../lib/api';
import { toast } from 'sonner';

interface RemediationItem {
  id: string;
  cve?: string;
  title: string;
  status: 'pending' | 'in-progress' | 'completed' | 'failed';
  severity: string;
  fix?: string;
  prUrl?: string;
}

export default function RemediationCenter() {
  const [selectedCve, setSelectedCve] = useState('');
  const [remediations, setRemediations] = useState<RemediationItem[]>([]);

  // Generate remediation mutation
  const generateMutation = useMutation({
    mutationFn: async (cve: string) => {
      return remediationApi.generateFix(cve);
    },
    onSuccess: (data, cve) => {
      const newRemediation: RemediationItem = {
        id: crypto.randomUUID(),
        cve,
        title: `Fix for ${cve}`,
        status: 'completed',
        severity: 'high',
        fix: data.fix || data.code || data.remediation,
      };
      setRemediations((prev) => [newRemediation, ...prev]);
      toast.success('Remediation generated', {
        description: `Fix code generated for ${cve}`,
      });
    },
    onError: (error: any) => {
      toast.error('Failed to generate fix', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  // Create PR mutation
  const prMutation = useMutation({
    mutationFn: async (remediation: RemediationItem) => {
      return remediationApi.createPR({
        cve: remediation.cve || '',
        fix: remediation.fix || '',
        title: remediation.title,
      });
    },
    onSuccess: (data, remediation) => {
      setRemediations((prev) =>
        prev.map((r) =>
          r.id === remediation.id
            ? { ...r, prUrl: data.pr_url || data.url, status: 'in-progress' }
            : r
        )
      );
      toast.success('Pull request created', {
        description: 'PR opened for review',
      });
    },
    onError: (error: any) => {
      toast.error('Failed to create PR', {
        description: error.response?.data?.detail || error.message,
      });
    },
  });

  const handleGenerate = () => {
    if (!selectedCve.trim()) {
      toast.error('Enter a CVE ID');
      return;
    }
    generateMutation.mutate(selectedCve.trim());
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const getStatusBadge = (status: RemediationItem['status']) => {
    const variants = {
      pending: 'secondary',
      'in-progress': 'medium',
      completed: 'default',
      failed: 'critical',
    } as const;
    return <Badge variant={variants[status]}>{status}</Badge>;
  };

  // Sample remediation templates
  const templates = [
    {
      id: 'dependency-upgrade',
      name: 'Dependency Upgrade',
      description: 'Upgrade vulnerable package to patched version',
      icon: Package,
    },
    {
      id: 'code-fix',
      name: 'Code Fix',
      description: 'Apply secure coding pattern to fix vulnerability',
      icon: FileCode,
    },
    {
      id: 'config-change',
      name: 'Configuration Change',
      description: 'Update security configuration settings',
      icon: Wrench,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Wrench className="w-8 h-8 text-primary" />
            Remediation Center
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered fix generation and deployment
          </p>
        </div>
        <Button variant="outline" className="gap-2">
          <RefreshCw className="w-4 h-4" />
          Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <Clock className="w-6 h-6 text-yellow-500" />
            </div>
            <h3 className="text-2xl font-bold">{remediations.filter(r => r.status === 'pending').length}</h3>
            <p className="text-sm text-muted-foreground">Pending</p>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <Play className="w-6 h-6 text-blue-500" />
            </div>
            <h3 className="text-2xl font-bold">{remediations.filter(r => r.status === 'in-progress').length}</h3>
            <p className="text-sm text-muted-foreground">In Progress</p>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <CheckCircle2 className="w-6 h-6 text-green-500" />
            </div>
            <h3 className="text-2xl font-bold">{remediations.filter(r => r.status === 'completed').length}</h3>
            <p className="text-sm text-muted-foreground">Completed</p>
          </CardContent>
        </Card>

        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between mb-2">
              <GitPullRequest className="w-6 h-6 text-purple-500" />
            </div>
            <h3 className="text-2xl font-bold">{remediations.filter(r => r.prUrl).length}</h3>
            <p className="text-sm text-muted-foreground">PRs Created</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="generate" className="space-y-6">
        <TabsList>
          <TabsTrigger value="generate">Generate Fix</TabsTrigger>
          <TabsTrigger value="queue">Remediation Queue</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>

        {/* Generate Tab */}
        <TabsContent value="generate" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Code className="w-5 h-5 text-primary" />
                AI Fix Generator
              </CardTitle>
              <CardDescription>
                Generate remediation code for vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Input
                  placeholder="Enter CVE ID (e.g., CVE-2024-3400)"
                  value={selectedCve}
                  onChange={(e) => setSelectedCve(e.target.value)}
                  className="flex-1"
                />
                <Button
                  onClick={handleGenerate}
                  disabled={generateMutation.isPending}
                  className="gap-2"
                >
                  {generateMutation.isPending ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Code className="w-4 h-4" />
                  )}
                  Generate Fix
                </Button>
              </div>

              {/* Quick CVE selection */}
              <div className="flex flex-wrap gap-2">
                <span className="text-sm text-muted-foreground">Quick select:</span>
                {['CVE-2024-3400', 'CVE-2024-21887', 'CVE-2023-46805'].map((cve) => (
                  <Badge
                    key={cve}
                    variant="outline"
                    className="cursor-pointer hover:bg-primary/10"
                    onClick={() => setSelectedCve(cve)}
                  >
                    {cve}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Generated Fixes */}
          {remediations.filter(r => r.fix).length > 0 && (
            <Card className="glass-card">
              <CardHeader>
                <CardTitle>Generated Fixes</CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[400px]">
                  <div className="space-y-4">
                    {remediations.filter(r => r.fix).map((remediation, index) => (
                      <motion.div
                        key={remediation.id}
                        initial={{ opacity: 0, y: 20 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.1 }}
                        className="p-4 rounded-lg border border-border bg-muted/30"
                      >
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h4 className="font-medium">{remediation.title}</h4>
                            {remediation.cve && (
                              <Badge variant="outline" className="mt-1">
                                {remediation.cve}
                              </Badge>
                            )}
                          </div>
                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => copyToClipboard(remediation.fix!)}
                            >
                              <Copy className="w-3 h-3 mr-1" />
                              Copy
                            </Button>
                            <Button
                              size="sm"
                              onClick={() => prMutation.mutate(remediation)}
                              disabled={prMutation.isPending || !!remediation.prUrl}
                            >
                              <GitPullRequest className="w-3 h-3 mr-1" />
                              {remediation.prUrl ? 'PR Created' : 'Create PR'}
                            </Button>
                          </div>
                        </div>
                        
                        <div className="rounded bg-background/50 p-3 font-mono text-sm overflow-x-auto">
                          <pre className="whitespace-pre-wrap">{remediation.fix}</pre>
                        </div>

                        {remediation.prUrl && (
                          <div className="mt-3 flex items-center gap-2">
                            <CheckCircle2 className="w-4 h-4 text-green-500" />
                            <a
                              href={remediation.prUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-sm text-primary hover:underline flex items-center gap-1"
                            >
                              View Pull Request
                              <ExternalLink className="w-3 h-3" />
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
              <CardTitle>Remediation Queue</CardTitle>
              <CardDescription>
                Track the status of all remediation efforts
              </CardDescription>
            </CardHeader>
            <CardContent>
              {remediations.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Wrench className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No remediations in queue</p>
                  <p className="text-sm">Generate a fix to get started</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {remediations.map((item, index) => (
                    <motion.div
                      key={item.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.05 }}
                      className="flex items-center justify-between p-4 rounded-lg border border-border bg-muted/30"
                    >
                      <div className="flex items-center gap-4">
                        <div className={`w-2 h-2 rounded-full ${
                          item.status === 'completed' ? 'bg-green-500' :
                          item.status === 'in-progress' ? 'bg-blue-500' :
                          item.status === 'failed' ? 'bg-red-500' : 'bg-yellow-500'
                        }`} />
                        <div>
                          <p className="font-medium">{item.title}</p>
                          {item.cve && (
                            <p className="text-sm text-muted-foreground">{item.cve}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {getStatusBadge(item.status)}
                        {item.prUrl && (
                          <a
                            href={item.prUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <Button size="sm" variant="outline">
                              <ExternalLink className="w-3 h-3" />
                            </Button>
                          </a>
                        )}
                      </div>
                    </motion.div>
                  ))}
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
              <CardDescription>
                Pre-built fix patterns for common vulnerabilities
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {templates.map((template, index) => {
                  const Icon = template.icon;
                  return (
                    <motion.div
                      key={template.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: index * 0.1 }}
                    >
                      <Card className="glass-card hover:border-primary/30 transition-colors cursor-pointer">
                        <CardContent className="pt-6">
                          <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
                            <Icon className="w-6 h-6 text-primary" />
                          </div>
                          <h4 className="font-semibold">{template.name}</h4>
                          <p className="text-sm text-muted-foreground mt-1">
                            {template.description}
                          </p>
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
