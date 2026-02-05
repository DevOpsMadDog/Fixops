import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Key,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Eye,
  EyeOff,
  Loader2,
  Download,
  Lock,
  FileCode,
  GitBranch,
  Filter,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { secretsApi } from '../../lib/api';
import { toast } from 'sonner';

interface SecretFinding {
  id: string;
  type: string;
  file: string;
  line: number;
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'resolved' | 'false-positive';
  detected: string;
  repository?: string;
}

export default function SecretsDetection() {
  const queryClient = useQueryClient();
  const [filterText, setFilterText] = useState('');
  const [showValues, setShowValues] = useState<Set<string>>(new Set());
  const [scanContent, setScanContent] = useState('');

  // Fetch secrets
  const { data: secretsData, isLoading, refetch } = useQuery({
    queryKey: ['secrets'],
    queryFn: secretsApi.list,
  });

  // Fetch scanner status
  const { data: scannerStatus } = useQuery({
    queryKey: ['secrets-scanner-status'],
    queryFn: secretsApi.getScannersStatus,
  });

  // Scan content mutation
  const scanMutation = useMutation({
    mutationFn: async (content: string) => {
      return secretsApi.scanContent(content);
    },
    onSuccess: (data) => {
      const count = data?.secrets_found || data?.findings?.length || 0;
      if (count > 0) {
        toast.warning(`Found ${count} potential secrets!`, {
          description: 'Review and remediate immediately.',
        });
      } else {
        toast.success('No secrets detected in the provided content.');
      }
      refetch();
    },
    onError: (error) => {
      toast.error(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Resolve secret mutation
  const resolveMutation = useMutation({
    mutationFn: async (secretId: string) => {
      return secretsApi.resolve(secretId);
    },
    onSuccess: (_, secretId) => {
      toast.success(`Secret ${secretId} marked as resolved`);
      queryClient.invalidateQueries({ queryKey: ['secrets'] });
    },
    onError: (error) => {
      toast.error(`Failed to resolve: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Sample secrets (would come from API)
  const secrets: SecretFinding[] = secretsData?.secrets || secretsData || [
    { id: 's-1', type: 'AWS Access Key', file: 'config/aws.js', line: 23, value: 'AKIA***************', severity: 'critical', status: 'active', detected: '2 hours ago', repository: 'backend-api' },
    { id: 's-2', type: 'GitHub Token', file: '.env.production', line: 5, value: 'ghp_***************', severity: 'critical', status: 'active', detected: '1 day ago', repository: 'frontend-app' },
    { id: 's-3', type: 'Database Password', file: 'docker-compose.yml', line: 45, value: 'postgres:***', severity: 'high', status: 'active', detected: '3 days ago', repository: 'infrastructure' },
    { id: 's-4', type: 'API Key', file: 'src/services/stripe.ts', line: 12, value: 'sk_live_***********', severity: 'critical', status: 'resolved', detected: '1 week ago', repository: 'payment-service' },
    { id: 's-5', type: 'Private Key', file: 'deploy/keys/id_rsa', line: 1, value: '-----BEGIN RSA PRIVATE KEY-----', severity: 'critical', status: 'active', detected: '5 hours ago', repository: 'devops-scripts' },
    { id: 's-6', type: 'Slack Webhook', file: 'scripts/notify.sh', line: 8, value: 'https://hooks.slack.com/***', severity: 'medium', status: 'active', detected: '2 days ago', repository: 'ci-scripts' },
  ];

  const filteredSecrets = secrets.filter(s => 
    s.type.toLowerCase().includes(filterText.toLowerCase()) ||
    s.file.toLowerCase().includes(filterText.toLowerCase()) ||
    s.repository?.toLowerCase().includes(filterText.toLowerCase())
  );

  const stats = {
    total: secrets.length,
    active: secrets.filter(s => s.status === 'active').length,
    resolved: secrets.filter(s => s.status === 'resolved').length,
    critical: secrets.filter(s => s.severity === 'critical' && s.status === 'active').length,
  };

  const toggleShowValue = (id: string) => {
    setShowValues(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const secretTypeIcons: Record<string, string> = {
    'AWS Access Key': '🔶',
    'GitHub Token': '🐙',
    'Database Password': '🗄️',
    'API Key': '🔑',
    'Private Key': '🔐',
    'Slack Webhook': '💬',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Key className="w-8 h-8 text-primary" />
            Secrets Detection
          </h1>
          <p className="text-muted-foreground mt-1">
            Detect and remediate exposed secrets, API keys, and credentials
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button 
            variant="outline"
            onClick={() => {
              const data = JSON.stringify(secrets, null, 2);
              const blob = new Blob([data], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = url;
              a.download = 'secrets-report.json';
              a.click();
              URL.revokeObjectURL(url);
              toast.success('Report exported');
            }}
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Detected</p>
                <p className="text-3xl font-bold">{stats.total}</p>
              </div>
              <Key className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Critical</p>
                <p className="text-3xl font-bold text-red-500">{stats.critical}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-orange-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Pending</p>
                <p className="text-3xl font-bold text-orange-500">{stats.active}</p>
              </div>
              <Shield className="w-10 h-10 text-orange-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-green-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Resolved</p>
                <p className="text-3xl font-bold text-green-500">{stats.resolved}</p>
              </div>
              <CheckCircle2 className="w-10 h-10 text-green-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Scanner Status */}
      {scannerStatus && (
        <Card className="glass-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Scanner Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-4 gap-4 text-center">
              <div>
                <p className="text-2xl font-bold">{scannerStatus?.scanners?.length || 3}</p>
                <p className="text-sm text-muted-foreground">Active Scanners</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{scannerStatus?.patterns || 150}+</p>
                <p className="text-sm text-muted-foreground">Detection Patterns</p>
              </div>
              <div>
                <p className="text-2xl font-bold text-green-500">{scannerStatus?.repos_scanned || 12}</p>
                <p className="text-sm text-muted-foreground">Repos Scanned</p>
              </div>
              <div>
                <p className="text-2xl font-bold">{scannerStatus?.last_scan || 'N/A'}</p>
                <p className="text-sm text-muted-foreground">Last Scan</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Quick Scan */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileCode className="w-5 h-5" />
            Quick Scan
          </CardTitle>
          <CardDescription>Paste code or config to scan for secrets</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <textarea
              className="w-full h-32 p-3 rounded-md border border-border bg-background font-mono text-sm"
              placeholder="Paste code, config, or environment variables here to scan for secrets..."
              value={scanContent}
              onChange={(e) => setScanContent(e.target.value)}
            />
            <div className="flex justify-end">
              <Button 
                onClick={() => scanMutation.mutate(scanContent)}
                disabled={!scanContent.trim() || scanMutation.isPending}
              >
                {scanMutation.isPending ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Shield className="w-4 h-4 mr-2" />
                )}
                Scan for Secrets
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Secrets List */}
      <Card className="glass-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Detected Secrets</CardTitle>
              <CardDescription>Click to view details and remediate</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Filter by type, file, or repo..."
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                className="w-64"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
            <div className="space-y-3">
              {filteredSecrets.map((secret) => (
                <motion.div
                  key={secret.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-4 rounded-lg border ${
                    secret.status === 'resolved' 
                      ? 'border-green-500/30 bg-green-500/5' 
                      : 'border-border hover:border-primary/50'
                  } transition-all`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <span className="text-2xl">{secretTypeIcons[secret.type] || '🔑'}</span>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{secret.type}</p>
                          <Badge variant={
                            secret.severity === 'critical' ? 'destructive' :
                            secret.severity === 'high' ? 'high' :
                            secret.severity === 'medium' ? 'medium' :
                            'default'
                          }>
                            {secret.severity}
                          </Badge>
                          {secret.status === 'resolved' && (
                            <Badge variant="default" className="bg-green-600">Resolved</Badge>
                          )}
                        </div>
                        <p className="text-sm text-muted-foreground flex items-center gap-2">
                          <FileCode className="w-3 h-3" />
                          {secret.file}:{secret.line}
                          {secret.repository && (
                            <>
                              <GitBranch className="w-3 h-3 ml-2" />
                              {secret.repository}
                            </>
                          )}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="text-right text-sm mr-4">
                        <p className="font-mono text-xs bg-muted px-2 py-1 rounded">
                          {showValues.has(secret.id) ? secret.value : '•'.repeat(20)}
                        </p>
                        <p className="text-muted-foreground text-xs mt-1">{secret.detected}</p>
                      </div>
                      <Button 
                        variant="ghost" 
                        size="icon"
                        onClick={() => toggleShowValue(secret.id)}
                        title={showValues.has(secret.id) ? 'Hide value' : 'Show value'}
                      >
                        {showValues.has(secret.id) ? (
                          <EyeOff className="w-4 h-4" />
                        ) : (
                          <Eye className="w-4 h-4" />
                        )}
                      </Button>
                      {secret.status !== 'resolved' && (
                        <Button 
                          size="sm"
                          onClick={() => resolveMutation.mutate(secret.id)}
                          disabled={resolveMutation.isPending}
                        >
                          {resolveMutation.isPending ? (
                            <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                          ) : (
                            <Lock className="w-3 h-3 mr-1" />
                          )}
                          Resolve
                        </Button>
                      )}
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
