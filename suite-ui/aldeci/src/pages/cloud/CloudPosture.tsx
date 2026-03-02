import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Cloud,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Shield,
  Server,
  Loader2,
  Download,
  Eye,
  Database,
  Filter,
  ExternalLink,
  Wrench,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { cnappApi, inventoryApi } from '../../lib/api';
import { toast } from 'sonner';

interface CloudResource {
  id: string;
  name: string;
  type: string;
  provider: 'aws' | 'azure' | 'gcp';
  region: string;
  status: 'compliant' | 'non-compliant' | 'warning';
  findings: number;
  lastScanned?: string;
}

interface Misconfiguration {
  id: string;
  resource: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  framework: string;
  status: 'open' | 'resolved' | 'accepted';
}

export default function CloudPosture() {
  const queryClient = useQueryClient();
  const [filterText, setFilterText] = useState('');
  const [selectedProvider, setSelectedProvider] = useState<string>('all');

  // Fetch CNAPP data
  const { data: cnappData, isLoading: cnappLoading, refetch: refetchCnapp } = useQuery({
    queryKey: ['cnapp-findings'],
    queryFn: cnappApi.getFindings,
  });

  // Fetch inventory
  const { data: inventoryData, isLoading: inventoryLoading } = useQuery({
    queryKey: ['cloud-inventory'],
    queryFn: inventoryApi.getAssets,
  });

  // Fetch posture summary - used for compliance score
  useQuery({
    queryKey: ['posture-summary'],
    queryFn: () => cnappApi.getSummary(),
  });

  // Run scan mutation
  const scanMutation = useMutation({
    mutationFn: async (provider?: string) => {
      toast.info('Starting cloud posture scan...', { duration: 2000 });
      return cnappApi.scan(JSON.stringify({ provider: provider || 'all', full_scan: true }));
    },
    onSuccess: (data) => {
      toast.success(`Scan complete! Found ${data?.findings_count || 0} findings.`);
      queryClient.invalidateQueries({ queryKey: ['cnapp-findings'] });
    },
    onError: (error) => {
      toast.error(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Export report mutation
  const exportMutation = useMutation({
    mutationFn: async () => {
      const data = await cnappApi.export('json');
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cloud-posture-report.json';
      a.click();
      URL.revokeObjectURL(url);
      return data;
    },
    onSuccess: () => {
      toast.success('Report exported successfully');
    },
    onError: () => {
      toast.error('Export failed');
    },
  });

  // Remediate misconfiguration mutation
  const remediateMutation = useMutation({
    mutationFn: async (findingId: string) => {
      return cnappApi.remediate(findingId);
    },
    onSuccess: (_, findingId) => {
      toast.success(`Remediation initiated for ${findingId}`);
      refetchCnapp();
    },
    onError: (error) => {
      toast.error(`Remediation failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Cloud resources from inventory API - zero mock data
  const rawInventory = inventoryData?.items || inventoryData?.assets || (Array.isArray(inventoryData) ? inventoryData : []);
  const cloudResources: CloudResource[] = rawInventory.map((item: any) => ({
    id: item.id || item.asset_id || `r-${Math.random().toString(36).slice(2, 8)}`,
    name: item.name || item.hostname || 'Unknown Resource',
    type: item.type || item.resource_type || 'Unknown',
    provider: (item.provider || item.cloud_provider || 'aws').toLowerCase() as 'aws' | 'azure' | 'gcp',
    region: item.region || item.location || 'unknown',
    status: item.compliance_status === 'compliant' || item.findings === 0 ? 'compliant'
      : item.compliance_status === 'warning' ? 'warning' : 'non-compliant',
    findings: item.findings_count ?? item.findings ?? 0,
    lastScanned: item.last_scanned || item.updated_at || undefined,
  }));

  // Misconfigurations from CNAPP API - zero mock data
  const rawFindings = cnappData?.findings || cnappData?.items || (Array.isArray(cnappData) ? cnappData : []);
  const misconfigurations: Misconfiguration[] = rawFindings.map((f: any) => ({
    id: f.id || f.finding_id || `mc-${Math.random().toString(36).slice(2, 8)}`,
    resource: f.resource || f.asset_name || f.resource_id || 'Unknown',
    title: f.title || f.description || f.rule_id || 'Unnamed finding',
    severity: (f.severity || 'medium').toLowerCase() as 'critical' | 'high' | 'medium' | 'low',
    framework: f.framework || f.compliance_framework || f.rule_set || 'CIS',
    status: (f.status || 'open').toLowerCase() as 'open' | 'resolved' | 'accepted',
  }));

  const filteredMisconfigs = misconfigurations.filter(m => 
    m.title.toLowerCase().includes(filterText.toLowerCase()) ||
    m.resource.toLowerCase().includes(filterText.toLowerCase())
  );

  const stats = {
    totalResources: cloudResources.length,
    compliant: cloudResources.filter(r => r.status === 'compliant').length,
    nonCompliant: cloudResources.filter(r => r.status === 'non-compliant').length,
    totalFindings: misconfigurations.length,
    criticalFindings: misconfigurations.filter(m => m.severity === 'critical').length,
  };

  const complianceScore = stats.totalResources > 0 
    ? Math.round((stats.compliant / stats.totalResources) * 100) 
    : 0;

  const providerIcons: Record<string, string> = {
    aws: '🔶',
    azure: '🔷',
    gcp: '🔴',
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Cloud className="w-8 h-8 text-primary" />
            Cloud Posture (CSPM)
          </h1>
          <p className="text-muted-foreground mt-1">
            Cloud Security Posture Management across AWS, Azure, and GCP
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetchCnapp()} disabled={cnappLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${cnappLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button variant="outline" onClick={() => exportMutation.mutate()} disabled={exportMutation.isPending}>
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button onClick={() => scanMutation.mutate(undefined)} disabled={scanMutation.isPending}>
            {scanMutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Shield className="w-4 h-4 mr-2" />
            )}
            Run Scan
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="text-center">
              <p className="text-sm text-muted-foreground">Compliance Score</p>
              <p className="text-4xl font-bold text-primary">{complianceScore}%</p>
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Resources</p>
                <p className="text-3xl font-bold">{stats.totalResources}</p>
              </div>
              <Server className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-green-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Compliant</p>
                <p className="text-3xl font-bold text-green-500">{stats.compliant}</p>
              </div>
              <CheckCircle2 className="w-10 h-10 text-green-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Non-Compliant</p>
                <p className="text-3xl font-bold text-red-500">{stats.nonCompliant}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-orange-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical</p>
                <p className="text-3xl font-bold text-orange-500">{stats.criticalFindings}</p>
              </div>
              <Shield className="w-10 h-10 text-orange-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Cloud Resources */}
      <Card className="glass-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Database className="w-5 h-5" />
                Cloud Resources
              </CardTitle>
              <CardDescription>All monitored cloud resources</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <select 
                className="p-2 rounded-md border border-border bg-background text-sm"
                value={selectedProvider}
                onChange={(e) => setSelectedProvider(e.target.value)}
              >
                <option value="all">All Providers</option>
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {(cnappLoading || inventoryLoading) ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : cloudResources.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Cloud className="w-16 h-16 text-muted-foreground/30 mb-4" />
              <h3 className="text-lg font-semibold text-muted-foreground mb-2">No Cloud Resources Discovered</h3>
              <p className="text-sm text-muted-foreground/70 max-w-md mb-4">
                Run a CSPM scan to discover cloud resources across AWS, Azure, and GCP.
                Resources will appear here with their compliance status.
              </p>
              <Button onClick={() => scanMutation.mutate(undefined)} disabled={scanMutation.isPending}>
                {scanMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Shield className="w-4 h-4 mr-2" />}
                Run Cloud Scan
              </Button>
            </div>
          ) : (
          <div className="space-y-2">
            {cloudResources
              .filter(r => selectedProvider === 'all' || r.provider === selectedProvider)
              .map((resource) => (
                <div
                  key={resource.id}
                  className="flex items-center justify-between p-3 rounded-lg border border-border hover:border-primary/50 transition-all"
                >
                  <div className="flex items-center gap-4">
                    <span className="text-2xl">{providerIcons[resource.provider]}</span>
                    <div>
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{resource.name}</p>
                        <Badge variant={
                          resource.status === 'compliant' ? 'default' :
                          resource.status === 'non-compliant' ? 'destructive' :
                          'medium'
                        }>
                          {resource.status}
                        </Badge>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        {resource.type} • {resource.region}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-4">
                    {resource.findings > 0 && (
                      <Badge variant="destructive">{resource.findings} findings</Badge>
                    )}
                    <span className="text-xs text-muted-foreground">{resource.lastScanned}</span>
                    <Button 
                      variant="ghost" 
                      size="icon"
                      onClick={() => toast.info(`Viewing details for ${resource.name}`)}
                    >
                      <Eye className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
          </div>
          )}
        </CardContent>
      </Card>

      {/* Misconfigurations */}
      <Card className="glass-card">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-500" />
                Misconfigurations
              </CardTitle>
              <CardDescription>Security issues requiring attention</CardDescription>
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
          {cnappLoading || inventoryLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : filteredMisconfigs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <CheckCircle2 className="w-12 h-12 text-green-500/30 mb-3" />
              <h3 className="text-md font-semibold text-muted-foreground mb-1">No Misconfigurations Found</h3>
              <p className="text-sm text-muted-foreground/70">
                {filterText ? 'No results match your filter. Try a different search term.' : 'Run a CSPM scan to check for cloud security misconfigurations.'}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredMisconfigs.map((misconfig) => (
                <motion.div
                  key={misconfig.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-4 rounded-lg border border-border hover:border-primary/50 transition-all"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 rounded-full ${
                        misconfig.severity === 'critical' ? 'bg-red-500' :
                        misconfig.severity === 'high' ? 'bg-orange-500' :
                        misconfig.severity === 'medium' ? 'bg-yellow-500' :
                        'bg-blue-500'
                      }`} />
                      <div>
                        <p className="font-medium">{misconfig.title}</p>
                        <p className="text-sm text-muted-foreground">
                          Resource: {misconfig.resource} • Framework: {misconfig.framework}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={
                        misconfig.severity === 'critical' ? 'destructive' :
                        misconfig.severity === 'high' ? 'high' :
                        misconfig.severity === 'medium' ? 'medium' :
                        'default'
                      }>
                        {misconfig.severity}
                      </Badge>
                      <Button 
                        size="sm" 
                        variant="outline"
                        onClick={() => {
                          toast.info(`Opening remediation guide for: ${misconfig.title}`);
                        }}
                      >
                        <ExternalLink className="w-3 h-3 mr-1" />
                        Guide
                      </Button>
                      <Button 
                        size="sm"
                        onClick={() => remediateMutation.mutate(misconfig.id)}
                        disabled={remediateMutation.isPending}
                      >
                        {remediateMutation.isPending ? (
                          <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                        ) : (
                          <Wrench className="w-3 h-3 mr-1" />
                        )}
                        Remediate
                      </Button>
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
