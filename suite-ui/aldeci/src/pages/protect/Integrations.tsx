import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Link2,
  RefreshCw,
  Plus,
  CheckCircle2,
  XCircle,
  Settings,
  Trash2,
  ExternalLink,
  Loader2,
  Ticket,
  GitBranch,
  MessageSquare,
  Cloud,
  Shield,
  Database,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { integrationsApi, webhooksApi } from '../../lib/api';
import { toast } from 'sonner';

interface Integration {
  id: string;
  name: string;
  type: string;
  status: 'connected' | 'disconnected' | 'error';
  icon: React.ElementType;
  lastSync?: string;
  description: string;
  config?: Record<string, unknown>;
}

const integrationTypes = [
  { type: 'jira', name: 'Jira', icon: Ticket, description: 'Atlassian Jira for issue tracking' },
  { type: 'github', name: 'GitHub', icon: GitBranch, description: 'GitHub for repository integration' },
  { type: 'gitlab', name: 'GitLab', icon: GitBranch, description: 'GitLab for repository integration' },
  { type: 'slack', name: 'Slack', icon: MessageSquare, description: 'Slack for notifications' },
  { type: 'teams', name: 'Microsoft Teams', icon: MessageSquare, description: 'Teams for notifications' },
  { type: 'aws', name: 'AWS Security Hub', icon: Cloud, description: 'AWS Security Hub integration' },
  { type: 'azure', name: 'Azure Defender', icon: Shield, description: 'Azure Defender integration' },
  { type: 'splunk', name: 'Splunk', icon: Database, description: 'Splunk SIEM integration' },
  { type: 'servicenow', name: 'ServiceNow', icon: Ticket, description: 'ServiceNow ITSM integration' },
];

export default function Integrations() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [configuring, setConfiguring] = useState<string | null>(null);

  // Fetch integrations
  const { data: integrationsData, isLoading, refetch } = useQuery({
    queryKey: ['integrations'],
    queryFn: integrationsApi.list,
  });

  // Fetch webhooks
  const { data: webhooksData } = useQuery({
    queryKey: ['webhooks'],
    queryFn: webhooksApi.getMappings,
  });

  // Test integration mutation
  const testMutation = useMutation({
    mutationFn: async (integrationId: string) => {
      return integrationsApi.test(integrationId);
    },
    onSuccess: (data, integrationId) => {
      if (data?.success) {
        toast.success(`Integration ${integrationId} is working!`);
      } else {
        toast.error(`Integration test failed: ${data?.error || 'Unknown error'}`);
      }
    },
    onError: (error) => {
      toast.error(`Test failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Create integration mutation
  const createMutation = useMutation({
    mutationFn: async (data: { type: string; name: string; config: Record<string, string> }) => {
      return integrationsApi.create(data);
    },
    onSuccess: () => {
      toast.success('Integration created successfully!');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setShowAddModal(false);
      setSelectedType(null);
    },
    onError: (error) => {
      toast.error(`Failed to create integration: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Delete integration mutation
  const deleteMutation = useMutation({
    mutationFn: async (integrationId: string) => {
      return integrationsApi.delete(integrationId);
    },
    onSuccess: () => {
      toast.success('Integration deleted');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (error) => {
      toast.error(`Delete failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Sync integration mutation
  const syncMutation = useMutation({
    mutationFn: async (integrationId: string) => {
      return integrationsApi.sync(integrationId);
    },
    onSuccess: (_, integrationId) => {
      toast.success(`Synced ${integrationId} successfully`);
      refetch();
    },
    onError: (error) => {
      toast.error(`Sync failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Mock integrations if API doesn't return them
  const integrations: Integration[] = integrationsData?.integrations || [
    { id: 'jira-1', name: 'Jira Cloud', type: 'jira', status: 'connected', icon: Ticket, lastSync: '5 min ago', description: 'Project: SEC' },
    { id: 'github-1', name: 'GitHub Enterprise', type: 'github', status: 'connected', icon: GitBranch, lastSync: '2 min ago', description: 'Org: mycompany' },
    { id: 'slack-1', name: 'Slack #security', type: 'slack', status: 'connected', icon: MessageSquare, lastSync: '1 min ago', description: 'Channel: #security-alerts' },
    { id: 'aws-1', name: 'AWS Security Hub', type: 'aws', status: 'error', icon: Cloud, description: 'Account: prod-123' },
  ];

  const stats = {
    total: integrations.length,
    connected: integrations.filter(i => i.status === 'connected').length,
    errors: integrations.filter(i => i.status === 'error').length,
    webhooks: Array.isArray(webhooksData) ? webhooksData.length : webhooksData?.length || 0,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Link2 className="w-8 h-8 text-primary" />
            Integrations
          </h1>
          <p className="text-muted-foreground mt-1">
            Connect your security tools, ticketing systems, and notification channels
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button onClick={() => setShowAddModal(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Add Integration
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Integrations</p>
                <p className="text-3xl font-bold">{stats.total}</p>
              </div>
              <Link2 className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-green-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Connected</p>
                <p className="text-3xl font-bold text-green-500">{stats.connected}</p>
              </div>
              <CheckCircle2 className="w-10 h-10 text-green-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Errors</p>
                <p className="text-3xl font-bold text-red-500">{stats.errors}</p>
              </div>
              <XCircle className="w-10 h-10 text-red-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Webhooks</p>
                <p className="text-3xl font-bold">{stats.webhooks}</p>
              </div>
              <ExternalLink className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Active Integrations */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Active Integrations</CardTitle>
          <CardDescription>Manage your connected services and tools</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : (
            <div className="space-y-3">
              {integrations.map((integration) => {
                const Icon = integration.icon;
                return (
                  <motion.div
                    key={integration.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={`p-4 rounded-lg border ${
                      configuring === integration.id 
                        ? 'border-primary bg-primary/5' 
                        : 'border-border hover:border-primary/50'
                    } transition-all`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                          integration.status === 'connected' ? 'bg-green-500/10' :
                          integration.status === 'error' ? 'bg-red-500/10' :
                          'bg-muted'
                        }`}>
                          <Icon className={`w-6 h-6 ${
                            integration.status === 'connected' ? 'text-green-500' :
                            integration.status === 'error' ? 'text-red-500' :
                            'text-muted-foreground'
                          }`} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <p className="font-medium">{integration.name}</p>
                            <Badge variant={
                              integration.status === 'connected' ? 'default' :
                              integration.status === 'error' ? 'destructive' :
                              'secondary'
                            }>
                              {integration.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">{integration.description}</p>
                          {integration.lastSync && (
                            <p className="text-xs text-muted-foreground mt-1">
                              Last sync: {integration.lastSync}
                            </p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={() => testMutation.mutate(integration.id)}
                          disabled={testMutation.isPending}
                          title="Test connection"
                        >
                          {testMutation.isPending ? (
                            <Loader2 className="w-4 h-4 animate-spin" />
                          ) : (
                            <CheckCircle2 className="w-4 h-4" />
                          )}
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={() => syncMutation.mutate(integration.id)}
                          disabled={syncMutation.isPending}
                          title="Sync now"
                        >
                          <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={() => setConfiguring(configuring === integration.id ? null : integration.id)}
                          title="Configure"
                        >
                          <Settings className="w-4 h-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="icon"
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this integration?')) {
                              deleteMutation.mutate(integration.id);
                            }
                          }}
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4 text-red-500" />
                        </Button>
                      </div>
                    </div>

                    {/* Expanded Config */}
                    {configuring === integration.id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        className="mt-4 pt-4 border-t border-border"
                      >
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="text-sm font-medium">API URL</label>
                            <Input 
                              defaultValue={`https://${integration.type}.example.com`} 
                              className="mt-1"
                            />
                          </div>
                          <div>
                            <label className="text-sm font-medium">API Key</label>
                            <Input 
                              type="password" 
                              defaultValue="••••••••••••" 
                              className="mt-1"
                            />
                          </div>
                        </div>
                        <div className="flex justify-end gap-2 mt-4">
                          <Button variant="outline" onClick={() => setConfiguring(null)}>
                            Cancel
                          </Button>
                          <Button onClick={() => {
                            toast.success(`Configuration saved for ${integration.name}`);
                            setConfiguring(null);
                          }}>
                            Save Changes
                          </Button>
                        </div>
                      </motion.div>
                    )}
                  </motion.div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Add Integration Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-card border border-border rounded-lg p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto"
          >
            <h2 className="text-xl font-bold mb-4">Add New Integration</h2>
            
            {!selectedType ? (
              <>
                <p className="text-muted-foreground mb-4">Select an integration type:</p>
                <div className="grid grid-cols-3 gap-3">
                  {integrationTypes.map((type) => {
                    const Icon = type.icon;
                    return (
                      <button
                        key={type.type}
                        onClick={() => setSelectedType(type.type)}
                        className="p-4 rounded-lg border border-border hover:border-primary hover:bg-primary/5 transition-all text-left"
                      >
                        <Icon className="w-8 h-8 mb-2 text-primary" />
                        <p className="font-medium">{type.name}</p>
                        <p className="text-xs text-muted-foreground">{type.description}</p>
                      </button>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center gap-2 mb-4">
                  <Button variant="ghost" size="sm" onClick={() => setSelectedType(null)}>
                    ← Back
                  </Button>
                  <span className="font-medium">
                    Configure {integrationTypes.find(t => t.type === selectedType)?.name}
                  </span>
                </div>
                
                <div>
                  <label className="text-sm font-medium">Name</label>
                  <Input placeholder="My Integration" className="mt-1" />
                </div>
                <div>
                  <label className="text-sm font-medium">API URL / Instance URL</label>
                  <Input placeholder="https://your-instance.atlassian.net" className="mt-1" />
                </div>
                <div>
                  <label className="text-sm font-medium">API Key / Token</label>
                  <Input type="password" placeholder="Enter your API key" className="mt-1" />
                </div>
                {selectedType === 'jira' && (
                  <div>
                    <label className="text-sm font-medium">Project Key</label>
                    <Input placeholder="SEC" className="mt-1" />
                  </div>
                )}
                {selectedType === 'slack' && (
                  <div>
                    <label className="text-sm font-medium">Channel</label>
                    <Input placeholder="#security-alerts" className="mt-1" />
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end gap-2 mt-6">
              <Button variant="outline" onClick={() => {
                setShowAddModal(false);
                setSelectedType(null);
              }}>
                Cancel
              </Button>
              {selectedType && (
                <Button 
                  onClick={() => createMutation.mutate({
                    type: selectedType,
                    name: `New ${integrationTypes.find(t => t.type === selectedType)?.name}`,
                    config: {}
                  })}
                  disabled={createMutation.isPending}
                >
                  {createMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : null}
                  Connect Integration
                </Button>
              )}
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
}
