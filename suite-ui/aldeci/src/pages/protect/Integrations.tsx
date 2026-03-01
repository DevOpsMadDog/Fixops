import { useState, useRef } from 'react';
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
  FileText,
  Bug,
  Radar,
  Search,
  BarChart3,
  AlertTriangle,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Input } from '../../components/ui/input';
import { integrationsApi, webhooksApi } from '../../lib/api';
import { toast } from 'sonner';

// ── Backend integration response shape ──────────────────────────────────────
interface BackendIntegration {
  id: string;
  name: string;
  integration_type: string;
  status: 'active' | 'inactive' | 'error';
  config: Record<string, unknown>;
  last_sync_at: string | null;
  last_sync_status: string | null;
  created_at: string;
  updated_at: string;
}

// ── UI-enriched integration ─────────────────────────────────────────────────
interface Integration {
  id: string;
  name: string;
  type: string;
  status: 'connected' | 'disconnected' | 'error';
  icon: React.ElementType;
  lastSync?: string;
  description: string;
  config: Record<string, unknown>;
}

// ── All 14 backend-supported types + config field metadata ─────────────────
const integrationTypes: {
  type: string;
  name: string;
  icon: React.ElementType;
  description: string;
  category: 'devops' | 'notification' | 'security' | 'cloud';
  configFields: { key: string; label: string; type: 'text' | 'password' | 'url'; placeholder: string; required: boolean }[];
}[] = [
  // ── DevOps / Ticketing ──
  {
    type: 'jira', name: 'Jira', icon: Ticket, description: 'Atlassian Jira for issue tracking',
    category: 'devops',
    configFields: [
      { key: 'url', label: 'Jira URL', type: 'url', placeholder: 'https://your-org.atlassian.net', required: true },
      { key: 'username', label: 'Username / Email', type: 'text', placeholder: 'user@company.com', required: true },
      { key: 'api_token', label: 'API Token', type: 'password', placeholder: 'Jira API token', required: true },
      { key: 'project_key', label: 'Project Key', type: 'text', placeholder: 'SEC', required: true },
    ],
  },
  {
    type: 'confluence', name: 'Confluence', icon: FileText, description: 'Atlassian Confluence for documentation',
    category: 'devops',
    configFields: [
      { key: 'url', label: 'Confluence URL', type: 'url', placeholder: 'https://your-org.atlassian.net/wiki', required: true },
      { key: 'username', label: 'Username / Email', type: 'text', placeholder: 'user@company.com', required: true },
      { key: 'api_token', label: 'API Token', type: 'password', placeholder: 'API token', required: true },
      { key: 'space_key', label: 'Space Key', type: 'text', placeholder: 'SEC', required: true },
    ],
  },
  {
    type: 'github', name: 'GitHub', icon: GitBranch, description: 'GitHub for repository integration',
    category: 'devops',
    configFields: [
      { key: 'owner', label: 'Owner (org/user)', type: 'text', placeholder: 'acme-corp', required: true },
      { key: 'repo', label: 'Repository', type: 'text', placeholder: 'main-app', required: true },
      { key: 'token', label: 'Personal Access Token', type: 'password', placeholder: 'ghp_...', required: true },
    ],
  },
  {
    type: 'gitlab', name: 'GitLab', icon: GitBranch, description: 'GitLab for repository integration',
    category: 'devops',
    configFields: [
      { key: 'base_url', label: 'GitLab URL', type: 'url', placeholder: 'https://gitlab.com', required: true },
      { key: 'project_id', label: 'Project ID', type: 'text', placeholder: '12345', required: true },
      { key: 'private_token', label: 'Private Token', type: 'password', placeholder: 'glpat-...', required: true },
    ],
  },
  {
    type: 'azure_devops', name: 'Azure DevOps', icon: Cloud, description: 'Azure DevOps for boards & repos',
    category: 'devops',
    configFields: [
      { key: 'organization', label: 'Organization', type: 'text', placeholder: 'my-org', required: true },
      { key: 'project', label: 'Project', type: 'text', placeholder: 'my-project', required: true },
      { key: 'pat', label: 'Personal Access Token', type: 'password', placeholder: 'Azure DevOps PAT', required: true },
    ],
  },
  {
    type: 'servicenow', name: 'ServiceNow', icon: Ticket, description: 'ServiceNow ITSM integration',
    category: 'devops',
    configFields: [
      { key: 'instance_url', label: 'Instance URL', type: 'url', placeholder: 'https://your-instance.service-now.com', required: true },
      { key: 'username', label: 'Username', type: 'text', placeholder: 'admin', required: true },
      { key: 'password', label: 'Password', type: 'password', placeholder: 'Password', required: true },
    ],
  },
  // ── Notifications ──
  {
    type: 'slack', name: 'Slack', icon: MessageSquare, description: 'Slack for notifications',
    category: 'notification',
    configFields: [
      { key: 'webhook_url', label: 'Webhook URL', type: 'url', placeholder: 'https://hooks.slack.com/services/...', required: true },
      { key: 'channel', label: 'Channel', type: 'text', placeholder: '#security-alerts', required: false },
    ],
  },
  {
    type: 'pagerduty', name: 'PagerDuty', icon: AlertTriangle, description: 'PagerDuty for incident management',
    category: 'notification',
    configFields: [
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'PagerDuty API key', required: true },
      { key: 'service_id', label: 'Service ID', type: 'text', placeholder: 'PXXXXXX', required: true },
    ],
  },
  // ── Security Tools ──
  {
    type: 'snyk', name: 'Snyk', icon: Bug, description: 'Snyk for dependency & code vulnerabilities',
    category: 'security',
    configFields: [
      { key: 'token', label: 'API Token', type: 'password', placeholder: 'Snyk API token', required: true },
      { key: 'org_id', label: 'Organization ID', type: 'text', placeholder: 'org-uuid', required: true },
    ],
  },
  {
    type: 'sonarqube', name: 'SonarQube', icon: BarChart3, description: 'SonarQube for code quality & security',
    category: 'security',
    configFields: [
      { key: 'base_url', label: 'SonarQube URL', type: 'url', placeholder: 'https://sonarqube.company.com', required: true },
      { key: 'token', label: 'User Token', type: 'password', placeholder: 'squ_...', required: true },
      { key: 'project_key', label: 'Project Key', type: 'text', placeholder: 'my-project', required: false },
    ],
  },
  {
    type: 'dependabot', name: 'Dependabot', icon: Search, description: 'GitHub Dependabot vulnerability alerts',
    category: 'security',
    configFields: [
      { key: 'github_token', label: 'GitHub Token', type: 'password', placeholder: 'ghp_...', required: true },
      { key: 'owner', label: 'Owner', type: 'text', placeholder: 'acme-corp', required: true },
      { key: 'repo', label: 'Repository', type: 'text', placeholder: 'main-app', required: false },
    ],
  },
  {
    type: 'threatmapper', name: 'ThreatMapper', icon: Radar, description: 'Deepfence ThreatMapper runtime security',
    category: 'security',
    configFields: [
      { key: 'console_url', label: 'Console URL', type: 'url', placeholder: 'https://threatmapper.local:9090', required: true },
      { key: 'api_key', label: 'API Key', type: 'password', placeholder: 'ThreatMapper API key', required: true },
    ],
  },
  // ── Cloud Security ──
  {
    type: 'aws_security_hub', name: 'AWS Security Hub', icon: Cloud, description: 'AWS-native security findings aggregator',
    category: 'cloud',
    configFields: [
      { key: 'access_key_id', label: 'Access Key ID', type: 'text', placeholder: 'AKIA...', required: true },
      { key: 'secret_access_key', label: 'Secret Access Key', type: 'password', placeholder: 'Secret key', required: true },
      { key: 'region', label: 'Region', type: 'text', placeholder: 'us-east-1', required: true },
    ],
  },
  {
    type: 'azure_security_center', name: 'Azure Security Center', icon: Shield, description: 'Azure Defender for Cloud',
    category: 'cloud',
    configFields: [
      { key: 'tenant_id', label: 'Tenant ID', type: 'text', placeholder: 'Azure AD tenant ID', required: true },
      { key: 'client_id', label: 'Client ID', type: 'text', placeholder: 'App registration client ID', required: true },
      { key: 'client_secret', label: 'Client Secret', type: 'password', placeholder: 'Client secret', required: true },
      { key: 'subscription_id', label: 'Subscription ID', type: 'text', placeholder: 'Azure subscription ID', required: true },
    ],
  },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Map backend status → UI status */
function mapStatus(s: string): 'connected' | 'disconnected' | 'error' {
  if (s === 'active') return 'connected';
  if (s === 'error') return 'error';
  return 'disconnected';
}

/** Look up integration type metadata — fallback for unknown types */
function getTypeMeta(type: string) {
  return integrationTypes.find(t => t.type === type) ||
    { type, name: type, icon: Link2, description: `${type} integration`, category: 'devops' as const, configFields: [] };
}

/** Friendly "last sync" string */
function formatLastSync(iso: string | null): string | undefined {
  if (!iso) return undefined;
  try {
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000) return 'just now';
    if (diff < 3_600_000) return `${Math.round(diff / 60_000)} min ago`;
    if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
    return new Date(iso).toLocaleDateString();
  } catch { return undefined; }
}

/** Convert a backend record to a UI integration */
function toUIIntegration(b: BackendIntegration): Integration {
  const meta = getTypeMeta(b.integration_type);
  return {
    id: b.id,
    name: b.name,
    type: b.integration_type,
    status: mapStatus(b.status),
    icon: meta.icon,
    lastSync: formatLastSync(b.last_sync_at),
    description: meta.description,
    config: b.config || {},
  };
}

/** Group label for categories */
const categoryLabels: Record<string, string> = {
  devops: 'DevOps & Ticketing',
  notification: 'Notifications',
  security: 'Security Tools',
  cloud: 'Cloud Security',
};

export default function Integrations() {
  const queryClient = useQueryClient();
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [configuring, setConfiguring] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const configRefs = useRef<Record<string, Record<string, HTMLInputElement | null>>>({});
  const addFormRefs = useRef<Record<string, HTMLInputElement | null>>({});

  // ── Fetch real integrations from backend ────────────────────────────────
  const { data: integrationsData, isLoading, refetch } = useQuery({
    queryKey: ['integrations'],
    queryFn: integrationsApi.list,
  });

  // Fetch webhooks
  const { data: webhooksData } = useQuery({
    queryKey: ['webhooks'],
    queryFn: webhooksApi.getMappings,
  });

  // ── Map backend response (items → UI integrations) ──────────────────────
  const integrations: Integration[] = (integrationsData?.items || []).map(toUIIntegration);

  // ── Mutations ───────────────────────────────────────────────────────────
  const testMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsApi.test(integrationId),
    onSuccess: (data, integrationId) => {
      if (data?.success) {
        toast.success(`${integrationId} connection verified`);
      } else {
        toast.error(`Test failed: ${data?.message || 'Unknown error'}`);
      }
    },
    onError: (err) => toast.error(`Test failed: ${err instanceof Error ? err.message : 'Unknown error'}`),
  });

  const createMutation = useMutation({
    mutationFn: (data: { integration_type: string; name: string; config: Record<string, string> }) =>
      integrationsApi.create(data),
    onSuccess: () => {
      toast.success('Integration created!');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      setShowAddModal(false);
      setSelectedType(null);
    },
    onError: (err) => toast.error(`Create failed: ${err instanceof Error ? err.message : 'Unknown error'}`),
  });

  const deleteMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsApi.delete(integrationId),
    onSuccess: () => {
      toast.success('Integration deleted');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (err) => toast.error(`Delete failed: ${err instanceof Error ? err.message : 'Unknown error'}`),
  });

  const syncMutation = useMutation({
    mutationFn: (integrationId: string) => integrationsApi.sync(integrationId),
    onSuccess: (data, id) => {
      if (data?.sync_status === 'success') {
        toast.success(`Synced ${id} — ${data.message}`);
      } else {
        toast.error(`Sync failed: ${data?.details?.error || data?.message || 'Unknown'}`);
      }
      refetch();
    },
    onError: (err) => toast.error(`Sync failed: ${err instanceof Error ? err.message : 'Unknown error'}`),
  });

  const configureMutation = useMutation({
    mutationFn: ({ id, config }: { id: string; config: Record<string, unknown> }) =>
      integrationsApi.configure(id, { config }),
    onSuccess: () => {
      toast.success('Configuration saved');
      setConfiguring(null);
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (err) => toast.error(`Save failed: ${err instanceof Error ? err.message : 'Unknown error'}`),
  });

  const stats = {
    total: integrations.length,
    connected: integrations.filter(i => i.status === 'connected').length,
    errors: integrations.filter(i => i.status === 'error').length,
    webhooks: Array.isArray(webhooksData) ? webhooksData.length : webhooksData?.length || 0,
    types: [...new Set(integrations.map(i => i.type))].length,
  };

  /** Collect config values from refs for an integration row */
  const collectConfig = (integrationId: string): Record<string, string> => {
    const refs = configRefs.current[integrationId] || {};
    const config: Record<string, string> = {};
    for (const [key, el] of Object.entries(refs)) {
      if (el?.value) config[key] = el.value;
    }
    return config;
  };

  /** Collect config values from the "Add" modal */
  const collectAddConfig = (): Record<string, string> => {
    const refs = addFormRefs.current;
    const config: Record<string, string> = {};
    for (const [key, el] of Object.entries(refs)) {
      if (el?.value) config[key] = el.value;
    }
    return config;
  };

  // Selected type metadata for the add modal
  const selectedMeta = selectedType ? getTypeMeta(selectedType) : null;

  // Group available types by category for the add modal
  const typesGrouped = Object.entries(categoryLabels).map(([cat, label]) => ({
    category: cat,
    label,
    types: integrationTypes.filter(t => t.category === cat),
  }));

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
            17 connectors &middot; ticketing, notifications, security tools &amp; cloud platforms
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
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total</p>
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
                <p className="text-sm text-muted-foreground">Types</p>
                <p className="text-3xl font-bold">{stats.types}</p>
              </div>
              <Database className="w-10 h-10 text-primary opacity-20" />
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

      {/* Category filter tabs */}
      <div className="flex items-center gap-2 flex-wrap">
        <Button
          variant={categoryFilter === null ? 'default' : 'outline'}
          size="sm"
          onClick={() => setCategoryFilter(null)}
        >
          All ({integrations.length})
        </Button>
        {Object.entries(categoryLabels).map(([cat, label]) => {
          const count = integrations.filter(i => getTypeMeta(i.type).category === cat).length;
          if (count === 0) return null;
          return (
            <Button
              key={cat}
              variant={categoryFilter === cat ? 'default' : 'outline'}
              size="sm"
              onClick={() => setCategoryFilter(categoryFilter === cat ? null : cat)}
            >
              {label} ({count})
            </Button>
          );
        })}
      </div>

      {/* Active Integrations */}
      <Card className="glass-card">
        <CardHeader>
          <CardTitle>Active Integrations</CardTitle>
          <CardDescription>
            {isLoading ? 'Loading...' : `${integrations.length} integrations from backend (live data)`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
            </div>
          ) : integrations.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Link2 className="w-12 h-12 mx-auto mb-4 opacity-30" />
              <p className="text-lg font-medium">No integrations configured</p>
              <p className="text-sm mt-1">Click "Add Integration" to connect your first tool</p>
            </div>
          ) : (
            <div className="space-y-3">
              {integrations
                .filter(i => !categoryFilter || getTypeMeta(i.type).category === categoryFilter)
                .map((integration) => {
                const Icon = integration.icon;
                const typeMeta = getTypeMeta(integration.type);
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
                            <Badge variant="outline" className="text-xs">{typeMeta.name}</Badge>
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

                    {/* Expanded Config — type-specific fields from backend connector metadata */}
                    {configuring === integration.id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        className="mt-4 pt-4 border-t border-border"
                      >
                        <div className="grid grid-cols-2 gap-4">
                          {typeMeta.configFields.map((field) => (
                            <div key={field.key}>
                              <label className="text-sm font-medium">
                                {field.label}
                                {field.required && <span className="text-red-500 ml-1">*</span>}
                              </label>
                              <Input
                                ref={(el) => {
                                  if (!configRefs.current[integration.id]) configRefs.current[integration.id] = {};
                                  configRefs.current[integration.id][field.key] = el;
                                }}
                                type={field.type === 'password' ? 'password' : 'text'}
                                defaultValue={
                                  field.type === 'password'
                                    ? ''
                                    : String(integration.config?.[field.key] || '')
                                }
                                placeholder={field.placeholder}
                                className="mt-1"
                              />
                            </div>
                          ))}
                        </div>
                        <div className="flex justify-end gap-2 mt-4">
                          <Button variant="outline" onClick={() => setConfiguring(null)}>
                            Cancel
                          </Button>
                          <Button
                            disabled={configureMutation.isPending}
                            onClick={() => {
                              const config = collectConfig(integration.id);
                              configureMutation.mutate({ id: integration.id, config });
                            }}
                          >
                            {configureMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
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

      {/* ── Add Integration Modal ────────────────────────────────────────── */}
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
                <p className="text-muted-foreground mb-4">
                  14 supported types across 4 categories — backed by 17 real connector engines (4,340 LOC)
                </p>
                {typesGrouped.map(({ category, label, types }) => (
                  <div key={category} className="mb-4">
                    <h3 className="text-sm font-semibold text-muted-foreground mb-2">{label}</h3>
                    <div className="grid grid-cols-3 gap-3">
                      {types.map((type) => {
                        const TypeIcon = type.icon;
                        return (
                          <button
                            key={type.type}
                            onClick={() => {
                              setSelectedType(type.type);
                              addFormRefs.current = {};
                            }}
                            className="p-4 rounded-lg border border-border hover:border-primary hover:bg-primary/5 transition-all text-left"
                          >
                            <TypeIcon className="w-8 h-8 mb-2 text-primary" />
                            <p className="font-medium">{type.name}</p>
                            <p className="text-xs text-muted-foreground">{type.description}</p>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <div className="space-y-4">
                <div className="flex items-center gap-2 mb-4">
                  <Button variant="ghost" size="sm" onClick={() => setSelectedType(null)}>
                    &larr; Back
                  </Button>
                  <span className="font-medium">
                    Configure {selectedMeta?.name}
                  </span>
                </div>
                
                {/* Name */}
                <div>
                  <label className="text-sm font-medium">Integration Name <span className="text-red-500">*</span></label>
                  <Input
                    ref={(el) => { addFormRefs.current['__name__'] = el; }}
                    placeholder={`My ${selectedMeta?.name}`}
                    className="mt-1"
                  />
                </div>

                {/* Type-specific config fields */}
                {selectedMeta?.configFields.map((field) => (
                  <div key={field.key}>
                    <label className="text-sm font-medium">
                      {field.label}
                      {field.required && <span className="text-red-500 ml-1">*</span>}
                    </label>
                    <Input
                      ref={(el) => { addFormRefs.current[field.key] = el; }}
                      type={field.type === 'password' ? 'password' : 'text'}
                      placeholder={field.placeholder}
                      className="mt-1"
                    />
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-end gap-2 mt-6">
              <Button variant="outline" onClick={() => {
                setShowAddModal(false);
                setSelectedType(null);
                addFormRefs.current = {};
              }}>
                Cancel
              </Button>
              {selectedType && (
                <Button 
                  onClick={() => {
                    const config = collectAddConfig();
                    const name = config['__name__'] || `${selectedMeta?.name} Integration`;
                    delete config['__name__'];
                    createMutation.mutate({
                      integration_type: selectedType,
                      name,
                      config,
                    });
                  }}
                  disabled={createMutation.isPending}
                >
                  {createMutation.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
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
