import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Settings as SettingsIcon,
  Key,
  Database,
  Bell,
  Globe,
  Moon,
  Sun,
  Palette,
  Save,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Server,
  Activity,
  Webhook,
  Store,
  Users,
  ChevronRight,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { useUIStore, useAuthStore } from '../stores';
import { systemApi, updateApiKey as updateApiKeyGlobal, getActiveApiKey } from '../lib/api';
import { toast } from 'sonner';

const NOTIFICATION_STORAGE_KEY = 'fixops-notification-settings';

interface NotificationSettings {
  criticalVuln: boolean;
  kevUpdates: boolean;
  complianceDeadlines: boolean;
}

const loadNotificationSettings = (): NotificationSettings => {
  try {
    const saved = localStorage.getItem(NOTIFICATION_STORAGE_KEY);
    if (saved) return JSON.parse(saved);
  } catch (e) {
    console.error('Failed to load notification settings:', e);
  }
  return { criticalVuln: true, kevUpdates: true, complianceDeadlines: false };
};

export default function Settings() {
  const navigate = useNavigate();
  const { theme, setTheme } = useUIStore();
  const { apiKey, setApiKey } = useAuthStore();
  const [newApiKey, setNewApiKey] = useState(apiKey || getActiveApiKey());
  const [apiUrl, setApiUrl] = useState('http://localhost:8000');
  const [notifications, setNotifications] = useState<NotificationSettings>(loadNotificationSettings);

  // Save notification settings when they change
  const toggleNotification = (key: keyof NotificationSettings) => {
    setNotifications(prev => {
      const updated = { ...prev, [key]: !prev[key] };
      localStorage.setItem(NOTIFICATION_STORAGE_KEY, JSON.stringify(updated));
      toast.success(`${updated[key] ? 'Enabled' : 'Disabled'} ${key === 'criticalVuln' ? 'Critical Alerts' : key === 'kevUpdates' ? 'KEV Updates' : 'Compliance Reminders'}`);
      return updated;
    });
  };

  // Fetch system status
  const { data: healthData, isLoading: healthLoading, refetch } = useQuery({
    queryKey: ['system-health'],
    queryFn: systemApi.getHealth,
    refetchInterval: 30000,
  });

  const { data: statusData, isLoading: statusLoading } = useQuery({
    queryKey: ['system-status'],
    queryFn: systemApi.getStatus,
  });

  const handleSaveApiKey = () => {
    setApiKey(newApiKey);
    updateApiKeyGlobal(newApiKey);
    toast.success('API key saved');
  };

  const handleTestConnection = async () => {
    try {
      await refetch();
      toast.success('Connection successful', {
        description: 'API is responding normally',
      });
    } catch (error) {
      toast.error('Connection failed', {
        description: 'Unable to reach the API',
      });
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <SettingsIcon className="w-8 h-8 text-primary" />
          Settings
        </h1>
        <p className="text-muted-foreground mt-1">
          Configure your ALdeci Intelligence Hub
        </p>
      </div>

      {/* Sub-navigation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card 
          className="cursor-pointer hover:border-primary/50 transition-colors"
          onClick={() => navigate('/settings/webhooks')}
        >
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="p-2 bg-primary/10 rounded-lg">
                <Webhook className="w-5 h-5 text-primary" />
              </div>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <h3 className="font-semibold">Webhooks</h3>
            <p className="text-sm text-muted-foreground">Manage webhook integrations and event mappings</p>
          </CardContent>
        </Card>

        <Card 
          className="cursor-pointer hover:border-primary/50 transition-colors"
          onClick={() => navigate('/settings/marketplace')}
        >
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="p-2 bg-green-500/10 rounded-lg">
                <Store className="w-5 h-5 text-green-500" />
              </div>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <h3 className="font-semibold">Marketplace</h3>
            <p className="text-sm text-muted-foreground">Browse and manage integrations</p>
          </CardContent>
        </Card>

        <Card 
          className="cursor-pointer hover:border-primary/50 transition-colors"
          onClick={() => navigate('/settings/users')}
        >
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <Users className="w-5 h-5 text-blue-500" />
              </div>
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
            </div>
          </CardHeader>
          <CardContent>
            <h3 className="font-semibold">Users</h3>
            <p className="text-sm text-muted-foreground">Manage users and permissions</p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="general" className="space-y-6">
        <TabsList>
          <TabsTrigger value="general">General</TabsTrigger>
          <TabsTrigger value="api">API Configuration</TabsTrigger>
          <TabsTrigger value="system">System Status</TabsTrigger>
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
        </TabsList>

        {/* General Tab */}
        <TabsContent value="general" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Notifications</CardTitle>
              <CardDescription>
                Configure how you receive alerts and updates
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Critical Vulnerability Alerts</p>
                  <p className="text-sm text-muted-foreground">
                    Get notified when critical vulnerabilities are discovered
                  </p>
                </div>
                <Button 
                  variant={notifications.criticalVuln ? 'default' : 'ghost'} 
                  size="sm"
                  onClick={() => toggleNotification('criticalVuln')}
                >
                  <Bell className="w-4 h-4 mr-2" />
                  {notifications.criticalVuln ? 'Enabled' : 'Disabled'}
                </Button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">KEV Updates</p>
                  <p className="text-sm text-muted-foreground">
                    Notifications when CISA adds new KEV entries
                  </p>
                </div>
                <Button 
                  variant={notifications.kevUpdates ? 'default' : 'ghost'} 
                  size="sm"
                  onClick={() => toggleNotification('kevUpdates')}
                >
                  <Bell className="w-4 h-4 mr-2" />
                  {notifications.kevUpdates ? 'Enabled' : 'Disabled'}
                </Button>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Compliance Deadlines</p>
                  <p className="text-sm text-muted-foreground">
                    Reminders for upcoming compliance deadlines
                  </p>
                </div>
                <Button 
                  variant={notifications.complianceDeadlines ? 'default' : 'ghost'} 
                  size="sm"
                  onClick={() => toggleNotification('complianceDeadlines')}
                >
                  <Bell className="w-4 h-4 mr-2" />
                  {notifications.complianceDeadlines ? 'Enabled' : 'Disabled'}
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Data Retention</CardTitle>
              <CardDescription>
                Configure how long data is stored
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Vulnerability History</p>
                  <p className="text-sm text-muted-foreground">
                    Historical vulnerability data retention
                  </p>
                </div>
                <Badge variant="outline">90 days</Badge>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Scan Results</p>
                  <p className="text-sm text-muted-foreground">
                    Security scan result retention
                  </p>
                </div>
                <Badge variant="outline">1 year</Badge>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Audit Logs</p>
                  <p className="text-sm text-muted-foreground">
                    System audit log retention
                  </p>
                </div>
                <Badge variant="outline">7 years</Badge>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Configuration Tab */}
        <TabsContent value="api" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Key className="w-5 h-5" />
                API Authentication
              </CardTitle>
              <CardDescription>
                Configure API connection settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">API Endpoint</label>
                <Input
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="http://localhost:8000"
                />
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">API Key</label>
                <Input
                  type="password"
                  value={newApiKey}
                  onChange={(e) => setNewApiKey(e.target.value)}
                  placeholder="Enter your API key"
                />
              </div>

              <div className="flex gap-2">
                <Button onClick={handleSaveApiKey} className="gap-2">
                  <Save className="w-4 h-4" />
                  Save
                </Button>
                <Button variant="outline" onClick={handleTestConnection} className="gap-2">
                  <RefreshCw className="w-4 h-4" />
                  Test Connection
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Integration Endpoints</CardTitle>
              <CardDescription>
                Available API endpoints for integration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {[
                  { path: '/api/v1/ingest/sbom', method: 'POST', description: 'Ingest SBOM data' },
                  { path: '/api/v1/ingest/sarif', method: 'POST', description: 'Ingest SARIF results' },
                  { path: '/api/v1/feeds/epss', method: 'GET', description: 'Get EPSS scores' },
                  { path: '/api/v1/feeds/kev', method: 'GET', description: 'Get KEV data' },
                  { path: '/api/v1/algorithms/prioritize', method: 'POST', description: 'Run prioritization' },
                  { path: '/api/v1/pentest/run', method: 'POST', description: 'Run micro-pentest' },
                ].map((endpoint, index) => (
                  <motion.div
                    key={index}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: index * 0.05 }}
                    className="flex items-center justify-between p-3 rounded-lg bg-muted/50"
                  >
                    <div className="flex items-center gap-3">
                      <Badge variant={endpoint.method === 'GET' ? 'default' : 'secondary'}>
                        {endpoint.method}
                      </Badge>
                      <code className="text-sm">{endpoint.path}</code>
                    </div>
                    <span className="text-sm text-muted-foreground">{endpoint.description}</span>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* System Status Tab */}
        <TabsContent value="system" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="w-5 h-5" />
                System Health
              </CardTitle>
              <CardDescription>
                Current system status and diagnostics
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                  <div className="flex items-center gap-3">
                    {healthData?.status === 'healthy' ? (
                      <CheckCircle2 className="w-6 h-6 text-green-500" />
                    ) : (
                      <AlertCircle className="w-6 h-6 text-yellow-500" />
                    )}
                    <div>
                      <p className="font-medium">API Server</p>
                      <p className="text-sm text-muted-foreground">
                        {healthData?.service || 'Backend API'} v{healthData?.version || statusData?.version || '1.0.0'}
                      </p>
                    </div>
                  </div>
                  <Badge variant={healthData?.status === 'healthy' ? 'default' : 'medium'}>
                    {healthLoading ? 'Checking...' : healthData?.status || 'Unknown'}
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                  <div className="flex items-center gap-3">
                    <Activity className="w-6 h-6 text-primary" />
                    <div>
                      <p className="font-medium">Service Status</p>
                      <p className="text-sm text-muted-foreground">
                        {statusData?.service || 'fixops-api'}
                      </p>
                    </div>
                  </div>
                  <Badge variant="default">
                    {statusLoading ? 'Loading...' : statusData?.status || 'OK'}
                  </Badge>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                  <div className="flex items-center gap-3">
                    <Database className="w-6 h-6 text-blue-500" />
                    <div>
                      <p className="font-medium">Database</p>
                      <p className="text-sm text-muted-foreground">MongoDB / MindsDB</p>
                    </div>
                  </div>
                  <Badge variant="default">Connected</Badge>
                </div>

                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/50">
                  <div className="flex items-center gap-3">
                    <Globe className="w-6 h-6 text-purple-500" />
                    <div>
                      <p className="font-medium">Threat Feeds</p>
                      <p className="text-sm text-muted-foreground">EPSS, KEV, NVD</p>
                    </div>
                  </div>
                  <Badge variant="default">Active</Badge>
                </div>
              </div>

              <div className="mt-6 pt-6 border-t border-border">
                <Button variant="outline" onClick={() => refetch()} className="gap-2">
                  <RefreshCw className="w-4 h-4" />
                  Refresh Status
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* System Info */}
          <Card className="glass-card">
            <CardHeader>
              <CardTitle>System Information</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Version</p>
                  <p className="font-medium">{healthData?.version || statusData?.version || '1.0.0'}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Service</p>
                  <p className="font-medium">{healthData?.service || 'fixops-api'}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">Last Updated</p>
                  <p className="font-medium">{statusData?.timestamp ? new Date(statusData.timestamp).toLocaleString() : 'N/A'}</p>
                </div>
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground">API Endpoint</p>
                  <p className="font-medium text-sm">http://localhost:8000</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Appearance Tab */}
        <TabsContent value="appearance" className="space-y-6">
          <Card className="glass-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Palette className="w-5 h-5" />
                Theme
              </CardTitle>
              <CardDescription>
                Customize the look and feel
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-4">
                <Button
                  variant={theme === 'dark' ? 'default' : 'outline'}
                  onClick={() => setTheme('dark')}
                  className="flex-1 h-24 flex-col gap-2"
                >
                  <Moon className="w-6 h-6" />
                  <span>Dark</span>
                </Button>
                <Button
                  variant={theme === 'light' ? 'default' : 'outline'}
                  onClick={() => setTheme('light')}
                  className="flex-1 h-24 flex-col gap-2"
                >
                  <Sun className="w-6 h-6" />
                  <span>Light</span>
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card className="glass-card">
            <CardHeader>
              <CardTitle>Accent Colors</CardTitle>
              <CardDescription>
                Choose your primary accent color
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-3">
                {[
                  { name: 'Green', color: 'bg-green-500' },
                  { name: 'Blue', color: 'bg-blue-500' },
                  { name: 'Purple', color: 'bg-purple-500' },
                  { name: 'Orange', color: 'bg-orange-500' },
                  { name: 'Red', color: 'bg-red-500' },
                ].map((accent) => (
                  <button
                    key={accent.name}
                    className={`w-10 h-10 rounded-full ${accent.color} ring-2 ring-offset-2 ring-offset-background ring-transparent hover:ring-white transition-all`}
                    title={accent.name}
                  />
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
