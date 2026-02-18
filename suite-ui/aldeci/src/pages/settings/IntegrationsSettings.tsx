import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { toast } from 'sonner';
import { integrationsApi, cnappConnectorsApi } from '../../lib/api';
import { Plus, Settings2, RefreshCw, Trash2, Check, Plug, Shield, Cloud, Code, AlertTriangle } from 'lucide-react';

interface ConnectorType {
  id: string;
  name: string;
  icon: string;
  category: string;
  description: string;
  configFields: string[];
}

interface ConfiguredConnector {
  id: string;
  type: string;
  name: string;
  status: 'connected' | 'disconnected' | 'error';
  last_sync?: string;
  config?: Record<string, unknown>;
}

const IntegrationsSettings = () => {
  const queryClient = useQueryClient();
  const [selectedType, setSelectedType] = useState<ConnectorType | null>(null);
  const [configDialogOpen, setConfigDialogOpen] = useState(false);
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [connectorName, setConnectorName] = useState('');

  // Fetch connector types
  const { data: connectorTypes = [] } = useQuery({
    queryKey: ['connector-types'],
    queryFn: () => cnappConnectorsApi.getConnectorTypes(),
  });

  // Fetch configured integrations
  const { data: integrations = [], isLoading, refetch } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => integrationsApi.list(),
  });

  // Create integration mutation
  const createMutation = useMutation({
    mutationFn: (data: { type: string; name: string; config: Record<string, unknown> }) =>
      cnappConnectorsApi.create(data),
    onSuccess: () => {
      toast.success('Connector created successfully');
      setConfigDialogOpen(false);
      setConfigValues({});
      setConnectorName('');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (error: any) => {
      toast.error(`Failed to create connector: ${error.message}`);
    },
  });

  // Test integration mutation
  const testMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.test(id),
    onSuccess: (result) => {
      if (result?.success) {
        toast.success('Connection test successful!');
      } else {
        toast.error(`Connection test failed: ${result?.error || 'Unknown error'}`);
      }
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (error: any) => {
      toast.error(`Test failed: ${error.message}`);
    },
  });

  // Delete integration mutation
  const deleteMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.delete(id),
    onSuccess: () => {
      toast.success('Connector deleted');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (error: any) => {
      toast.error(`Delete failed: ${error.message}`);
    },
  });

  // Sync integration mutation
  const syncMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.sync(id),
    onSuccess: () => {
      toast.success('Sync started');
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (error: any) => {
      toast.error(`Sync failed: ${error.message}`);
    },
  });

  const handleAddConnector = (type: ConnectorType) => {
    setSelectedType(type);
    setConnectorName(`${type.name} Integration`);
    setConfigValues({});
    setConfigDialogOpen(true);
  };

  const handleSaveConnector = () => {
    if (!selectedType || !connectorName.trim()) return;
    createMutation.mutate({
      type: selectedType.id,
      name: connectorName,
      config: configValues,
    });
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'cnapp': return <Shield className="w-4 h-4" />;
      case 'cloud-native': return <Cloud className="w-4 h-4" />;
      case 'sast-sca': return <Code className="w-4 h-4" />;
      default: return <Plug className="w-4 h-4" />;
    }
  };

  const getCategoryLabel = (category: string) => {
    switch (category) {
      case 'cnapp': return 'CNAPP';
      case 'cloud-native': return 'Cloud Native';
      case 'sast-sca': return 'SAST/SCA';
      default: return 'Other';
    }
  };

  const groupedTypes = connectorTypes.reduce((acc: Record<string, ConnectorType[]>, type) => {
    if (!acc[type.category]) acc[type.category] = [];
    acc[type.category].push(type);
    return acc;
  }, {});

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Integrations & Connectors</h1>
          <p className="text-muted-foreground mt-1">Connect security tools, CNAPP platforms, and DevOps systems</p>
        </div>
        <Button onClick={() => refetch()} variant="outline" size="sm">
          <RefreshCw className="w-4 h-4 mr-2" />
          Refresh
        </Button>
      </div>

      <Tabs defaultValue="available" className="space-y-6">
        <TabsList>
          <TabsTrigger value="available">Available Connectors</TabsTrigger>
          <TabsTrigger value="configured">Configured ({Array.isArray(integrations) ? integrations.length : 0})</TabsTrigger>
        </TabsList>

        <TabsContent value="available" className="space-y-6">
          {Object.entries(groupedTypes).map(([category, types]) => (
            <Card key={category}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  {getCategoryIcon(category)}
                  {getCategoryLabel(category)} Connectors
                </CardTitle>
                <CardDescription>
                  {category === 'cnapp' && 'Cloud-native application protection platforms for comprehensive cloud security'}
                  {category === 'cloud-native' && 'Native cloud provider security services'}
                  {category === 'sast-sca' && 'Static analysis and dependency scanning tools'}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {types.map((type) => (
                    <div key={type.id} className="p-4 border rounded-lg hover:border-primary/50 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-3xl">{type.icon}</span>
                          <div>
                            <h3 className="font-semibold">{type.name}</h3>
                            <p className="text-sm text-muted-foreground line-clamp-2">{type.description}</p>
                          </div>
                        </div>
                      </div>
                      <Button 
                        className="w-full mt-4" 
                        variant="outline" 
                        size="sm"
                        onClick={() => handleAddConnector(type)}
                      >
                        <Plus className="w-4 h-4 mr-2" />
                        Add Connector
                      </Button>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="configured" className="space-y-4">
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">Loading integrations...</div>
          ) : !Array.isArray(integrations) || integrations.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Plug className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Connectors Configured</h3>
                <p className="text-muted-foreground mb-4">Add connectors from the Available tab to start ingesting security data</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {integrations.map((integration: ConfiguredConnector) => (
                <Card key={integration.id}>
                  <CardContent className="py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center text-2xl">
                          {connectorTypes.find(t => t.id === integration.type)?.icon || '🔌'}
                        </div>
                        <div>
                          <h3 className="font-semibold">{integration.name}</h3>
                          <div className="flex items-center gap-2 mt-1">
                            <Badge variant={integration.status === 'connected' ? 'success' : integration.status === 'error' ? 'destructive' : 'secondary'}>
                              {integration.status === 'connected' && <Check className="w-3 h-3 mr-1" />}
                              {integration.status === 'error' && <AlertTriangle className="w-3 h-3 mr-1" />}
                              {integration.status}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              Type: {connectorTypes.find(t => t.id === integration.type)?.name || integration.type}
                            </span>
                            {integration.last_sync && (
                              <span className="text-xs text-muted-foreground">
                                Last sync: {new Date(integration.last_sync).toLocaleString()}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => syncMutation.mutate(integration.id)}
                          disabled={syncMutation.isPending}
                        >
                          <RefreshCw className={`w-4 h-4 mr-1 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                          Sync
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => testMutation.mutate(integration.id)}
                          disabled={testMutation.isPending}
                        >
                          <Check className="w-4 h-4 mr-1" />
                          Test
                        </Button>
                        <Button variant="outline" size="sm">
                          <Settings2 className="w-4 h-4" />
                        </Button>
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => {
                            if (confirm('Delete this connector?')) {
                              deleteMutation.mutate(integration.id);
                            }
                          }}
                        >
                          <Trash2 className="w-4 h-4 text-destructive" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Configuration Dialog */}
      <Dialog open={configDialogOpen} onOpenChange={setConfigDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <span className="text-2xl">{selectedType?.icon}</span>
              Configure {selectedType?.name}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="connector-name">Connector Name</Label>
              <Input
                id="connector-name"
                value={connectorName}
                onChange={(e) => setConnectorName(e.target.value)}
                placeholder="My Integration"
              />
            </div>
            {selectedType?.configFields.map((field) => (
              <div key={field} className="space-y-2">
                <Label htmlFor={field}>{field.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</Label>
                <Input
                  id={field}
                  type={field.includes('secret') || field.includes('token') || field.includes('key') ? 'password' : 'text'}
                  value={configValues[field] || ''}
                  onChange={(e) => setConfigValues(prev => ({ ...prev, [field]: e.target.value }))}
                  placeholder={`Enter ${field.replace(/_/g, ' ')}`}
                />
              </div>
            ))}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfigDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleSaveConnector} disabled={createMutation.isPending}>
              {createMutation.isPending ? 'Creating...' : 'Create Connector'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default IntegrationsSettings;
