import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Webhook,
  RefreshCw,
  Play,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Send,
  Inbox,
  RotateCw,
  Trash2,
  Activity,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../../components/ui/card';
import { Button } from '../../components/ui/button';
import { Badge } from '../../components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../../components/ui/tabs';
import { webhooksApi } from '../../lib/api';
import { toast } from 'sonner';

interface OutboxItem {
  id: string;
  connector_type: string;
  action: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  payload: unknown;
  created_at: string;
  processed_at?: string;
  error?: string;
  retries: number;
}

interface WebhookEvent {
  id: string;
  source: string;
  event_type: string;
  received_at: string;
  processed: boolean;
  payload_size: number;
}

interface DriftItem {
  id: string;
  mapping_id: string;
  connector_type: string;
  drift_type: string;
  description: string;
  detected_at: string;
  resolved: boolean;
}

interface Mapping {
  id: string;
  connector_type: string;
  name: string;
  status: string;
  last_sync?: string;
  config: Record<string, unknown>;
}

export default function Webhooks() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('outbox');

  // Fetch outbox items
  const { data: outboxData, isLoading: outboxLoading, refetch: refetchOutbox } = useQuery({
    queryKey: ['webhooks-outbox'],
    queryFn: webhooksApi.getOutbox,
  });

  // Fetch pending items
  const { data: pendingData } = useQuery({
    queryKey: ['webhooks-pending'],
    queryFn: webhooksApi.getPendingOutbox,
  });

  // Fetch outbox stats
  const { data: statsData } = useQuery({
    queryKey: ['webhooks-stats'],
    queryFn: webhooksApi.getOutboxStats,
  });

  // Fetch events
  const { data: eventsData, isLoading: eventsLoading, refetch: refetchEvents } = useQuery({
    queryKey: ['webhooks-events'],
    queryFn: () => webhooksApi.getEvents({ limit: 50 }),
    enabled: activeTab === 'events',
  });

  // Fetch drifts
  const { data: driftsData, isLoading: driftsLoading, refetch: refetchDrifts } = useQuery({
    queryKey: ['webhooks-drifts'],
    queryFn: webhooksApi.getDrifts,
    enabled: activeTab === 'drift',
  });

  // Fetch mappings
  const { data: mappingsData, isLoading: mappingsLoading, refetch: refetchMappings } = useQuery({
    queryKey: ['webhooks-mappings'],
    queryFn: webhooksApi.getMappings,
    enabled: activeTab === 'mappings',
  });

  // Execute outbox item mutation
  const executeMutation = useMutation({
    mutationFn: webhooksApi.executeOutboxItem,
    onSuccess: (_, id) => {
      toast.success(`Executed outbox item ${id}`);
      queryClient.invalidateQueries({ queryKey: ['webhooks-outbox'] });
    },
    onError: (error) => {
      toast.error(`Execute failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Retry outbox item mutation
  const retryMutation = useMutation({
    mutationFn: webhooksApi.retryOutboxItem,
    onSuccess: (_, id) => {
      toast.success(`Retrying outbox item ${id}`);
      queryClient.invalidateQueries({ queryKey: ['webhooks-outbox'] });
    },
    onError: (error) => {
      toast.error(`Retry failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Delete outbox item mutation
  const deleteMutation = useMutation({
    mutationFn: webhooksApi.deleteOutboxItem,
    onSuccess: () => {
      toast.success('Outbox item deleted');
      queryClient.invalidateQueries({ queryKey: ['webhooks-outbox'] });
    },
    onError: (error) => {
      toast.error(`Delete failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Process all pending mutation
  const processPendingMutation = useMutation({
    mutationFn: webhooksApi.processPending,
    onSuccess: (data) => {
      toast.success(`Processed ${data?.processed || 0} pending items`);
      queryClient.invalidateQueries({ queryKey: ['webhooks-outbox'] });
      queryClient.invalidateQueries({ queryKey: ['webhooks-pending'] });
    },
    onError: (error) => {
      toast.error(`Process failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Resolve drift mutation
  const resolveDriftMutation = useMutation({
    mutationFn: webhooksApi.resolveDrift,
    onSuccess: () => {
      toast.success('Drift resolved');
      queryClient.invalidateQueries({ queryKey: ['webhooks-drifts'] });
    },
    onError: (error) => {
      toast.error(`Resolve failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  // Sync mapping mutation
  const syncMappingMutation = useMutation({
    mutationFn: webhooksApi.syncMapping,
    onSuccess: () => {
      toast.success('Mapping synced');
      queryClient.invalidateQueries({ queryKey: ['webhooks-mappings'] });
    },
    onError: (error) => {
      toast.error(`Sync failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    },
  });

  const outboxItems: OutboxItem[] = outboxData?.items || outboxData || [];
  const pendingItems: OutboxItem[] = pendingData?.items || pendingData || [];
  const events: WebhookEvent[] = eventsData?.events || eventsData || [];
  const drifts: DriftItem[] = driftsData?.drifts || driftsData || [];
  const mappings: Mapping[] = mappingsData?.mappings || mappingsData || [];

  const stats = statsData || {
    total: outboxItems.length,
    pending: pendingItems.length,
    completed: outboxItems.filter(i => i.status === 'completed').length,
    failed: outboxItems.filter(i => i.status === 'failed').length,
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge variant="default" className="bg-green-500/20 text-green-400 border-green-500/30"><CheckCircle2 className="w-3 h-3 mr-1" /> Completed</Badge>;
      case 'failed':
        return <Badge variant="destructive"><XCircle className="w-3 h-3 mr-1" /> Failed</Badge>;
      case 'pending':
        return <Badge variant="secondary"><Clock className="w-3 h-3 mr-1" /> Pending</Badge>;
      case 'processing':
        return <Badge variant="default" className="bg-blue-500/20 text-blue-400 border-blue-500/30"><RefreshCw className="w-3 h-3 mr-1 animate-spin" /> Processing</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Webhook className="w-8 h-8 text-primary" />
            Webhook Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage outbound webhooks, event streams, and integration syncs
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button 
            variant="outline" 
            onClick={() => processPendingMutation.mutate()}
            disabled={processPendingMutation.isPending || stats.pending === 0}
          >
            <Play className={`w-4 h-4 mr-2 ${processPendingMutation.isPending ? 'animate-spin' : ''}`} />
            Process Pending ({stats.pending})
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="glass-card">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Total Outbox</p>
                <p className="text-3xl font-bold">{stats.total}</p>
              </div>
              <Inbox className="w-10 h-10 text-primary opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-yellow-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Pending</p>
                <p className="text-3xl font-bold text-yellow-500">{stats.pending}</p>
              </div>
              <Clock className="w-10 h-10 text-yellow-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-green-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Completed</p>
                <p className="text-3xl font-bold text-green-500">{stats.completed}</p>
              </div>
              <CheckCircle2 className="w-10 h-10 text-green-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
        
        <Card className="glass-card border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Failed</p>
                <p className="text-3xl font-bold text-red-500">{stats.failed}</p>
              </div>
              <XCircle className="w-10 h-10 text-red-500 opacity-20" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full max-w-lg grid-cols-4">
          <TabsTrigger value="outbox" className="flex items-center gap-2">
            <Send className="w-4 h-4" /> Outbox
          </TabsTrigger>
          <TabsTrigger value="events" className="flex items-center gap-2">
            <Activity className="w-4 h-4" /> Events
          </TabsTrigger>
          <TabsTrigger value="drift" className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Drift
          </TabsTrigger>
          <TabsTrigger value="mappings" className="flex items-center gap-2">
            <Webhook className="w-4 h-4" /> Mappings
          </TabsTrigger>
        </TabsList>

        {/* Outbox Tab */}
        <TabsContent value="outbox">
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Outbox Queue</CardTitle>
                <CardDescription>
                  Pending webhook deliveries and their status
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => refetchOutbox()}>
                <RefreshCw className={`w-4 h-4 mr-2 ${outboxLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </CardHeader>
            <CardContent>
              {outboxItems.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Inbox className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No outbox items</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {outboxItems.map((item) => (
                    <motion.div
                      key={item.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="flex items-center justify-between p-4 rounded-lg bg-background/50 border hover:border-primary/50 transition-colors"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 rounded-lg bg-primary/10">
                          <Send className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{item.connector_type}</span>
                            <Badge variant="outline">{item.action}</Badge>
                          </div>
                          <div className="text-sm text-muted-foreground">
                            Created: {new Date(item.created_at).toLocaleString()}
                            {item.retries > 0 && <span className="ml-2">(Retries: {item.retries})</span>}
                          </div>
                          {item.error && (
                            <div className="text-sm text-red-400 mt-1">{item.error}</div>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {getStatusBadge(item.status)}
                        <div className="flex items-center gap-1">
                          {item.status === 'pending' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => executeMutation.mutate(item.id)}
                              disabled={executeMutation.isPending}
                            >
                              <Play className="w-4 h-4" />
                            </Button>
                          )}
                          {item.status === 'failed' && (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => retryMutation.mutate(item.id)}
                              disabled={retryMutation.isPending}
                            >
                              <RotateCw className="w-4 h-4" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteMutation.mutate(item.id)}
                            disabled={deleteMutation.isPending}
                          >
                            <Trash2 className="w-4 h-4 text-red-400" />
                          </Button>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Events Tab */}
        <TabsContent value="events">
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Webhook Events</CardTitle>
                <CardDescription>
                  Incoming webhook events from external systems
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => refetchEvents()}>
                <RefreshCw className={`w-4 h-4 mr-2 ${eventsLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </CardHeader>
            <CardContent>
              {events.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No webhook events received</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {events.map((event) => (
                    <div
                      key={event.id}
                      className="flex items-center justify-between p-3 rounded-lg bg-background/50 border"
                    >
                      <div className="flex items-center gap-3">
                        <Activity className="w-4 h-4 text-primary" />
                        <div>
                          <span className="font-medium">{event.source}</span>
                          <span className="text-muted-foreground mx-2">→</span>
                          <Badge variant="outline">{event.event_type}</Badge>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-sm text-muted-foreground">
                          {new Date(event.received_at).toLocaleString()}
                        </span>
                        {event.processed ? (
                          <CheckCircle2 className="w-4 h-4 text-green-500" />
                        ) : (
                          <Clock className="w-4 h-4 text-yellow-500" />
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Drift Tab */}
        <TabsContent value="drift">
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Drift Detection</CardTitle>
                <CardDescription>
                  Detected drifts between FixOps and external systems
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => refetchDrifts()}>
                <RefreshCw className={`w-4 h-4 mr-2 ${driftsLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </CardHeader>
            <CardContent>
              {drifts.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <CheckCircle2 className="w-12 h-12 mx-auto mb-4 opacity-50 text-green-500" />
                  <p>No drift detected - all systems in sync!</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {drifts.map((drift) => (
                    <div
                      key={drift.id}
                      className="flex items-center justify-between p-4 rounded-lg bg-background/50 border border-yellow-500/30"
                    >
                      <div className="flex items-center gap-4">
                        <AlertTriangle className="w-6 h-6 text-yellow-500" />
                        <div>
                          <div className="font-medium">{drift.drift_type}</div>
                          <div className="text-sm text-muted-foreground">
                            {drift.connector_type} - {drift.description}
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">
                            Detected: {new Date(drift.detected_at).toLocaleString()}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {drift.resolved ? (
                          <Badge variant="default" className="bg-green-500/20 text-green-400">Resolved</Badge>
                        ) : (
                          <>
                            <Badge variant="secondary">Unresolved</Badge>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => resolveDriftMutation.mutate(drift.id)}
                              disabled={resolveDriftMutation.isPending}
                            >
                              Resolve
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Mappings Tab */}
        <TabsContent value="mappings">
          <Card className="glass-card">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle>Integration Mappings</CardTitle>
                <CardDescription>
                  Configured webhook endpoints and their sync status
                </CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => refetchMappings()}>
                <RefreshCw className={`w-4 h-4 mr-2 ${mappingsLoading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </CardHeader>
            <CardContent>
              {mappings.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <Webhook className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>No mappings configured</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {mappings.map((mapping) => (
                    <div
                      key={mapping.id}
                      className="flex items-center justify-between p-4 rounded-lg bg-background/50 border"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 rounded-lg bg-primary/10">
                          <Webhook className="w-5 h-5 text-primary" />
                        </div>
                        <div>
                          <div className="font-medium">{mapping.name}</div>
                          <div className="text-sm text-muted-foreground">
                            {mapping.connector_type} - Last sync: {mapping.last_sync || 'Never'}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge variant={mapping.status === 'active' ? 'default' : 'secondary'}>
                          {mapping.status}
                        </Badge>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => syncMappingMutation.mutate(mapping.id)}
                          disabled={syncMappingMutation.isPending}
                        >
                          <RefreshCw className="w-4 h-4 mr-1" />
                          Sync
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
