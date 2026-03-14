import { useEffect, useState, useCallback, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield, AlertTriangle, Server, Activity, RefreshCw,
  Wifi, WifiOff, Cpu, HardDrive, Eye, Search,
  CheckCircle2, Zap, ChevronRight,
} from 'lucide-react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types [V5]
// ============================================================================

interface RuntimeAgent {
  hostname?: string;
  name?: string;
  id?: string;
  status: string;
  type?: string;
  cpu_usage?: number;
  memory_usage?: number;
  event_count?: number;
  last_heartbeat?: string;
  os?: string;
  version?: string;
  ip_address?: string;
  uptime_hours?: number;
}

interface SecurityEvent {
  id?: string;
  type?: string;
  event_type?: string;
  severity?: string;
  description?: string;
  message?: string;
  timestamp?: string;
  source?: string;
  agent_id?: string;
  rule_matched?: string;
  action_taken?: string;
}

// ============================================================================
// Constants
// ============================================================================

const statusConfig: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  active: { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30', dot: 'bg-green-500' },
  healthy: { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30', dot: 'bg-green-500' },
  alert: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-500' },
  warning: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-500' },
  degraded: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-500' },
  offline: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30', dot: 'bg-gray-500' },
  inactive: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30', dot: 'bg-gray-500' },
};

const defaultStatus = statusConfig.inactive;

const sevConfig: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-500/20', text: 'text-red-400' },
  high: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  medium: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  low: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  info: { bg: 'bg-gray-500/20', text: 'text-gray-400' },
};

const containerV = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.04 } },
};
const itemV = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function RuntimeSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div className="space-y-2">
          <Skeleton className="h-9 w-72" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Skeleton className="h-10 w-24" />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[1, 2, 3, 4, 5].map(i => (
          <Card key={i} className="border-border/50 bg-card/50">
            <CardContent className="pt-4 pb-3">
              <Skeleton className="h-8 w-14 mb-2" />
              <Skeleton className="h-3 w-20" />
            </CardContent>
          </Card>
        ))}
      </div>
      <Card className="border-border/50">
        <CardContent className="pt-6">
          <Skeleton className="h-4 w-full mb-4" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {[1, 2, 3, 4, 5, 6].map(i => (
              <Skeleton key={i} className="h-36 w-full rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// Agent Card
// ============================================================================

function AgentCard({ agent, index }: { agent: RuntimeAgent; index: number }) {
  const config = statusConfig[agent.status] || defaultStatus;
  const cpuUsage = agent.cpu_usage || 0;
  const memUsage = agent.memory_usage || 0;

  return (
    <motion.div variants={itemV}>
      <div
        className="p-4 border border-border/30 rounded-lg bg-card/20 hover:bg-card/40 transition-all group relative"
        role="article"
        aria-label={`Agent ${agent.hostname || agent.name || `agent-${index}`}`}
      >
        {/* Header */}
        <div className="flex justify-between items-center mb-3">
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className={`w-2 h-2 rounded-full ${config.dot}`} />
              {(agent.status === 'active' || agent.status === 'healthy') && (
                <span className={`absolute inset-0 w-2 h-2 rounded-full ${config.dot} animate-ping`} />
              )}
            </div>
            <span className="font-semibold text-foreground text-sm truncate max-w-[140px]">
              {agent.hostname || agent.name || `agent-${index}`}
            </span>
          </div>
          <Badge className={`border text-[10px] ${config.bg} ${config.text} ${config.border}`}>
            {agent.status}
          </Badge>
        </div>

        {/* Metrics */}
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Cpu className="w-3.5 h-3.5 text-muted-foreground" aria-hidden="true" />
            <span className="text-xs text-muted-foreground w-8">CPU</span>
            <Progress value={cpuUsage} className="flex-1 h-1.5" />
            <span className={`text-xs font-mono w-10 text-right ${
              cpuUsage > 80 ? 'text-red-400' : cpuUsage > 60 ? 'text-yellow-400' : 'text-foreground'
            }`}>{cpuUsage}%</span>
          </div>
          <div className="flex items-center gap-2">
            <HardDrive className="w-3.5 h-3.5 text-muted-foreground" aria-hidden="true" />
            <span className="text-xs text-muted-foreground w-8">RAM</span>
            <Progress value={memUsage} className="flex-1 h-1.5" />
            <span className={`text-xs font-mono w-10 text-right ${
              memUsage > 80 ? 'text-red-400' : memUsage > 60 ? 'text-yellow-400' : 'text-foreground'
            }`}>{memUsage}%</span>
          </div>
        </div>

        {/* Details */}
        <div className="grid grid-cols-2 gap-1 mt-3 text-[11px] text-muted-foreground">
          <div>Type: <span className="text-foreground">{agent.type || agent.os || 'linux'}</span></div>
          <div>Events: <span className="text-foreground">{agent.event_count || 0}</span></div>
          {agent.ip_address && <div>IP: <span className="text-foreground font-mono">{agent.ip_address}</span></div>}
          {agent.uptime_hours != null && <div>Uptime: <span className="text-foreground">{Math.round(agent.uptime_hours)}h</span></div>}
        </div>

        {/* Heartbeat */}
        {agent.last_heartbeat && (
          <div className="mt-2 pt-2 border-t border-border/20 flex items-center gap-1.5 text-[10px] text-muted-foreground">
            <Activity className="w-3 h-3" aria-hidden="true" />
            Last heartbeat: {new Date(agent.last_heartbeat).toLocaleTimeString()}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ============================================================================
// Event Row
// ============================================================================

function EventRow({ evt }: { evt: SecurityEvent }) {
  const sev = sevConfig[evt.severity || 'info'] || sevConfig.info;

  return (
    <motion.div variants={itemV}
      className="flex items-center justify-between p-3 border border-border/30 rounded-lg bg-card/10 hover:bg-card/30 transition-colors group"
    >
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <Badge className={`border ${sev.bg} ${sev.text} shrink-0`}>
          {(evt.severity || 'info').toUpperCase()}
        </Badge>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm text-foreground font-medium truncate">
              {evt.type || evt.event_type || 'security_event'}
            </span>
            {evt.action_taken && (
              <Badge variant="outline" className="text-[10px] shrink-0">{evt.action_taken}</Badge>
            )}
          </div>
          <p className="text-xs text-muted-foreground truncate">{evt.description || evt.message || 'No details'}</p>
        </div>
      </div>
      <div className="flex items-center gap-3 shrink-0 ml-4">
        {evt.source && <span className="text-[10px] text-muted-foreground">{evt.source}</span>}
        <span className="text-xs text-muted-foreground font-mono">
          {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A'}
        </span>
        <ChevronRight className="w-4 h-4 text-muted-foreground/50 opacity-0 group-hover:opacity-100 transition-opacity" />
      </div>
    </motion.div>
  );
}

// ============================================================================
// Main Component [V5]
// ============================================================================

const RuntimeProtection = () => {
  const [agents, setAgents] = useState<RuntimeAgent[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [eventSearch, setEventSearch] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [agentsRes, eventsRes] = await Promise.all([
        api.get('/api/v1/inventory/services').catch((e) => { console.error('[Runtime] services fetch failed:', e?.message); return { data: { agents: [], services: [] } }; }),
        api.get('/api/v1/nerve-center/state').catch((e) => { console.error('[Runtime] nerve-center fetch failed:', e?.message); return { data: { events: [], alerts: [] } }; }),
      ]);
      const agentData = agentsRes.data?.agents || agentsRes.data?.services || [];
      setAgents(Array.isArray(agentData) ? agentData : []);
      const eventData = eventsRes.data?.events || eventsRes.data?.alerts || [];
      setEvents(Array.isArray(eventData) ? eventData : []);
    } catch (e) {
      console.error('Runtime fetch error', e);
      toast.error('Failed to fetch runtime data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // Auto-refresh every 10s when enabled
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh, fetchData]);

  const activeCount = useMemo(() => agents.filter(a => a.status === 'active' || a.status === 'healthy').length, [agents]);
  const alertCount = useMemo(() => events.filter(e => e.severity === 'critical' || e.severity === 'high').length, [events]);

  const filteredEvents = useMemo(() => {
    if (!eventSearch) return events;
    const q = eventSearch.toLowerCase();
    return events.filter(e =>
      (e.type || e.event_type || '').toLowerCase().includes(q) ||
      (e.description || e.message || '').toLowerCase().includes(q) ||
      (e.severity || '').toLowerCase().includes(q) ||
      (e.source || '').toLowerCase().includes(q)
    );
  }, [events, eventSearch]);

  if (loading) return <RuntimeSkeleton />;

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ type: 'spring', stiffness: 200, damping: 22 }}
        className="flex items-center justify-between"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-rose-400 to-pink-500 bg-clip-text text-transparent">
            Runtime Protection
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time workload monitoring, threat detection, and runtime defense for applications and infrastructure
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant={autoRefresh ? 'default' : 'outline'}
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            aria-label={autoRefresh ? 'Disable auto-refresh' : 'Enable auto-refresh'}
          >
            {autoRefresh ? <Wifi className="w-4 h-4 mr-1.5" /> : <WifiOff className="w-4 h-4 mr-1.5" />}
            {autoRefresh ? 'Live' : 'Paused'}
          </Button>
          <Button variant="outline" onClick={fetchData} aria-label="Refresh data">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
        </div>
      </motion.div>

      {/* Pillar Badge */}
      <div className="flex items-center gap-3">
        <Badge className="bg-primary/20 text-primary border-primary/30 border px-3 py-1">
          <Shield className="w-3.5 h-3.5 mr-1.5" /> V5 Validate
        </Badge>
        {autoRefresh && (
          <Badge className="bg-green-500/20 text-green-400 border-green-500/30 border px-2 py-0.5">
            <span className="relative flex h-2 w-2 mr-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
            </span>
            Real-time
          </Badge>
        )}
      </div>

      {/* Stats Row */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Runtime Agents', value: agents.length, color: 'text-blue-400', icon: Server },
          { label: 'Active', value: activeCount, color: 'text-green-400', icon: CheckCircle2 },
          { label: 'Fleet Health', value: agents.length ? `${Math.round((activeCount / agents.length) * 100)}%` : '0%', color: 'text-cyan-400', icon: Activity },
          { label: 'Security Events', value: events.length, color: 'text-yellow-400', icon: Zap },
          { label: 'Critical Alerts', value: alertCount, color: alertCount > 0 ? 'text-red-400' : 'text-green-400', icon: AlertTriangle },
        ].map((s) => (
          <motion.div key={s.label} variants={itemV}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                    <div className="text-xs text-muted-foreground">{s.label}</div>
                  </div>
                  <s.icon className={`w-5 h-5 ${s.color} opacity-50`} aria-hidden="true" />
                </div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </motion.div>

      <Tabs defaultValue="agents" className="space-y-4">
        <TabsList>
          <TabsTrigger value="agents">
            <Server className="w-4 h-4 mr-1.5" /> Agents ({agents.length})
          </TabsTrigger>
          <TabsTrigger value="events">
            <Zap className="w-4 h-4 mr-1.5" /> Events ({events.length})
          </TabsTrigger>
        </TabsList>

        {/* Agents Tab */}
        <TabsContent value="agents">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="w-5 h-5 text-blue-400" />
                Runtime Agent Fleet
              </CardTitle>
              <CardDescription>
                {activeCount} of {agents.length} agents active
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Fleet Health Progress */}
              <div className="flex items-center gap-3 mb-4 p-3 rounded-lg bg-card/30 border border-border/20">
                <span className="text-sm text-muted-foreground">Fleet Health:</span>
                <Progress value={agents.length ? (activeCount / agents.length) * 100 : 0} className="flex-1 h-3" />
                <span className="text-sm font-bold text-foreground">
                  {agents.length ? Math.round((activeCount / agents.length) * 100) : 0}%
                </span>
              </div>

              {agents.length === 0 ? (
                <div className="text-center py-16">
                  <Server className="w-16 h-16 text-muted-foreground/30 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">No runtime agents deployed</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Deploy runtime protection agents to your workloads to enable real-time threat detection.
                  </p>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible"
                  className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {agents.map((agent, i) => (
                    <AgentCard key={agent.id || agent.hostname || i} agent={agent} index={i} />
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Events Tab */}
        <TabsContent value="events">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Zap className="w-5 h-5 text-yellow-400" />
                    Security Events
                  </CardTitle>
                  <CardDescription>{filteredEvents.length} events</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Search */}
              <div className="relative max-w-sm mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
                <Input
                  placeholder="Search events..."
                  value={eventSearch}
                  onChange={e => setEventSearch(e.target.value)}
                  className="pl-10 bg-gray-900/40 border-gray-700/40"
                  aria-label="Search security events"
                />
              </div>

              {filteredEvents.length === 0 ? (
                <div className="text-center py-16">
                  <Eye className="w-16 h-16 text-muted-foreground/30 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-foreground mb-2">
                    {events.length === 0 ? 'No security events detected' : 'No matching events'}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    {events.length === 0 ? 'Runtime agents are monitoring — all clear.' : 'Try a different search term.'}
                  </p>
                </div>
              ) : (
                <AnimatePresence mode="popLayout">
                  <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-2">
                    {filteredEvents.slice(0, 30).map((evt, i) => (
                      <EventRow key={evt.id || i} evt={evt} />
                    ))}
                    {filteredEvents.length > 30 && (
                      <p className="text-center text-sm text-muted-foreground py-2">
                        Showing 30 of {filteredEvents.length} events
                      </p>
                    )}
                  </motion.div>
                </AnimatePresence>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default RuntimeProtection;
