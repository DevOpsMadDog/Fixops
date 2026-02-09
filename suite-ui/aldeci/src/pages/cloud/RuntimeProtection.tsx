import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';

const statusColor = (s: string) => {
  switch (s) {
    case 'active': return 'bg-green-500/20 text-green-400';
    case 'alert': return 'bg-red-500/20 text-red-400';
    case 'warning': return 'bg-yellow-500/20 text-yellow-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

const RuntimeProtection = () => {
  const [agents, setAgents] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [agentsRes, eventsRes] = await Promise.all([
        api.get('/api/v1/inventory/services').catch(() => ({ data: { agents: [] } })),
        api.get('/api/v1/nerve-center/state').catch(() => ({ data: { events: [] } })),
      ]);
      setAgents(agentsRes.data?.agents || []);
      setEvents(eventsRes.data?.events || []);
    } catch (e) { console.error('Runtime fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const activeCount = agents.filter((a: any) => a.status === 'active').length;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-rose-400 to-pink-500 bg-clip-text text-transparent">Runtime Protection</h1>
          <p className="text-muted-foreground mt-1">Real-time workload monitoring, threat detection, and runtime defense</p>
        </div>
        <Button variant="outline" onClick={fetchData}>Refresh</Button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Runtime Agents', value: agents.length, color: 'text-blue-400' },
          { label: 'Active', value: activeCount, color: 'text-green-400' },
          { label: 'Security Events', value: events.length, color: 'text-yellow-400' },
          { label: 'Alerts', value: events.filter((e: any) => e.severity === 'critical' || e.severity === 'high').length, color: 'text-red-400' },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Agent Status */}
      <Card className="border-border/50">
        <CardHeader><CardTitle>Runtime Agents</CardTitle></CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 mb-4">
            <span className="text-sm text-muted-foreground">Fleet Health:</span>
            <Progress value={agents.length ? (activeCount / agents.length) * 100 : 0} className="flex-1 h-3" />
            <span className="text-sm font-medium">{agents.length ? Math.round((activeCount / agents.length) * 100) : 0}%</span>
          </div>
          {loading ? <div className="text-center py-8 text-muted-foreground">Loading...</div> : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {agents.map((agent: any, i: number) => (
              <motion.div key={i} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.03 }}>
                <div className="p-4 border border-border/30 rounded-lg">
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-semibold text-foreground">{agent.hostname || agent.name || `agent-${i}`}</span>
                    <Badge className={statusColor(agent.status)}>{agent.status}</Badge>
                  </div>
                  <div className="grid grid-cols-2 gap-1 text-xs text-muted-foreground">
                    <div>Type: <span className="text-foreground">{agent.type || 'linux'}</span></div>
                    <div>CPU: <span className="text-foreground">{agent.cpu_usage || 0}%</span></div>
                    <div>Memory: <span className="text-foreground">{agent.memory_usage || 0}%</span></div>
                    <div>Events: <span className="text-foreground">{agent.event_count || 0}</span></div>
                  </div>
                </div>
              </motion.div>
            ))}
            {agents.length === 0 && <div className="col-span-3 text-center py-12 text-muted-foreground">No runtime agents deployed.</div>}
          </div>)}
        </CardContent>
      </Card>

      {/* Security Events */}
      <Card className="border-border/50">
        <CardHeader><CardTitle>Recent Security Events</CardTitle></CardHeader>
        <CardContent>
          <div className="space-y-2">
            {events.slice(0, 20).map((evt: any, i: number) => (
              <motion.div key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.02 }}
                className="flex items-center justify-between p-3 border border-border/30 rounded-lg">
                <div className="flex items-center gap-3">
                  <Badge className={statusColor(evt.severity === 'critical' ? 'alert' : evt.severity === 'high' ? 'warning' : 'active')}>{evt.severity || 'info'}</Badge>
                  <div>
                    <span className="text-sm text-foreground">{evt.type || evt.event_type || 'security_event'}</span>
                    <p className="text-xs text-muted-foreground">{evt.description || evt.message || 'No details'}</p>
                  </div>
                </div>
                <span className="text-xs text-muted-foreground">{evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : 'N/A'}</span>
              </motion.div>
            ))}
            {events.length === 0 && <div className="text-center py-12 text-muted-foreground">No security events detected.</div>}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default RuntimeProtection;

