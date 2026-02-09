import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { motion } from 'framer-motion';
import { api } from '../../lib/api';

interface FeedStatus {
  name: string;
  status: 'healthy' | 'degraded' | 'down' | 'unknown';
  last_update: string;
  total_records: number;
  new_today: number;
  latency_ms: number;
}

interface FeedStats {
  total_cves: number;
  new_today: number;
  sources: Record<string, number>;
  last_refresh: string;
}

const feedStatusColor = (s: string) => {
  switch (s) {
    case 'healthy': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'degraded': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'down': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const feedIcons: Record<string, string> = {
  NVD: '🏛️', EPSS: '📊', KEV: '⚠️', ExploitDB: '💀', OSV: '🔓', GitHub: '🐙',
};

const LiveFeedDashboard = () => {
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [stats, setStats] = useState<FeedStats | null>(null);
  const [epssData, setEpssData] = useState<any[]>([]);
  const [kevData, setKevData] = useState<any[]>([]);
  const [, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [healthRes, statsRes, epssRes, kevRes] = await Promise.all([
        api.get('/api/v1/feeds/health').catch(() => ({ data: { feeds: [], status: 'unknown' } })),
        api.get('/api/v1/feeds/stats').catch(() => ({ data: { total_cves: 0, new_today: 0, sources: {} } })),
        api.get('/api/v1/feeds/epss', { params: { limit: 20 } }).catch(() => ({ data: { results: [] } })),
        api.get('/api/v1/feeds/kev', { params: { limit: 20 } }).catch(() => ({ data: { results: [] } })),
      ]);
      const healthData = healthRes.data;
      // Normalize feeds from health endpoint
      const feedList: FeedStatus[] = (healthData.feeds || []).length > 0 ? healthData.feeds :
        ['NVD', 'EPSS', 'KEV', 'ExploitDB', 'OSV', 'GitHub'].map(name => ({
          name, status: healthData.status || 'unknown', last_update: healthData.last_check || new Date().toISOString(),
          total_records: 0, new_today: 0, latency_ms: healthData.latency || 0,
        }));
      setFeeds(feedList);
      setStats(statsRes.data);
      setEpssData(epssRes.data?.results || epssRes.data?.scores || []);
      setKevData(kevRes.data?.results || kevRes.data?.vulnerabilities || []);
    } catch (e) { console.error('Feed fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleRefreshFeed = async (feedName: string) => {
    setRefreshing(feedName);
    try {
      await api.post('/api/v1/feeds/refresh', { source: feedName.toLowerCase() }).catch(() => {});
      await fetchData();
    } catch (e) { console.error('Refresh error', e); }
    finally { setRefreshing(null); }
  };

  const healthyCount = feeds.filter(f => f.status === 'healthy').length;
  const totalFeeds = feeds.length || 6;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">Live Feed Dashboard</h1>
          <p className="text-muted-foreground mt-1">Real-time security intelligence from NVD, EPSS, KEV, ExploitDB, OSV & GitHub</p>
        </div>
        <Button variant="outline" onClick={fetchData}>Refresh All</Button>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total CVEs', value: stats?.total_cves ?? 0, color: 'text-blue-400' },
          { label: 'New Today', value: stats?.new_today ?? 0, color: 'text-green-400' },
          { label: 'Active Feeds', value: `${healthyCount}/${totalFeeds}`, color: 'text-cyan-400' },
          { label: 'Sources', value: Object.keys(stats?.sources || {}).length, color: 'text-purple-400' },
          { label: 'Last Refresh', value: stats?.last_refresh ? new Date(stats.last_refresh).toLocaleTimeString() : 'N/A', color: 'text-yellow-400' },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <Card className="border-border/50 bg-card/50">
              <CardContent className="pt-4 pb-3">
                <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Feed Health Overview */}
      <Card className="border-border/50">
        <CardHeader><CardTitle>Feed Health</CardTitle></CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 mb-4">
            <span className="text-sm text-muted-foreground">Overall Health:</span>
            <Progress value={(healthyCount / totalFeeds) * 100} className="flex-1 h-3" />
            <span className="text-sm font-medium">{Math.round((healthyCount / totalFeeds) * 100)}%</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {feeds.map((feed, i) => (
              <motion.div key={feed.name} initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.05 }}>
                <div className="p-4 border border-border/50 rounded-lg bg-card/30 hover:bg-card/60 transition-colors">
                  <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xl">{feedIcons[feed.name] || '📡'}</span>
                      <span className="font-semibold text-foreground">{feed.name}</span>
                    </div>
                    <Badge className={feedStatusColor(feed.status)}>{feed.status}</Badge>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground mb-3">
                    <div>Records: <span className="text-foreground">{feed.total_records.toLocaleString()}</span></div>
                    <div>New: <span className="text-green-400">+{feed.new_today}</span></div>
                    <div>Latency: <span className="text-foreground">{feed.latency_ms}ms</span></div>
                    <div>Updated: <span className="text-foreground">{feed.last_update ? new Date(feed.last_update).toLocaleTimeString() : 'N/A'}</span></div>
                  </div>
                  <Button size="sm" variant="outline" className="w-full" onClick={() => handleRefreshFeed(feed.name)} disabled={refreshing === feed.name}>
                    {refreshing === feed.name ? 'Refreshing...' : `Refresh ${feed.name}`}
                  </Button>
                </div>
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* EPSS & KEV Data Tabs */}
      <Tabs defaultValue="epss" className="space-y-4">
        <TabsList>
          <TabsTrigger value="epss">📊 EPSS Scores ({epssData.length})</TabsTrigger>
          <TabsTrigger value="kev">⚠️ KEV Catalog ({kevData.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="epss">
          <Card className="border-border/50">
            <CardContent className="pt-6">
              <div className="space-y-2">{epssData.slice(0, 15).map((item: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-3 border border-border/30 rounded-lg">
                  <div><span className="font-mono text-sm text-foreground">{item.cve || item.cve_id || 'N/A'}</span></div>
                  <div className="flex items-center gap-3">
                    <Progress value={(item.epss || item.score || 0) * 100} className="w-32 h-2" />
                    <span className="text-sm font-medium w-16 text-right">{((item.epss || item.score || 0) * 100).toFixed(1)}%</span>
                  </div>
                </div>
              ))}{epssData.length === 0 && <div className="text-center py-8 text-muted-foreground">No EPSS data available.</div>}</div>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="kev">
          <Card className="border-border/50">
            <CardContent className="pt-6">
              <div className="space-y-2">{kevData.slice(0, 15).map((item: any, i: number) => (
                <div key={i} className="p-3 border border-border/30 rounded-lg">
                  <div className="flex justify-between items-start">
                    <div>
                      <span className="font-mono text-sm text-foreground">{item.cveID || item.cve_id || 'N/A'}</span>
                      <p className="text-xs text-muted-foreground mt-1">{item.vulnerabilityName || item.name || 'No description'}</p>
                    </div>
                    <Badge variant="destructive">KEV</Badge>
                  </div>
                </div>
              ))}{kevData.length === 0 && <div className="text-center py-8 text-muted-foreground">No KEV data available.</div>}</div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default LiveFeedDashboard;

