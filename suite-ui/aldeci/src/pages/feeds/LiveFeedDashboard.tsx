import { useEffect, useState, useCallback, useMemo } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { Input } from '@/components/ui/input';
import { motion } from 'framer-motion';
import {
  Radio, RefreshCw, Search, Activity, Wifi,
  AlertTriangle, Clock, TrendingUp, Database, Globe,
  CheckCircle2, Shield, BarChart3,
} from 'lucide-react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types [V3]
// ============================================================================

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

interface EPSSRecord {
  cve?: string;
  cve_id?: string;
  epss?: number;
  score?: number;
  percentile?: number;
  date?: string;
}

interface KEVRecord {
  cveID?: string;
  cve_id?: string;
  vulnerabilityName?: string;
  name?: string;
  vendorProject?: string;
  product?: string;
  dateAdded?: string;
  dueDate?: string;
  shortDescription?: string;
}

// ============================================================================
// Constants
// ============================================================================

const feedStatusColors: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  healthy: { bg: 'bg-green-500/20', text: 'text-green-400', border: 'border-green-500/30', dot: 'bg-green-500' },
  degraded: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-500' },
  down: { bg: 'bg-red-500/20', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-500' },
  unknown: { bg: 'bg-gray-500/20', text: 'text-gray-400', border: 'border-gray-500/30', dot: 'bg-gray-500' },
};

const feedIcons: Record<string, string> = {
  NVD: '🏛️', EPSS: '📊', KEV: '⚠️', ExploitDB: '💀', OSV: '🔓', GitHub: '🐙',
};

const containerV = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};
const itemV = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function FeedSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div className="space-y-2">
          <Skeleton className="h-9 w-72" />
          <Skeleton className="h-4 w-[28rem]" />
        </div>
        <Skeleton className="h-10 w-28" />
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
          <Skeleton className="h-4 w-48 mb-4" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {[1, 2, 3, 4, 5, 6].map(i => (
              <Skeleton key={i} className="h-40 w-full rounded-lg" />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// Feed Card
// ============================================================================

function FeedCard({ feed, onRefresh, refreshing }: {
  feed: FeedStatus;
  onRefresh: (name: string) => void;
  refreshing: string | null;
}) {
  const colors = feedStatusColors[feed.status] || feedStatusColors.unknown;

  return (
    <motion.div variants={itemV}>
      <div className="p-4 border border-border/50 rounded-lg bg-card/30 hover:bg-card/60 transition-colors">
        <div className="flex justify-between items-start mb-3">
          <div className="flex items-center gap-2">
            <span className="text-xl" role="img" aria-label={feed.name}>{feedIcons[feed.name] || '📡'}</span>
            <span className="font-semibold text-foreground">{feed.name}</span>
          </div>
          <Badge className={`border ${colors.bg} ${colors.text} ${colors.border}`}>
            <span className="relative flex h-1.5 w-1.5 mr-1.5">
              {feed.status === 'healthy' && (
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${colors.dot} opacity-75`} />
              )}
              <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${colors.dot}`} />
            </span>
            {feed.status}
          </Badge>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground mb-3">
          <div className="flex items-center gap-1">
            <Database className="w-3 h-3" aria-hidden="true" />
            <span className="text-foreground">{feed.total_records.toLocaleString()}</span> records
          </div>
          <div className="flex items-center gap-1">
            <TrendingUp className="w-3 h-3 text-green-400" aria-hidden="true" />
            <span className="text-green-400">+{feed.new_today}</span> new
          </div>
          <div className="flex items-center gap-1">
            <Activity className="w-3 h-3" aria-hidden="true" />
            <span className="text-foreground">{feed.latency_ms}ms</span> latency
          </div>
          <div className="flex items-center gap-1">
            <Clock className="w-3 h-3" aria-hidden="true" />
            <span className="text-foreground">{feed.last_update ? new Date(feed.last_update).toLocaleTimeString() : 'N/A'}</span>
          </div>
        </div>

        {/* Latency bar */}
        <div className="mb-3">
          <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-0.5">
            <span>Latency</span>
            <span className={feed.latency_ms > 500 ? 'text-red-400' : feed.latency_ms > 200 ? 'text-yellow-400' : 'text-green-400'}>
              {feed.latency_ms}ms
            </span>
          </div>
          <Progress value={Math.min((feed.latency_ms / 1000) * 100, 100)} className="h-1.5" />
        </div>

        <Button
          size="sm"
          variant="outline"
          className="w-full"
          onClick={() => onRefresh(feed.name)}
          disabled={refreshing === feed.name}
          aria-label={`Refresh ${feed.name} feed`}
        >
          {refreshing === feed.name ? (
            <><RefreshCw className="w-3 h-3 mr-1.5 animate-spin" /> Refreshing...</>
          ) : (
            <><RefreshCw className="w-3 h-3 mr-1.5" /> Refresh {feed.name}</>
          )}
        </Button>
      </div>
    </motion.div>
  );
}

// ============================================================================
// EPSS Score Bar
// ============================================================================

function EPSSScoreBar({ score }: { score: number }) {
  const pct = score * 100;
  const color = pct > 50 ? 'bg-red-500' : pct > 20 ? 'bg-orange-500' : pct > 5 ? 'bg-yellow-500' : 'bg-blue-500';

  return (
    <div className="flex items-center gap-2 w-40">
      <div className="flex-1 bg-gray-800/50 rounded-full h-2 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          className={`${color} h-full rounded-full`}
        />
      </div>
      <span className={`text-xs font-mono font-bold w-14 text-right ${
        pct > 50 ? 'text-red-400' : pct > 20 ? 'text-orange-400' : 'text-foreground'
      }`}>
        {pct.toFixed(1)}%
      </span>
    </div>
  );
}

// ============================================================================
// Main Component [V3]
// ============================================================================

const LiveFeedDashboard = () => {
  const [feeds, setFeeds] = useState<FeedStatus[]>([]);
  const [stats, setStats] = useState<FeedStats | null>(null);
  const [epssData, setEpssData] = useState<EPSSRecord[]>([]);
  const [kevData, setKevData] = useState<KEVRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState<string | null>(null);
  const [epssSearch, setEpssSearch] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [healthRes, statsRes, epssRes, kevRes] = await Promise.all([
        api.get('/api/v1/feeds/health').catch(() => ({ data: { feeds: [], status: 'unknown' } })),
        api.get('/api/v1/feeds/stats').catch(() => ({ data: { total_cves: 0, new_today: 0, sources: {} } })),
        api.get('/api/v1/feeds/epss', { params: { limit: 25 } }).catch(() => ({ data: { results: [] } })),
        api.get('/api/v1/feeds/kev', { params: { limit: 25 } }).catch(() => ({ data: { results: [] } })),
      ]);

      const healthData = healthRes.data;
      // Normalize feeds from health endpoint
      const feedList: FeedStatus[] = (healthData.feeds || []).length > 0
        ? healthData.feeds
        : ['NVD', 'EPSS', 'KEV', 'ExploitDB', 'OSV', 'GitHub'].map(name => ({
            name,
            status: healthData.status || 'unknown',
            last_update: healthData.last_check || new Date().toISOString(),
            total_records: 0,
            new_today: 0,
            latency_ms: healthData.latency || 0,
          }));

      setFeeds(feedList);
      setStats(statsRes.data);
      setEpssData(epssRes.data?.results || epssRes.data?.scores || []);
      setKevData(kevRes.data?.results || kevRes.data?.vulnerabilities || []);
    } catch (e) {
      console.error('Feed fetch error', e);
      toast.error('Failed to load feed data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleRefreshFeed = async (feedName: string) => {
    setRefreshing(feedName);
    try {
      const feedEndpoints: Record<string, string> = {
        epss: '/api/v1/feeds/epss/refresh',
        kev: '/api/v1/feeds/kev/refresh',
        nvd: '/api/v1/feeds/nvd/refresh',
        exploitdb: '/api/v1/feeds/exploitdb/refresh',
        osv: '/api/v1/feeds/osv/refresh',
        github: '/api/v1/feeds/github/refresh',
      };
      const endpoint = feedEndpoints[feedName.toLowerCase()] || '/api/v1/feeds/refresh/all';
      await api.post(endpoint).catch(() => {});
      toast.success(`${feedName} feed refreshed`);
      await fetchData();
    } catch (e) {
      toast.error(`Failed to refresh ${feedName}`);
    } finally {
      setRefreshing(null);
    }
  };

  const healthyCount = useMemo(() => feeds.filter(f => f.status === 'healthy').length, [feeds]);
  const totalFeeds = feeds.length || 6;

  // Filtered EPSS data
  const filteredEPSS = useMemo(() => {
    if (!epssSearch) return epssData;
    const q = epssSearch.toLowerCase();
    return epssData.filter(item =>
      (item.cve || item.cve_id || '').toLowerCase().includes(q)
    );
  }, [epssData, epssSearch]);

  if (loading) return <FeedSkeleton />;

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
          <h1 className="text-3xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
            Live Feed Dashboard
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time security intelligence from NVD, EPSS, KEV, ExploitDB, OSV & GitHub
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={fetchData} aria-label="Refresh all feeds">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh All
          </Button>
        </div>
      </motion.div>

      {/* Pillar Badge */}
      <div className="flex items-center gap-3">
        <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30 border px-3 py-1">
          <Radio className="w-3.5 h-3.5 mr-1.5" /> V3 Intelligence
        </Badge>
        <Badge className="bg-green-500/20 text-green-400 border-green-500/30 border px-2 py-0.5">
          <span className="relative flex h-2 w-2 mr-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
          </span>
          {healthyCount}/{totalFeeds} Feeds Active
        </Badge>
      </div>

      {/* Overview Stats */}
      <motion.div variants={containerV} initial="hidden" animate="visible"
        className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total CVEs', value: stats?.total_cves?.toLocaleString() ?? '0', color: 'text-blue-400', icon: Database },
          { label: 'New Today', value: stats?.new_today ?? 0, color: 'text-green-400', icon: TrendingUp },
          { label: 'Active Feeds', value: `${healthyCount}/${totalFeeds}`, color: 'text-cyan-400', icon: Wifi },
          { label: 'Sources', value: Object.keys(stats?.sources || {}).length, color: 'text-purple-400', icon: Globe },
          { label: 'Last Refresh', value: stats?.last_refresh ? new Date(stats.last_refresh).toLocaleTimeString() : 'N/A', color: 'text-yellow-400', icon: Clock },
        ].map(s => (
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

      {/* Feed Health Grid */}
      <Card className="border-border/50 bg-card/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Feed Health
          </CardTitle>
          <CardDescription>{healthyCount} of {totalFeeds} feeds healthy</CardDescription>
        </CardHeader>
        <CardContent>
          {/* Health Progress */}
          <div className="flex items-center gap-3 mb-4 p-3 rounded-lg bg-card/30 border border-border/20">
            <span className="text-sm text-muted-foreground">Overall Health:</span>
            <Progress value={(healthyCount / totalFeeds) * 100} className="flex-1 h-3" />
            <span className="text-sm font-bold">{Math.round((healthyCount / totalFeeds) * 100)}%</span>
          </div>

          <motion.div variants={containerV} initial="hidden" animate="visible"
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {feeds.map((feed) => (
              <FeedCard key={feed.name} feed={feed} onRefresh={handleRefreshFeed} refreshing={refreshing} />
            ))}
          </motion.div>
        </CardContent>
      </Card>

      {/* EPSS & KEV Tabs */}
      <Tabs defaultValue="epss" className="space-y-4">
        <TabsList>
          <TabsTrigger value="epss">
            <BarChart3 className="w-4 h-4 mr-1.5" /> EPSS Scores ({epssData.length})
          </TabsTrigger>
          <TabsTrigger value="kev">
            <AlertTriangle className="w-4 h-4 mr-1.5" /> CISA KEV ({kevData.length})
          </TabsTrigger>
        </TabsList>

        {/* EPSS Tab */}
        <TabsContent value="epss">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-blue-400" />
                    EPSS Exploitation Probability
                  </CardTitle>
                  <CardDescription>Exploit Prediction Scoring System — probability of exploitation in the next 30 days</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {/* Search */}
              <div className="relative max-w-sm mb-4">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" aria-hidden="true" />
                <Input
                  placeholder="Search CVE..."
                  value={epssSearch}
                  onChange={e => setEpssSearch(e.target.value)}
                  className="pl-10 bg-gray-900/40 border-gray-700/40"
                  aria-label="Search EPSS scores by CVE"
                />
              </div>

              {filteredEPSS.length === 0 ? (
                <div className="text-center py-12">
                  <BarChart3 className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">
                    {epssData.length === 0 ? 'No EPSS data available. Refresh the EPSS feed.' : 'No matching CVEs found.'}
                  </p>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-2">
                  {filteredEPSS.slice(0, 20).map((item, i) => (
                    <motion.div key={i} variants={itemV}
                      className="flex items-center justify-between p-3 border border-border/30 rounded-lg bg-card/10 hover:bg-card/30 transition-colors">
                      <div className="flex items-center gap-3">
                        <Shield className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
                        <span className="font-mono text-sm text-foreground">{item.cve || item.cve_id || 'N/A'}</span>
                      </div>
                      <EPSSScoreBar score={item.epss || item.score || 0} />
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* KEV Tab */}
        <TabsContent value="kev">
          <Card className="border-border/50 bg-card/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                CISA Known Exploited Vulnerabilities
              </CardTitle>
              <CardDescription>Mandatory remediation catalog — actively exploited in the wild</CardDescription>
            </CardHeader>
            <CardContent>
              {kevData.length === 0 ? (
                <div className="text-center py-12">
                  <CheckCircle2 className="w-12 h-12 text-green-500/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">No KEV data available. Refresh the KEV feed.</p>
                </div>
              ) : (
                <motion.div variants={containerV} initial="hidden" animate="visible" className="space-y-2">
                  {kevData.slice(0, 20).map((item, i) => (
                    <motion.div key={i} variants={itemV}
                      className="p-3 border border-border/30 rounded-lg bg-card/10 hover:bg-card/30 transition-colors">
                      <div className="flex justify-between items-start">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono text-sm text-foreground">{item.cveID || item.cve_id || 'N/A'}</span>
                            <Badge variant="destructive" className="text-[10px]">KEV</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground truncate">
                            {item.vulnerabilityName || item.name || 'No description'}
                          </p>
                          <div className="flex items-center gap-3 mt-1 text-[10px] text-muted-foreground">
                            {item.vendorProject && <span>Vendor: <span className="text-foreground">{item.vendorProject}</span></span>}
                            {item.product && <span>Product: <span className="text-foreground">{item.product}</span></span>}
                            {item.dateAdded && <span>Added: <span className="text-foreground">{item.dateAdded}</span></span>}
                          </div>
                        </div>
                        {item.dueDate && (
                          <div className="text-right shrink-0 ml-4">
                            <div className="text-[10px] text-muted-foreground">Due Date</div>
                            <div className="text-xs font-mono text-red-400">{item.dueDate}</div>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default LiveFeedDashboard;
