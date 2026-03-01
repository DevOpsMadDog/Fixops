import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import {
  Radio, Shield, AlertTriangle, RefreshCw, Search, TrendingUp,
  Database, Clock,
} from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { feedsApi } from '../../lib/api';
import { toast } from 'sonner';

// ============================================================================
// Types
// ============================================================================

interface EPSSEntry {
  cve: string;
  cve_id?: string;
  score: number;
  epss?: number;
  percentile?: number;
  date?: string;
}

interface KEVEntry {
  cveID: string;
  cve_id?: string;
  vulnerabilityName: string;
  vendorProject: string;
  product: string;
  dateAdded: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
}

// ============================================================================
// Animation Variants
// ============================================================================

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.03 } },
};

const itemVariants = {
  hidden: { opacity: 0, x: -10 },
  visible: { opacity: 1, x: 0, transition: { type: 'spring', stiffness: 200, damping: 22 } },
};

// ============================================================================
// Skeleton
// ============================================================================

function FeedSkeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 8 }, (_, i) => (
        <div key={i} className="flex items-center gap-4 p-3 animate-pulse">
          <div className="h-4 w-32 bg-gray-700/40 rounded" />
          <div className="flex-1 h-3 bg-gray-700/30 rounded" />
          <div className="h-4 w-16 bg-gray-700/30 rounded" />
        </div>
      ))}
    </div>
  );
}

// ============================================================================
// EPSS Score Bar
// ============================================================================

function EPSSBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color = pct >= 50 ? 'bg-red-500' : pct >= 20 ? 'bg-orange-500' : pct >= 5 ? 'bg-yellow-500' : 'bg-blue-500';
  return (
    <div className="flex items-center gap-2 w-32">
      <div className="flex-1 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <motion.div
          className={`h-full ${color} rounded-full`}
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
        />
      </div>
      <span className={`text-xs font-mono ${pct >= 50 ? 'text-red-400' : pct >= 20 ? 'text-orange-400' : 'text-gray-400'}`}>
        {pct}%
      </span>
    </div>
  );
}

// ============================================================================
// Main Threat Feeds Page [V3]
// ============================================================================

export default function ThreatFeeds() {
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('epss');

  // Fetch EPSS data from real API
  const { data: epssRaw, isLoading: epssLoading, isError: epssError, refetch: refetchEpss } = useQuery({
    queryKey: ['epss-feed'],
    queryFn: () => feedsApi.getEPSS(),
    refetchInterval: 300000, // 5 min
  });

  // Fetch KEV data from real API
  const { data: kevRaw, isLoading: kevLoading, isError: kevError, refetch: refetchKev } = useQuery({
    queryKey: ['kev-feed'],
    queryFn: () => feedsApi.getKEV(),
    refetchInterval: 300000,
  });

  // Fetch feed health
  const { data: feedHealth } = useQuery({
    queryKey: ['feed-health'],
    queryFn: () => feedsApi.getHealth(),
    retry: false,
  });

  // Normalize EPSS data
  const epssData = useMemo(() => {
    const scores = epssRaw?.scores || epssRaw?.data || (Array.isArray(epssRaw) ? epssRaw : []);
    return (scores as EPSSEntry[]).sort((a, b) => (b.score || b.epss || 0) - (a.score || a.epss || 0));
  }, [epssRaw]);

  // Normalize KEV data
  const kevData = useMemo(() => {
    const entries = kevRaw?.vulnerabilities || kevRaw?.data || (Array.isArray(kevRaw) ? kevRaw : []);
    return entries as KEVEntry[];
  }, [kevRaw]);

  // Filter
  const filteredEpss = useMemo(() => {
    if (!searchQuery) return epssData.slice(0, 100); // Show top 100
    const q = searchQuery.toLowerCase();
    return epssData.filter(e => (e.cve || e.cve_id || '').toLowerCase().includes(q)).slice(0, 100);
  }, [epssData, searchQuery]);

  const filteredKev = useMemo(() => {
    if (!searchQuery) return kevData.slice(0, 100);
    const q = searchQuery.toLowerCase();
    return kevData.filter(k =>
      (k.cveID || k.cve_id || '').toLowerCase().includes(q) ||
      (k.vulnerabilityName || '').toLowerCase().includes(q) ||
      (k.vendorProject || '').toLowerCase().includes(q)
    ).slice(0, 100);
  }, [kevData, searchQuery]);

  const handleRefresh = () => {
    refetchEpss();
    refetchKev();
    toast.success('Refreshing threat feeds...');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} transition={{ type: 'spring', stiffness: 150 }}
        className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-red-400 via-orange-400 to-yellow-400 bg-clip-text text-transparent">
            Threat Intelligence Feeds
          </h1>
          <p className="text-gray-400 mt-1">Real-time EPSS vulnerability scores and CISA Known Exploited Vulnerabilities</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge className="bg-primary/20 text-primary border-primary/30 border px-3 py-1">
            <Radio className="w-3.5 h-3.5 mr-1.5" /> Live Intel
          </Badge>
          <Button variant="outline" size="sm" onClick={handleRefresh} className="border-gray-600/50 hover:border-primary/50">
            <RefreshCw className="w-4 h-4 mr-2" /> Refresh
          </Button>
        </div>
      </motion.div>

      {/* Stats Row */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
        className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'EPSS Scores', value: epssData.length, icon: TrendingUp, color: 'text-blue-400' },
          { label: 'KEV Entries', value: kevData.length, icon: AlertTriangle, color: 'text-red-400' },
          { label: 'High Risk (>50%)', value: epssData.filter(e => (e.score || e.epss || 0) >= 0.5).length, icon: Shield, color: 'text-orange-400' },
          { label: 'Feed Status', value: feedHealth?.status === 'healthy' ? 'Online' : 'Checking...', icon: Database, color: 'text-green-400' },
        ].map(stat => (
          <Card key={stat.label} className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                  <p className="text-xs text-gray-400 mt-1">{stat.label}</p>
                </div>
                <stat.icon className={`w-5 h-5 ${stat.color} opacity-60`} />
              </div>
            </CardContent>
          </Card>
        ))}
      </motion.div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <Input
          placeholder="Search CVEs..."
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          className="pl-10 bg-gray-900/40 border-gray-700/40"
        />
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-gray-900/60">
          <TabsTrigger value="epss">EPSS Scores ({epssData.length})</TabsTrigger>
          <TabsTrigger value="kev">CISA KEV ({kevData.length})</TabsTrigger>
        </TabsList>

        {/* EPSS Tab */}
        <TabsContent value="epss">
          <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-primary" />
                Exploit Prediction Scoring System
              </CardTitle>
              <CardDescription>
                Probability of exploitation in the next 30 days — sorted by risk
              </CardDescription>
            </CardHeader>
            <CardContent>
              {epssLoading ? (
                <FeedSkeleton />
              ) : epssError ? (
                <div className="text-center py-8">
                  <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-60" />
                  <p className="text-gray-400">Failed to load EPSS data</p>
                  <Button variant="outline" size="sm" onClick={() => refetchEpss()} className="mt-4 border-gray-600/50">
                    Retry
                  </Button>
                </div>
              ) : filteredEpss.length === 0 ? (
                <div className="text-center py-8">
                  <Database className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                  <p className="text-gray-400">{searchQuery ? 'No matching CVEs' : 'No EPSS data loaded'}</p>
                </div>
              ) : (
                <motion.div variants={containerVariants} initial="hidden" animate="visible"
                  className="max-h-[500px] overflow-auto divide-y divide-gray-800/30">
                  {/* Header */}
                  <div className="flex items-center gap-4 px-3 py-2 text-xs text-gray-500 font-medium sticky top-0 bg-gray-900/80 backdrop-blur-sm">
                    <span className="w-32">CVE ID</span>
                    <span className="flex-1">EPSS Score</span>
                    {filteredEpss[0]?.percentile !== undefined && <span className="w-20 text-right">Percentile</span>}
                  </div>
                  {filteredEpss.map((entry) => (
                    <motion.div key={entry.cve || entry.cve_id} variants={itemVariants}
                      className="flex items-center gap-4 px-3 py-2.5 hover:bg-gray-800/30 transition-colors">
                      <span className="w-32 font-mono text-sm text-gray-200">{entry.cve || entry.cve_id}</span>
                      <div className="flex-1">
                        <EPSSBar score={entry.score || entry.epss || 0} />
                      </div>
                      {entry.percentile !== undefined && (
                        <span className="w-20 text-right text-xs text-gray-400">
                          {Math.round(entry.percentile * 100)}th
                        </span>
                      )}
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* KEV Tab */}
        <TabsContent value="kev">
          <Card className="border-gray-700/30 bg-gray-900/30 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                CISA Known Exploited Vulnerabilities
              </CardTitle>
              <CardDescription>
                CVEs confirmed as actively exploited in the wild — mandatory remediation
              </CardDescription>
            </CardHeader>
            <CardContent>
              {kevLoading ? (
                <FeedSkeleton />
              ) : kevError ? (
                <div className="text-center py-8">
                  <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-60" />
                  <p className="text-gray-400">Failed to load KEV data</p>
                  <Button variant="outline" size="sm" onClick={() => refetchKev()} className="mt-4 border-gray-600/50">
                    Retry
                  </Button>
                </div>
              ) : filteredKev.length === 0 ? (
                <div className="text-center py-8">
                  <Database className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                  <p className="text-gray-400">{searchQuery ? 'No matching entries' : 'No KEV entries loaded'}</p>
                </div>
              ) : (
                <motion.div variants={containerVariants} initial="hidden" animate="visible"
                  className="max-h-[500px] overflow-auto space-y-2">
                  {filteredKev.map((entry) => (
                    <motion.div key={entry.cveID || entry.cve_id} variants={itemVariants}
                      className="p-3 rounded-lg border border-gray-700/30 bg-gray-800/20 hover:bg-gray-800/40 transition-all">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sm font-medium text-red-400">{entry.cveID || entry.cve_id}</span>
                            <Badge className="bg-red-500/20 text-red-400 border-red-500/30 border text-[10px]">KEV</Badge>
                          </div>
                          <p className="text-sm text-gray-300 mt-1">{entry.vulnerabilityName}</p>
                          {entry.shortDescription && (
                            <p className="text-xs text-gray-500 mt-1 line-clamp-2">{entry.shortDescription}</p>
                          )}
                          <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                            <span>{entry.vendorProject} / {entry.product}</span>
                            {entry.dateAdded && (
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" /> Added: {new Date(entry.dateAdded).toLocaleDateString()}
                              </span>
                            )}
                            {entry.dueDate && (
                              <span className="flex items-center gap-1 text-red-400">
                                <Clock className="w-3 h-3" /> Due: {new Date(entry.dueDate).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      {entry.requiredAction && (
                        <div className="mt-2 p-2 rounded bg-red-500/5 border border-red-500/20">
                          <p className="text-xs text-red-300">Required: {entry.requiredAction}</p>
                        </div>
                      )}
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
}
