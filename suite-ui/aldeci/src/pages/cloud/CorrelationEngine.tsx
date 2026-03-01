import { useState, useMemo } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { motion } from 'framer-motion';
import {
  GitMerge,
  Search,
  Layers,
  TrendingDown,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface Cluster {
  id: string;
  canonical_cve?: string;
  finding_count: number;
  status: string;
  severity?: string;
  created_at?: string;
  merged_findings?: string[];
  confidence?: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const statusColor = (status: string): string => {
  switch (status?.toLowerCase()) {
    case 'active':    return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'merged':    return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'reviewing': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    default:          return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const severityBar = (severity?: string): string => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-red-500';
    case 'high':     return 'bg-orange-500';
    case 'medium':   return 'bg-yellow-500';
    case 'low':      return 'bg-green-500';
    default:         return 'bg-gray-500';
  }
};

const formatDate = (iso?: string): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return iso;
  }
};

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function ClustersSkeleton() {
  return (
    <div className="space-y-3">
      {Array.from({ length: 5 }, (_, i) => (
        <div
          key={i}
          className="flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 animate-pulse"
        >
          <div className="w-1.5 h-12 bg-gray-700/40 rounded-full" />
          <div className="flex-1 space-y-2">
            <div className="h-4 w-40 bg-gray-700/40 rounded" />
            <div className="h-3 w-24 bg-gray-700/30 rounded" />
          </div>
          <div className="h-6 w-20 bg-gray-700/30 rounded" />
        </div>
      ))}
    </div>
  );
}

// ─── Animation variants ───────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { type: 'spring', stiffness: 200, damping: 22 },
  },
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function CorrelationEngine() {
  const [searchQuery, setSearchQuery] = useState('');

  // ── Data fetching ──────────────────────────────────────────────────────────

  const { data: clustersRaw, isLoading, refetch } = useQuery({
    queryKey: ['correlation-clusters'],
    queryFn: async () => {
      const res = await api.get('/api/v1/dedup/clusters');
      return res.data?.clusters || res.data?.items || res.data || [];
    },
  });

  const clusters = useMemo(() => {
    const list = (clustersRaw || []) as Cluster[];
    if (!searchQuery) return list;
    const q = searchQuery.toLowerCase();
    return list.filter(
      (c) =>
        (c.canonical_cve || '').toLowerCase().includes(q) ||
        c.status.toLowerCase().includes(q),
    );
  }, [clustersRaw, searchQuery]);

  // ── Mutation ───────────────────────────────────────────────────────────────

  const processMutation = useMutation({
    mutationFn: async () => {
      await api.post('/api/v1/dedup/process', {
        run_id: `run-${Date.now()}`,
        finding: { action: 'trigger_deduplication' },
      });
    },
    onSuccess: () => {
      toast.success('Correlation processing started');
      refetch();
    },
    onError: () => toast.error('Processing failed'),
  });

  // ── Derived stats ──────────────────────────────────────────────────────────

  const allClusters = (clustersRaw || []) as Cluster[];
  const totalClusters = allClusters.length;
  const totalMerged = allClusters.reduce((sum, c) => sum + (c.finding_count ?? 0), 0);
  const reductionRate =
    totalMerged > 0
      ? Math.round(((totalMerged - totalClusters) / totalMerged) * 100)
      : 0;

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 via-amber-400 to-yellow-400 bg-clip-text text-transparent">
            Correlation &amp; Deduplication
          </h1>
          <p className="mt-1 text-sm text-gray-400">
            Intelligent finding deduplication — reduce noise, focus on unique vulnerabilities
          </p>
        </div>

        <Button
          onClick={() => processMutation.mutate()}
          disabled={processMutation.isPending}
          className="gap-2 bg-orange-500/20 text-orange-400 border border-orange-500/30 hover:bg-orange-500/30 transition-colors"
          variant="outline"
        >
          {processMutation.isPending ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <GitMerge className="h-4 w-4" />
          )}
          {processMutation.isPending ? 'Running…' : 'Run Correlation'}
        </Button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Total Clusters */}
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2 text-gray-400">
              <Layers className="h-4 w-4 text-orange-400" />
              Total Clusters
            </CardDescription>
          </CardHeader>
          <CardContent>
            <span className="text-4xl font-bold text-white">{totalClusters}</span>
          </CardContent>
        </Card>

        {/* Total Merged Findings */}
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2 text-gray-400">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              Total Merged Findings
            </CardDescription>
          </CardHeader>
          <CardContent>
            <span className="text-4xl font-bold text-white">{totalMerged}</span>
          </CardContent>
        </Card>

        {/* Reduction Rate */}
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center gap-2 text-gray-400">
              <TrendingDown className="h-4 w-4 text-amber-400" />
              Reduction Rate
            </CardDescription>
          </CardHeader>
          <CardContent>
            <span className="text-4xl font-bold text-white">{reductionRate}%</span>
          </CardContent>
        </Card>
      </div>

      {/* Search + Cluster list */}
      <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
        <CardHeader className="pb-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <CardTitle className="text-white">Active Clusters</CardTitle>
              <CardDescription className="text-gray-400 mt-0.5">
                {clusters.length} cluster{clusters.length !== 1 ? 's' : ''} found
              </CardDescription>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
              <Input
                placeholder="Search by CVE or status…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-gray-800/60 border-gray-700/50 text-gray-200 placeholder:text-gray-500 focus-visible:ring-orange-500/40"
              />
            </div>
          </div>
        </CardHeader>

        <CardContent>
          {isLoading ? (
            <ClustersSkeleton />
          ) : clusters.length === 0 ? (
            /* Empty state */
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-gray-500">
              <Layers className="h-10 w-10 text-gray-600" />
              <p className="text-sm font-medium">No clustered findings</p>
              <p className="text-xs text-gray-600">
                Run correlation to start grouping related vulnerabilities
              </p>
            </div>
          ) : (
            <motion.div
              className="space-y-3"
              variants={containerVariants}
              initial="hidden"
              animate="visible"
            >
              {clusters.map((cluster) => (
                <motion.div
                  key={cluster.id}
                  variants={itemVariants}
                  className="flex items-center gap-4 p-4 rounded-lg border border-gray-700/30 bg-gray-800/30 hover:bg-gray-800/50 transition-colors"
                >
                  {/* Severity strip */}
                  <div
                    className={`w-1.5 h-12 rounded-full flex-shrink-0 ${severityBar(cluster.severity)}`}
                  />

                  {/* Main info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-semibold text-gray-100 truncate">
                        {cluster.canonical_cve || 'Grouped Issue'}
                      </span>
                      {cluster.severity && (
                        <span className="text-xs text-gray-500 capitalize">
                          {cluster.severity}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      <span className="text-xs text-gray-400">
                        {cluster.finding_count} finding{cluster.finding_count !== 1 ? 's' : ''} merged
                      </span>
                      {cluster.confidence !== undefined && (
                        <span className="text-xs text-gray-500">
                          {Math.round(cluster.confidence * 100)}% confidence
                        </span>
                      )}
                      {cluster.created_at && (
                        <span className="text-xs text-gray-600">
                          {formatDate(cluster.created_at)}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Right side: finding count + status */}
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge
                      variant="outline"
                      className="text-xs font-mono text-gray-400 border-gray-600/40 bg-gray-700/20"
                    >
                      {cluster.finding_count}
                    </Badge>
                    <Badge
                      variant="outline"
                      className={`text-xs capitalize border ${statusColor(cluster.status)}`}
                    >
                      {cluster.status}
                    </Badge>
                  </div>
                </motion.div>
              ))}
            </motion.div>
          )}

          {/* Error hint when no data after refetch */}
          {!isLoading && clusters.length === 0 && searchQuery && (
            <div className="flex items-center gap-2 mt-4 text-xs text-yellow-500/70">
              <AlertTriangle className="h-3.5 w-3.5" />
              No clusters match &quot;{searchQuery}&quot;
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
