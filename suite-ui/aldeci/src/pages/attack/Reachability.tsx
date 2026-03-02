import { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Network,
  CheckCircle2,
  XCircle,
  Loader2,
  RefreshCw,
  ArrowRight,
  BarChart3,
  Shield,
  Activity,
  Eye,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { reachabilityApi } from '../../lib/api';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface ReachabilityResult {
  cve_id: string;
  reachable: boolean;
  confidence: number;
  paths?: string[][];
  attack_surface?: string[];
  hop_count?: number;
  analysis_time_ms?: number;
  risk_score?: number;
  recommendation?: string;
  evidence?: string;
  timestamp?: string;
}

interface ReachabilityMetrics {
  total_analyses?: number;
  reachable_count?: number;
  not_reachable_count?: number;
  avg_confidence?: number;
  avg_analysis_time_ms?: number;
  recent_analyses?: Array<{
    cve_id: string;
    reachable: boolean;
    confidence: number;
    timestamp: string;
  }>;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const APPLE_EASE = [0.16, 1, 0.3, 1] as const;

// ─── Animation Variants ──────────────────────────────────────────────────────

const containerVariants = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.04 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12, scale: 0.97 },
  visible: {
    opacity: 1,
    y: 0,
    scale: 1,
    transition: { ease: APPLE_EASE, duration: 0.5 },
  },
};

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function AnalysisSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {Array.from({ length: 3 }, (_, i) => (
        <div key={i} className="rounded-xl border border-gray-700/30 bg-gray-900/40 p-5">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 rounded-lg bg-gray-700/40" />
            <div className="flex-1 space-y-2">
              <div className="h-4 w-40 bg-gray-700/40 rounded" />
              <div className="h-3 w-64 bg-gray-700/30 rounded" />
            </div>
            <div className="h-8 w-20 bg-gray-700/40 rounded-full" />
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Result Card ──────────────────────────────────────────────────────────────

function ResultCard({ result }: { result: ReachabilityResult }) {
  const [showPaths, setShowPaths] = useState(false);

  const reachableConfig = result.reachable
    ? {
        icon: XCircle,
        color: 'text-red-400',
        bg: 'bg-red-500/10 border-red-500/30',
        label: 'REACHABLE',
        description: 'This CVE is reachable from the network perimeter',
      }
    : {
        icon: CheckCircle2,
        color: 'text-green-400',
        bg: 'bg-green-500/10 border-green-500/30',
        label: 'NOT REACHABLE',
        description: 'No viable attack path found to this CVE',
      };

  const Icon = reachableConfig.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ ease: APPLE_EASE, duration: 0.45 }}
      className={`rounded-xl border p-5 space-y-4 ${reachableConfig.bg}`}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${result.reachable ? 'bg-red-500/20' : 'bg-green-500/20'}`}>
            <Icon className={`w-5 h-5 ${reachableConfig.color}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-semibold text-gray-200">{result.cve_id}</span>
              <Badge className={`border ${reachableConfig.bg} ${reachableConfig.color}`}>
                {reachableConfig.label}
              </Badge>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">{reachableConfig.description}</p>
          </div>
        </div>
        {result.analysis_time_ms !== undefined && (
          <span className="text-xs text-gray-500 font-mono">{result.analysis_time_ms}ms</span>
        )}
      </div>

      {/* Confidence Bar */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-sm">
          <span className="text-gray-400">Confidence</span>
          <span className={`font-semibold ${reachableConfig.color}`}>
            {Math.round((result.confidence ?? 0) * 100)}%
          </span>
        </div>
        <Progress value={(result.confidence ?? 0) * 100} className="h-2 bg-gray-800" />
      </div>

      {/* Risk Score + Hop Count */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {result.risk_score !== undefined && (
          <div className="p-2.5 rounded-lg bg-gray-900/40 border border-gray-700/20">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Risk Score</p>
            <p className={`text-lg font-bold ${result.risk_score > 7 ? 'text-red-400' : result.risk_score > 4 ? 'text-yellow-400' : 'text-green-400'}`}>
              {result.risk_score.toFixed(1)}/10
            </p>
          </div>
        )}
        {result.hop_count !== undefined && (
          <div className="p-2.5 rounded-lg bg-gray-900/40 border border-gray-700/20">
            <p className="text-xs text-gray-500 uppercase tracking-wider">Hop Count</p>
            <p className="text-lg font-bold text-blue-400">{result.hop_count}</p>
          </div>
        )}
        {result.attack_surface && result.attack_surface.length > 0 && (
          <div className="p-2.5 rounded-lg bg-gray-900/40 border border-gray-700/20 col-span-2">
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Attack Surface</p>
            <div className="flex flex-wrap gap-1">
              {result.attack_surface.map((s, i) => (
                <Badge key={i} variant="outline" className="text-[10px] border-gray-700 text-gray-400">
                  {s}
                </Badge>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Recommendation */}
      {result.recommendation && (
        <div className="p-3 rounded-lg border border-gray-700/20 bg-gray-900/30">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Recommendation</p>
          <p className="text-sm text-gray-300">{result.recommendation}</p>
        </div>
      )}

      {/* Attack Paths */}
      {result.paths && result.paths.length > 0 && (
        <div>
          <button
            onClick={() => setShowPaths(!showPaths)}
            className="flex items-center gap-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            <Network className="w-3.5 h-3.5" />
            {showPaths ? 'Hide' : 'Show'} Attack Paths ({result.paths.length})
          </button>
          <AnimatePresence>
            {showPaths && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden mt-2 space-y-2"
              >
                {result.paths.map((path, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-gray-950/60 border border-gray-800/50 font-mono text-xs"
                  >
                    <div className="flex items-center gap-1 flex-wrap">
                      {path.map((node, ni) => (
                        <span key={ni} className="flex items-center gap-1">
                          <span className={`px-2 py-0.5 rounded ${ni === 0 ? 'bg-blue-500/20 text-blue-400' : ni === path.length - 1 ? 'bg-red-500/20 text-red-400' : 'bg-gray-700/30 text-gray-400'}`}>
                            {node}
                          </span>
                          {ni < path.length - 1 && (
                            <ArrowRight className="w-3 h-3 text-gray-600 flex-shrink-0" />
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Evidence Hash */}
      {result.evidence && (
        <div className="p-2 rounded-lg bg-gray-950/50 border border-gray-700/20">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Evidence Hash (V10)</p>
          <code className="text-[10px] font-mono text-purple-300 break-all">{result.evidence}</code>
        </div>
      )}
    </motion.div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function Reachability() {
  const queryClient = useQueryClient();
  const [cveId, setCveId] = useState('');
  const [repository, setRepository] = useState('');

  // Metrics query
  const { data: metricsData, isLoading: metricsLoading } = useQuery<ReachabilityMetrics>({
    queryKey: ['reachability-metrics'],
    queryFn: reachabilityApi.getMetrics,
    refetchInterval: 60_000,
    retry: false,
  });

  // Analyze mutation
  const analyzeMutation = useMutation({
    mutationFn: async () => {
      if (!cveId.trim()) throw new Error('CVE ID is required');
      return reachabilityApi.analyze({ cve_id: cveId.trim(), repository: repository.trim() || undefined }) as Promise<ReachabilityResult>;
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['reachability-metrics'] });
      if (data.reachable) {
        toast.error(`${cveId} is REACHABLE — ${Math.round((data.confidence ?? 0) * 100)}% confidence`, {
          duration: 6000,
        });
      } else {
        toast.success(`${cveId} is NOT REACHABLE — ${Math.round((data.confidence ?? 0) * 100)}% confidence`);
      }
    },
    onError: (err: Error) => {
      toast.error(`Analysis failed: ${err.message}`);
    },
  });

  // Fetch cached results mutation
  const fetchCachedMutation = useMutation({
    mutationFn: async () => {
      if (!cveId.trim()) throw new Error('CVE ID is required');
      return reachabilityApi.getResults(cveId.trim()) as Promise<ReachabilityResult>;
    },
    onSuccess: () => {
      toast.success('Cached results loaded');
    },
    onError: () => {
      toast.error('No cached results found for this CVE');
    },
  });

  const handleAnalyze = useCallback(() => {
    if (!cveId.trim()) {
      toast.error('Please enter a CVE ID');
      return;
    }
    analyzeMutation.mutate();
  }, [cveId, analyzeMutation]);

  const handleFetchCached = useCallback(() => {
    if (!cveId.trim()) {
      toast.error('Please enter a CVE ID');
      return;
    }
    fetchCachedMutation.mutate();
  }, [cveId, fetchCachedMutation]);

  const latestResult = analyzeMutation.data ?? fetchCachedMutation.data ?? null;
  const isAnalyzing = analyzeMutation.isPending;
  const recentAnalyses = metricsData?.recent_analyses ?? [];

  return (
    <div className="min-h-screen p-6 space-y-6">
      {/* ── Header ─────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ ease: APPLE_EASE, duration: 0.5 }}
        className="flex items-start justify-between gap-4 flex-wrap"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-blue-400 via-cyan-400 to-teal-400 bg-clip-text text-transparent">
            Reachability Analysis
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            V5 — Determine if a CVE is reachable from the network perimeter via attack path analysis
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => queryClient.invalidateQueries({ queryKey: ['reachability-metrics'] })}
          className="border-gray-700 text-gray-400 hover:text-gray-200"
        >
          <RefreshCw className="w-4 h-4 mr-1.5" />
          Refresh
        </Button>
      </motion.div>

      {/* ── Stats Row ──────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.08, ease: APPLE_EASE }}
        className="grid grid-cols-2 md:grid-cols-4 gap-3"
      >
        {[
          {
            label: 'Total Analyses',
            value: metricsLoading ? '…' : (metricsData?.total_analyses ?? 0),
            icon: Activity,
            accent: 'text-blue-400',
          },
          {
            label: 'Reachable',
            value: metricsLoading ? '…' : (metricsData?.reachable_count ?? 0),
            icon: XCircle,
            accent: 'text-red-400',
          },
          {
            label: 'Not Reachable',
            value: metricsLoading ? '…' : (metricsData?.not_reachable_count ?? 0),
            icon: Shield,
            accent: 'text-green-400',
          },
          {
            label: 'Avg Confidence',
            value: metricsLoading
              ? '…'
              : metricsData?.avg_confidence != null
              ? `${Math.round(metricsData.avg_confidence * 100)}%`
              : '—',
            icon: BarChart3,
            accent: 'text-cyan-400',
          },
        ].map(({ label, value, icon: StatIcon, accent }) => (
          <Card key={label} className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-500 uppercase tracking-wider">{label}</span>
                <StatIcon className={`w-4 h-4 ${accent}`} />
              </div>
              <div className={`text-2xl font-bold ${accent}`}>{value}</div>
            </CardContent>
          </Card>
        ))}
      </motion.div>

      {/* ── Main Tabs ──────────────────────────────────────────────────── */}
      <Tabs defaultValue="analyze">
        <TabsList className="bg-gray-900/60 border border-gray-700/40 mb-5">
          <TabsTrigger value="analyze" className="data-[state=active]:bg-blue-500/20 data-[state=active]:text-blue-300">
            <Search className="w-4 h-4 mr-2" />
            Analyze
          </TabsTrigger>
          <TabsTrigger value="recent" className="data-[state=active]:bg-blue-500/20 data-[state=active]:text-blue-300">
            <Eye className="w-4 h-4 mr-2" />
            Recent
            {recentAnalyses.length > 0 && (
              <Badge className="ml-2 bg-gray-700/50 text-gray-300 border-0 text-[10px] px-1.5">
                {recentAnalyses.length}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        {/* ── Analyze Tab ─────────────────────────────────────────────── */}
        <TabsContent value="analyze" className="space-y-5 mt-0">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader className="pb-3">
              <CardTitle className="text-base text-gray-200 flex items-center gap-2">
                <Network className="w-4 h-4 text-blue-400" />
                CVE Reachability Analysis
              </CardTitle>
              <CardDescription className="text-gray-500">
                Enter a CVE ID to determine if it&apos;s reachable from the network perimeter
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs text-gray-500 uppercase tracking-wider">CVE ID</label>
                  <Input
                    value={cveId}
                    onChange={(e) => setCveId(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
                    placeholder="CVE-2024-1234"
                    className="bg-gray-900/60 border-gray-700/50 text-gray-200 font-mono placeholder:text-gray-700 focus:border-blue-500/50"
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-gray-500 uppercase tracking-wider">Repository URL (optional)</label>
                  <Input
                    value={repository}
                    onChange={(e) => setRepository(e.target.value)}
                    placeholder="https://github.com/org/repo"
                    className="bg-gray-900/60 border-gray-700/50 text-gray-200 font-mono placeholder:text-gray-700 focus:border-blue-500/50"
                  />
                </div>
              </div>

              <div className="flex items-center gap-3">
                <Button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing || !cveId.trim()}
                  className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-semibold px-6 disabled:opacity-50"
                >
                  {isAnalyzing ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Analyzing…
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Analyze Reachability
                    </>
                  )}
                </Button>

                <Button
                  variant="outline"
                  onClick={handleFetchCached}
                  disabled={fetchCachedMutation.isPending || !cveId.trim()}
                  className="border-gray-700/50 text-gray-400 hover:text-gray-200"
                >
                  {fetchCachedMutation.isPending ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Eye className="w-4 h-4 mr-2" />
                  )}
                  Cached Results
                </Button>

                {isAnalyzing && (
                  <p className="text-xs text-gray-500 animate-pulse">
                    Scanning attack paths and network topology…
                  </p>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Result Panel */}
          <AnimatePresence mode="wait">
            {latestResult && (
              <div key="result">
                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Network className="w-4 h-4 text-blue-400" />
                  Analysis Result
                </h3>
                <ResultCard result={latestResult} />
              </div>
            )}
          </AnimatePresence>

          {/* Empty State */}
          {!latestResult && !isAnalyzing && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center justify-center gap-4 py-16 text-gray-600"
            >
              <div className="w-16 h-16 rounded-2xl bg-gray-800/60 border border-gray-700/30 flex items-center justify-center">
                <Network className="w-8 h-8 text-gray-600" />
              </div>
              <div className="text-center">
                <p className="text-sm font-medium text-gray-400">No analysis results yet</p>
                <p className="text-xs text-gray-600 mt-1">
                  Enter a CVE ID above and click &quot;Analyze Reachability&quot; to start
                </p>
              </div>
            </motion.div>
          )}
        </TabsContent>

        {/* ── Recent Tab ──────────────────────────────────────────────── */}
        <TabsContent value="recent" className="mt-0">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-base text-gray-200 flex items-center gap-2">
                <Eye className="w-4 h-4 text-cyan-400" />
                Recent Analyses
              </CardTitle>
              <Button
                variant="outline"
                size="sm"
                onClick={() => queryClient.invalidateQueries({ queryKey: ['reachability-metrics'] })}
                className="border-gray-700 text-gray-400 hover:text-gray-200"
              >
                <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
                Refresh
              </Button>
            </CardHeader>
            <CardContent>
              {metricsLoading ? (
                <AnalysisSkeleton />
              ) : recentAnalyses.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-3 py-12 text-gray-600">
                  <Network className="w-10 h-10 opacity-40" />
                  <p className="text-sm">No recent analyses. Run your first analysis above.</p>
                </div>
              ) : (
                <motion.div
                  variants={containerVariants}
                  initial="hidden"
                  animate="visible"
                  className="space-y-2"
                >
                  {recentAnalyses.map((item, i) => (
                    <motion.div
                      key={`${item.cve_id}-${i}`}
                      variants={itemVariants}
                      className="flex items-center justify-between p-3 rounded-lg border border-gray-700/20 bg-gray-800/20 hover:bg-gray-800/40 transition-colors cursor-pointer"
                      onClick={() => {
                        setCveId(item.cve_id);
                        fetchCachedMutation.mutate();
                      }}
                    >
                      <div className="flex items-center gap-3">
                        {item.reachable ? (
                          <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                        ) : (
                          <CheckCircle2 className="w-4 h-4 text-green-400 flex-shrink-0" />
                        )}
                        <div>
                          <span className="text-sm font-mono font-medium text-gray-200">
                            {item.cve_id}
                          </span>
                          <Badge
                            className={`ml-2 text-[10px] border ${
                              item.reachable
                                ? 'bg-red-500/10 text-red-400 border-red-500/20'
                                : 'bg-green-500/10 text-green-400 border-green-500/20'
                            }`}
                          >
                            {item.reachable ? 'Reachable' : 'Not Reachable'}
                          </Badge>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 text-xs">
                        <div className="flex items-center gap-1.5">
                          <Progress value={item.confidence * 100} className="w-16 h-1.5 bg-gray-800" />
                          <span className="text-gray-400 w-10 text-right">
                            {Math.round(item.confidence * 100)}%
                          </span>
                        </div>
                        <span className="text-gray-600">
                          {item.timestamp ? new Date(item.timestamp).toLocaleString() : '—'}
                        </span>
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
}
