/**
 * FAIL Engine Dashboard — Validate Space [V3/V5]
 *
 * FAIL = Fixability, Attainability, Impact, Legitimacy
 * Shows real-time risk scoring, top risks, score distribution, and
 * allows users to score individual findings through the FAIL engine.
 *
 * API: /api/v1/fail/* (all endpoints verified 200)
 * Pillar: V3 (Decision Intelligence) + V5 (MPTE Verification)
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { motion } from 'framer-motion';
import { toast } from 'sonner';
import {
  AlertTriangle,
  TrendingUp,
  BarChart3,
  Target,
  ShieldAlert,
  ArrowUpRight,
  Loader2,
  Trash2,
  RefreshCw,
  Filter,
  Download,
  Activity,
  Zap,
  FileWarning,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card';
import { Badge } from '../../components/ui/badge';
import { Button } from '../../components/ui/button';
import { Input } from '../../components/ui/input';
import { Skeleton } from '../../components/ui/skeleton';
import { failApi } from '../../lib/api';

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

interface FAILScore {
  id: string;
  cve_id?: string;
  finding_id?: string;
  title: string;
  fail_score: number;
  fixability: number;
  attainability: number;
  impact: number;
  legitimacy: number;
  risk_level: string;
  scored_at?: string;
}

interface FAILStats {
  total_scores: number;
  avg_score: number;
  max_score: number;
  min_score: number;
  risk_distribution: Record<string, number>;
  recent_scores: number;
}

// ═══════════════════════════════════════════════════════════════════════════
// Animation
// ═══════════════════════════════════════════════════════════════════════════

const containerVariants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.05 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 12 },
  show: { opacity: 1, y: 0, transition: { ease: [0.16, 1, 0.3, 1], duration: 0.4 } },
};

// ═══════════════════════════════════════════════════════════════════════════
// Helper: Risk color
// ═══════════════════════════════════════════════════════════════════════════

function riskColor(level: string): string {
  switch (level?.toLowerCase()) {
    case 'critical': return 'text-red-400 bg-red-500/15 border-red-500/30';
    case 'high': return 'text-orange-400 bg-orange-500/15 border-orange-500/30';
    case 'medium': return 'text-yellow-400 bg-yellow-500/15 border-yellow-500/30';
    case 'low': return 'text-blue-400 bg-blue-500/15 border-blue-500/30';
    default: return 'text-gray-400 bg-gray-500/15 border-gray-500/30';
  }
}

function scoreColor(score: number): string {
  if (score >= 8) return 'text-red-400';
  if (score >= 6) return 'text-orange-400';
  if (score >= 4) return 'text-yellow-400';
  return 'text-emerald-400';
}

function scoreBarColor(score: number): string {
  if (score >= 8) return 'bg-red-500';
  if (score >= 6) return 'bg-orange-500';
  if (score >= 4) return 'bg-yellow-500';
  return 'bg-emerald-500';
}

// ═══════════════════════════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════════════════════════

export default function FAILEngineDashboard() {
  const queryClient = useQueryClient();
  const [scoreInput, setScoreInput] = useState({
    cve_id: '',
    title: '',
    cvss_score: '',
    epss_score: '',
    is_kev: false,
    has_exploit: false,
  });
  const [filterSearch, setFilterSearch] = useState('');

  // ── Real API queries ──────────────────────────────────────────────────
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['fail-stats'],
    queryFn: () => failApi.stats(),
    refetchInterval: 30_000,
  });

  const { data: topRisks, isLoading: risksLoading } = useQuery({
    queryKey: ['fail-top-risks'],
    queryFn: () => failApi.topRisks(20),
  });

  const { data: health } = useQuery({
    queryKey: ['fail-health'],
    queryFn: () => failApi.health(),
  });

  const { data: allScores, isLoading: scoresLoading } = useQuery({
    queryKey: ['fail-scores'],
    queryFn: () => failApi.listScores({ limit: 50 }),
  });

  // ── Score mutation ────────────────────────────────────────────────────
  const scoreMutation = useMutation({
    mutationFn: (data: Record<string, unknown>) => failApi.score(data),
    onSuccess: (result) => {
      toast.success(`FAIL Score: ${(result?.fail_score ?? result?.score ?? 0).toFixed(1)} — ${result?.risk_level ?? 'scored'}`);
      queryClient.invalidateQueries({ queryKey: ['fail-stats'] });
      queryClient.invalidateQueries({ queryKey: ['fail-top-risks'] });
      queryClient.invalidateQueries({ queryKey: ['fail-scores'] });
      setScoreInput({ cve_id: '', title: '', cvss_score: '', epss_score: '', is_kev: false, has_exploit: false });
    },
    onError: (err: Error) => toast.error(`Scoring failed: ${err.message}`),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => failApi.deleteScore(id),
    onSuccess: () => {
      toast.success('Score deleted');
      queryClient.invalidateQueries({ queryKey: ['fail-scores'] });
      queryClient.invalidateQueries({ queryKey: ['fail-stats'] });
    },
    onError: (err: Error) => toast.error(`Delete failed: ${err.message}`),
  });

  const handleScore = () => {
    if (!scoreInput.title && !scoreInput.cve_id) {
      toast.error('Provide a CVE ID or title');
      return;
    }
    scoreMutation.mutate({
      cve_id: scoreInput.cve_id || undefined,
      title: scoreInput.title || scoreInput.cve_id,
      cvss_score: scoreInput.cvss_score ? parseFloat(scoreInput.cvss_score) : undefined,
      epss_score: scoreInput.epss_score ? parseFloat(scoreInput.epss_score) : undefined,
      is_kev: scoreInput.is_kev,
      has_exploit: scoreInput.has_exploit,
    });
  };

  // Parse response data
  const statsData: FAILStats | null = stats ?? null;
  const topRisksList: FAILScore[] = (topRisks?.items || topRisks?.scores || topRisks || []) as FAILScore[];
  const scoresList: FAILScore[] = (allScores?.items || allScores?.scores || allScores || []) as FAILScore[];

  // Filter scores
  const filteredScores = filterSearch
    ? scoresList.filter(s =>
        (s.cve_id?.toLowerCase().includes(filterSearch.toLowerCase())) ||
        (s.title?.toLowerCase().includes(filterSearch.toLowerCase()))
      )
    : scoresList;

  // Risk distribution for visual
  const distribution = statsData?.risk_distribution ?? {};
  const distTotal = Object.values(distribution).reduce((a, b) => a + b, 0) || 1;

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* ═══ Header ═══ */}
      <motion.div variants={itemVariants} className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-orange-500/15 border border-orange-500/30">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">FAIL Engine</h1>
              <p className="text-sm text-muted-foreground">
                Fixability · Attainability · Impact · Legitimacy — V3 Decision Intelligence
              </p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {health && (
            <Badge variant="outline" className="border-emerald-500/30 text-emerald-400 bg-emerald-500/10">
              <Activity className="w-3 h-3 mr-1" />
              Engine {health.status || 'Online'}
            </Badge>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['fail-stats'] });
              queryClient.invalidateQueries({ queryKey: ['fail-top-risks'] });
              queryClient.invalidateQueries({ queryKey: ['fail-scores'] });
              toast.success('Refreshed FAIL data');
            }}
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </motion.div>

      {/* ═══ Stats Cards ═══ */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {statsLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Card key={i} className="border-gray-700/30 bg-gray-900/40">
              <CardContent className="p-5">
                <Skeleton className="h-3 w-20 mb-3" />
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))
        ) : (
          <>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Total Scored</span>
                  <BarChart3 className="w-4 h-4 text-indigo-400" />
                </div>
                <div className="text-3xl font-bold tabular-nums">{statsData?.total_scores ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">findings evaluated</p>
              </CardContent>
            </Card>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Avg Score</span>
                  <TrendingUp className="w-4 h-4 text-orange-400" />
                </div>
                <div className={`text-3xl font-bold tabular-nums ${scoreColor(statsData?.avg_score ?? 0)}`}>
                  {(statsData?.avg_score ?? 0).toFixed(1)}
                </div>
                <p className="text-xs text-muted-foreground mt-1">out of 10.0</p>
              </CardContent>
            </Card>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Max Score</span>
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                </div>
                <div className={`text-3xl font-bold tabular-nums ${scoreColor(statsData?.max_score ?? 0)}`}>
                  {(statsData?.max_score ?? 0).toFixed(1)}
                </div>
                <p className="text-xs text-muted-foreground mt-1">highest risk finding</p>
              </CardContent>
            </Card>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardContent className="p-5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Recent</span>
                  <Zap className="w-4 h-4 text-yellow-400" />
                </div>
                <div className="text-3xl font-bold tabular-nums">{statsData?.recent_scores ?? 0}</div>
                <p className="text-xs text-muted-foreground mt-1">scored in last 24h</p>
              </CardContent>
            </Card>
          </>
        )}
      </motion.div>

      {/* ═══ Risk Distribution ═══ */}
      <motion.div variants={itemVariants}>
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-3">
            <CardTitle className="text-base font-semibold">Risk Distribution</CardTitle>
            <CardDescription>How findings are distributed across risk levels</CardDescription>
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <div className="space-y-3">
                {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-6 w-full" />)}
              </div>
            ) : Object.keys(distribution).length > 0 ? (
              <div className="space-y-3">
                {['critical', 'high', 'medium', 'low'].map(level => {
                  const count = distribution[level] ?? 0;
                  const pct = Math.round((count / distTotal) * 100);
                  return (
                    <div key={level} className="flex items-center gap-3">
                      <Badge variant="outline" className={`w-20 justify-center text-xs ${riskColor(level)}`}>
                        {level}
                      </Badge>
                      <div className="flex-1 h-5 bg-gray-800/60 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ delay: 0.3, duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                          className={`h-full rounded-full ${
                            level === 'critical' ? 'bg-red-500/60' :
                            level === 'high' ? 'bg-orange-500/60' :
                            level === 'medium' ? 'bg-yellow-500/60' :
                            'bg-blue-500/60'
                          }`}
                        />
                      </div>
                      <span className="text-sm tabular-nums w-16 text-right text-muted-foreground">
                        {count} ({pct}%)
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-center py-8">
                <FileWarning className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No scores yet — use the scoring panel below to evaluate findings</p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* ═══ Score a Finding ═══ */}
        <motion.div variants={itemVariants}>
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold flex items-center gap-2">
                <Target className="w-4 h-4 text-orange-400" />
                Score a Finding
              </CardTitle>
              <CardDescription>Run the FAIL algorithm on a vulnerability</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Input
                placeholder="CVE-2024-3400"
                value={scoreInput.cve_id}
                onChange={e => setScoreInput(p => ({ ...p, cve_id: e.target.value }))}
                className="bg-gray-800/40 border-gray-700/40 text-sm"
              />
              <Input
                placeholder="Vulnerability title"
                value={scoreInput.title}
                onChange={e => setScoreInput(p => ({ ...p, title: e.target.value }))}
                className="bg-gray-800/40 border-gray-700/40 text-sm"
              />
              <div className="grid grid-cols-2 gap-2">
                <Input
                  placeholder="CVSS (0-10)"
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={scoreInput.cvss_score}
                  onChange={e => setScoreInput(p => ({ ...p, cvss_score: e.target.value }))}
                  className="bg-gray-800/40 border-gray-700/40 text-sm"
                />
                <Input
                  placeholder="EPSS (0-1)"
                  type="number"
                  step="0.01"
                  min="0"
                  max="1"
                  value={scoreInput.epss_score}
                  onChange={e => setScoreInput(p => ({ ...p, epss_score: e.target.value }))}
                  className="bg-gray-800/40 border-gray-700/40 text-sm"
                />
              </div>
              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
                  <input
                    type="checkbox"
                    checked={scoreInput.is_kev}
                    onChange={e => setScoreInput(p => ({ ...p, is_kev: e.target.checked }))}
                    className="rounded border-gray-600"
                  />
                  In CISA KEV
                </label>
                <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
                  <input
                    type="checkbox"
                    checked={scoreInput.has_exploit}
                    onChange={e => setScoreInput(p => ({ ...p, has_exploit: e.target.checked }))}
                    className="rounded border-gray-600"
                  />
                  Exploit exists
                </label>
              </div>
              <Button
                className="w-full"
                onClick={handleScore}
                disabled={scoreMutation.isPending}
              >
                {scoreMutation.isPending ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Zap className="w-4 h-4 mr-2" />
                )}
                Calculate FAIL Score
              </Button>

              {/* Show last result */}
              {scoreMutation.data && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-3 rounded-lg border border-gray-700/30 bg-gray-800/30"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-muted-foreground uppercase">Result</span>
                    <Badge variant="outline" className={riskColor(scoreMutation.data.risk_level || 'medium')}>
                      {scoreMutation.data.risk_level || 'unknown'}
                    </Badge>
                  </div>
                  <div className={`text-2xl font-bold tabular-nums ${scoreColor(scoreMutation.data.fail_score ?? scoreMutation.data.score ?? 0)}`}>
                    {(scoreMutation.data.fail_score ?? scoreMutation.data.score ?? 0).toFixed(2)}
                  </div>
                  <div className="grid grid-cols-2 gap-1 mt-2 text-xs text-muted-foreground">
                    <span>F: {(scoreMutation.data.fixability ?? 0).toFixed(1)}</span>
                    <span>A: {(scoreMutation.data.attainability ?? 0).toFixed(1)}</span>
                    <span>I: {(scoreMutation.data.impact ?? 0).toFixed(1)}</span>
                    <span>L: {(scoreMutation.data.legitimacy ?? 0).toFixed(1)}</span>
                  </div>
                </motion.div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* ═══ Top Risks ═══ */}
        <motion.div variants={itemVariants} className="lg:col-span-2">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md h-full">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base font-semibold flex items-center gap-2">
                    <ArrowUpRight className="w-4 h-4 text-red-400" />
                    Top Risks by FAIL Score
                  </CardTitle>
                  <CardDescription>Highest-priority findings ranked by the FAIL algorithm</CardDescription>
                </div>
                <Button variant="outline" size="sm" className="text-xs">
                  <Download className="w-3.5 h-3.5 mr-1.5" />
                  Export
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {risksLoading ? (
                <div className="space-y-2">
                  {Array.from({ length: 5 }).map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full" />
                  ))}
                </div>
              ) : topRisksList.length > 0 ? (
                <div className="space-y-2 max-h-[400px] overflow-y-auto scrollbar-thin pr-1">
                  {topRisksList.slice(0, 15).map((risk, idx) => (
                    <motion.div
                      key={risk.id || idx}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.03 }}
                      className="flex items-center gap-3 p-3 rounded-lg border border-gray-700/20 bg-gray-800/20 hover:bg-gray-800/40 transition-colors"
                    >
                      <span className="text-xs text-muted-foreground tabular-nums w-5">#{idx + 1}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          {risk.cve_id && (
                            <span className="text-xs font-mono text-orange-300">{risk.cve_id}</span>
                          )}
                          <span className="text-sm truncate">{risk.title || 'Untitled'}</span>
                        </div>
                      </div>
                      <Badge variant="outline" className={`text-xs ${riskColor(risk.risk_level)}`}>
                        {risk.risk_level}
                      </Badge>
                      <div className="w-20 flex items-center gap-2">
                        <div className="flex-1 h-1.5 bg-gray-800/60 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${scoreBarColor(risk.fail_score)}`}
                            style={{ width: `${(risk.fail_score / 10) * 100}%` }}
                          />
                        </div>
                        <span className={`text-xs tabular-nums font-semibold ${scoreColor(risk.fail_score)}`}>
                          {risk.fail_score?.toFixed(1)}
                        </span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-10">
                  <ShieldAlert className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">No risks scored yet</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">Score findings using the panel on the left</p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ═══ All Scores Table ═══ */}
      <motion.div variants={itemVariants}>
        <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-base font-semibold">Score History</CardTitle>
                <CardDescription>All FAIL scores computed by the engine</CardDescription>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Filter by CVE or title..."
                    value={filterSearch}
                    onChange={e => setFilterSearch(e.target.value)}
                    className="pl-9 h-8 text-xs w-56 bg-gray-800/40 border-gray-700/40"
                  />
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {scoresLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 8 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : filteredScores.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700/30 text-xs text-muted-foreground uppercase">
                      <th className="text-left py-2 px-3 font-medium">CVE / Title</th>
                      <th className="text-center py-2 px-2 font-medium">F</th>
                      <th className="text-center py-2 px-2 font-medium">A</th>
                      <th className="text-center py-2 px-2 font-medium">I</th>
                      <th className="text-center py-2 px-2 font-medium">L</th>
                      <th className="text-center py-2 px-3 font-medium">Score</th>
                      <th className="text-center py-2 px-3 font-medium">Risk</th>
                      <th className="text-right py-2 px-3 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredScores.slice(0, 50).map((s, idx) => (
                      <tr
                        key={s.id || idx}
                        className="border-b border-gray-700/10 hover:bg-gray-800/20 transition-colors"
                      >
                        <td className="py-2.5 px-3">
                          <div className="flex flex-col">
                            {s.cve_id && <span className="text-xs font-mono text-orange-300">{s.cve_id}</span>}
                            <span className="text-xs text-muted-foreground truncate max-w-[200px]">{s.title}</span>
                          </div>
                        </td>
                        <td className="text-center py-2 px-2 text-xs tabular-nums">{(s.fixability ?? 0).toFixed(1)}</td>
                        <td className="text-center py-2 px-2 text-xs tabular-nums">{(s.attainability ?? 0).toFixed(1)}</td>
                        <td className="text-center py-2 px-2 text-xs tabular-nums">{(s.impact ?? 0).toFixed(1)}</td>
                        <td className="text-center py-2 px-2 text-xs tabular-nums">{(s.legitimacy ?? 0).toFixed(1)}</td>
                        <td className="text-center py-2 px-3">
                          <span className={`text-sm font-bold tabular-nums ${scoreColor(s.fail_score)}`}>
                            {(s.fail_score ?? 0).toFixed(1)}
                          </span>
                        </td>
                        <td className="text-center py-2 px-3">
                          <Badge variant="outline" className={`text-[10px] ${riskColor(s.risk_level)}`}>
                            {s.risk_level}
                          </Badge>
                        </td>
                        <td className="text-right py-2 px-3">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                            onClick={() => s.id && deleteMutation.mutate(s.id)}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-center py-10">
                <BarChart3 className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">
                  {filterSearch ? `No scores match "${filterSearch}"` : 'No FAIL scores computed yet'}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
