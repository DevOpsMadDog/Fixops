import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';

// ═══════════════════════════════════════════════════════════════════════════
// Types (V3 — AutoFix Engine)
// ═══════════════════════════════════════════════════════════════════════════

interface FixSuggestion {
  fix_id: string;
  finding_id: string;
  fix_type: string;
  confidence: string;
  confidence_score: number;
  title: string;
  description: string;
  status: string;
  patch_format: string;
  created_at: string;
  pr_url?: string;
  patch?: string;
  diff?: string;
  rollback_id?: string;
}

interface AutoFixStats {
  total_fixes: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  by_confidence: Record<string, number>;
  success_rate: number;
  avg_confidence: number;
  total_prs_created: number;
  total_merged: number;
}

// The 10 AutoFix types from the engine
const FIX_TYPE_ICONS: Record<string, string> = {
  dependency_upgrade: '📦',
  code_patch: '🔧',
  config_hardening: '⚙️',
  secret_rotation: '🔑',
  access_control: '🔒',
  input_validation: '✅',
  crypto_fix: '🔐',
  header_fix: '🌐',
  dockerfile_fix: '🐳',
  iac_remediation: '☁️',
};

const appleEase = [0.16, 1, 0.3, 1];

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

const confidenceColor = (c: string) => {
  switch (c) {
    case 'HIGH': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'LOW': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const confidenceDotColor = (c: string) => {
  switch (c) {
    case 'HIGH': return 'bg-green-500';
    case 'MEDIUM': return 'bg-yellow-500';
    case 'LOW': return 'bg-red-500';
    default: return 'bg-gray-500';
  }
};

const statusColor = (s: string) => {
  switch (s) {
    case 'MERGED': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'PR_CREATED': return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'APPLIED': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    case 'VALIDATED': return 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30';
    case 'GENERATED': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'FAILED': return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'REJECTED': return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'ROLLED_BACK': return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// Diff View Component (V3 Enhancement)
// ═══════════════════════════════════════════════════════════════════════════

function DiffView({ patch }: { patch: string }) {
  const lines = patch.split('\n');
  return (
    <div className="rounded-lg overflow-hidden border border-gray-700/30 bg-gray-950/80 font-mono text-xs max-h-64 overflow-y-auto">
      {lines.map((line, i) => {
        let bg = '';
        let textColor = 'text-gray-400';
        if (line.startsWith('+') && !line.startsWith('+++')) {
          bg = 'bg-green-900/30';
          textColor = 'text-green-400';
        } else if (line.startsWith('-') && !line.startsWith('---')) {
          bg = 'bg-red-900/30';
          textColor = 'text-red-400';
        } else if (line.startsWith('@@')) {
          bg = 'bg-blue-900/20';
          textColor = 'text-blue-400';
        } else if (line.startsWith('diff') || line.startsWith('index')) {
          textColor = 'text-gray-500';
        }
        return (
          <div key={i} className={`flex ${bg}`}>
            <span className="w-10 text-right pr-2 text-gray-600 select-none shrink-0 border-r border-gray-800/50 py-0.5">
              {i + 1}
            </span>
            <pre className={`pl-2 py-0.5 whitespace-pre-wrap break-all ${textColor}`}>{line}</pre>
          </div>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Fix Type Distribution Chart (V3 Enhancement)
// ═══════════════════════════════════════════════════════════════════════════

function FixTypeDistribution({ byType }: { byType: Record<string, number> }) {
  const entries = Object.entries(byType).sort(([, a], [, b]) => b - a);
  const maxCount = Math.max(...entries.map(([, v]) => v), 1);

  if (entries.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <div className="text-4xl mb-3">📊</div>
        <p>No fix type data available yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {entries.map(([type, count], i) => (
        <motion.div
          key={type}
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: i * 0.05, ease: appleEase }}
          className="flex items-center gap-3"
        >
          <span className="text-lg w-8">{FIX_TYPE_ICONS[type] || '🔧'}</span>
          <span className="text-xs text-gray-300 w-36 truncate capitalize">{type.replace(/_/g, ' ')}</span>
          <div className="flex-1 h-6 bg-gray-800/50 rounded-lg overflow-hidden relative">
            <motion.div
              className="h-full bg-gradient-to-r from-green-500/60 to-emerald-500/40 rounded-lg"
              initial={{ width: 0 }}
              animate={{ width: `${(count / maxCount) * 100}%` }}
              transition={{ delay: i * 0.05 + 0.2, duration: 0.6, ease: appleEase }}
            />
            <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] font-mono text-gray-300">
              {count}
            </span>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Fix Card Component (Enhanced with Diff View)
// ═══════════════════════════════════════════════════════════════════════════

function FixCard({
  fix,
  index,
  onApply,
  onRollback,
  onViewDiff,
  expandedDiff,
}: {
  fix: FixSuggestion;
  index: number;
  onApply: (id: string) => void;
  onRollback: (id: string) => void;
  onViewDiff: (id: string) => void;
  expandedDiff: string | null;
}) {
  const isExpanded = expandedDiff === fix.fix_id;
  const hasPatch = Boolean(fix.patch || fix.diff);

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.03, ease: appleEase }}
      className="border border-gray-700/30 rounded-lg bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-all"
    >
      <div className="p-4">
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="text-lg">{FIX_TYPE_ICONS[fix.fix_type] || '🔧'}</span>
              <span className="font-semibold text-gray-200">{fix.title || fix.fix_type?.replace(/_/g, ' ') || 'Fix'}</span>
              <div className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${confidenceDotColor(fix.confidence)}`} />
                <Badge variant="outline" className={confidenceColor(fix.confidence)}>
                  {fix.confidence} ({Math.round(fix.confidence_score * 100)}%)
                </Badge>
              </div>
              <Badge variant="outline" className={statusColor(fix.status)}>{fix.status}</Badge>
            </div>
            <p className="text-sm text-muted-foreground">{fix.description || `Auto-generated ${fix.fix_type} fix for finding ${fix.finding_id}`}</p>
            <div className="flex gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
              <span>ID: <code className="text-gray-400">{fix.fix_id}</code></span>
              <span>Type: {fix.fix_type}</span>
              <span>Format: {fix.patch_format}</span>
              <span>Created: {fix.created_at ? new Date(fix.created_at).toLocaleString() : '—'}</span>
              {fix.pr_url && (
                <a href={fix.pr_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">
                  View PR →
                </a>
              )}
            </div>
          </div>
          <div className="flex gap-2 ml-4 shrink-0">
            {hasPatch && (
              <Button size="sm" variant="outline" onClick={() => onViewDiff(fix.fix_id)}
                className="border-gray-600/50 text-gray-300 hover:bg-gray-800/50">
                {isExpanded ? '▲ Hide' : '▼ Diff'}
              </Button>
            )}
            {(fix.status === 'GENERATED' || fix.status === 'VALIDATED') && (
              <Button size="sm" onClick={() => onApply(fix.fix_id)}
                className="bg-green-600 hover:bg-green-700 text-white">
                ✓ Apply
              </Button>
            )}
            {(fix.status === 'APPLIED' || fix.status === 'PR_CREATED') && (
              <Button size="sm" variant="outline" onClick={() => onRollback(fix.fix_id)}
                className="border-orange-500/30 text-orange-400 hover:bg-orange-500/10">
                ↩ Rollback
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Expandable Diff View */}
      <AnimatePresence>
        {isExpanded && hasPatch && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3, ease: appleEase }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4">
              <DiffView patch={fix.patch || fix.diff || ''} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════════════════════

const AutoFixDashboard = () => {
  const [stats, setStats] = useState<AutoFixStats | null>(null);
  const [fixes, setFixes] = useState<FixSuggestion[]>([]);
  const [fixTypes, setFixTypes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);
  const [expandedDiff, setExpandedDiff] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, historyRes, typesRes] = await Promise.all([
        api.get('/api/v1/autofix/stats').catch((e) => { console.error('[AutoFix] stats fetch failed:', e?.message); return { data: { total_fixes: 0, by_status: {}, by_type: {}, by_confidence: {}, success_rate: 0 } }; }),
        api.get('/api/v1/autofix/history').catch((e) => { console.error('[AutoFix] history fetch failed:', e?.message); return { data: { fixes: [] } }; }),
        api.get('/api/v1/autofix/fix-types').catch((e) => { console.error('[AutoFix] fix-types fetch failed:', e?.message); return { data: { fix_types: [] } }; }),
      ]);
      setStats(statsRes.data as AutoFixStats);
      setFixes((historyRes.data?.fixes || []) as FixSuggestion[]);
      const rawTypes = (typesRes.data?.fix_types || []) as Array<string | { name?: string; value?: string }>;
      setFixTypes(rawTypes.map((t) => (typeof t === 'string' ? t : (t as Record<string, string>)?.name ?? (t as Record<string, string>)?.value ?? String(t))));
    } catch (e) {
      console.error('AutoFix fetch error', e);
      toast.error('Failed to load AutoFix data');
    }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleGenerate = async (findingId: string) => {
    setGenerating(findingId);
    toast.info('Generating fix suggestion...');
    try {
      const res = await api.post('/api/v1/autofix/generate', {
        finding_id: findingId,
        severity: 'high',
        title: 'Security vulnerability',
        cve_id: findingId,
      });
      toast.success(`Fix generated: ${(res.data as Record<string, string>)?.fix_id || 'success'}`);
      await fetchData();
    } catch (e) {
      console.error('Generate fix error', e);
      toast.error('Failed to generate fix');
    }
    finally { setGenerating(null); }
  };

  const handleApply = async (fixId: string) => {
    toast.info('Applying fix and creating PR...');
    try {
      await api.post('/api/v1/autofix/apply', { fix_id: fixId, repository: 'main', create_pr: true });
      toast.success('Fix applied successfully');
      await fetchData();
    } catch (e) {
      console.error('Apply fix error', e);
      toast.error('Failed to apply fix');
    }
  };

  const handleRollback = async (fixId: string) => {
    toast.info('Rolling back fix...');
    try {
      await api.post('/api/v1/autofix/rollback', { fix_id: fixId });
      toast.success('Fix rolled back successfully');
      await fetchData();
    } catch (e) {
      console.error('Rollback error', e);
      toast.error('Failed to rollback fix');
    }
  };

  const toggleDiff = (fixId: string) => {
    setExpandedDiff(prev => prev === fixId ? null : fixId);
  };

  const pendingFixes = fixes.filter(f => f.status === 'GENERATED' || f.status === 'VALIDATED');
  const highConfidenceFixes = pendingFixes.filter(f => f.confidence === 'HIGH');

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex justify-between items-center"
      >
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 via-emerald-400 to-cyan-400 bg-clip-text text-transparent">
            AutoFix Center
          </h1>
          <p className="text-muted-foreground mt-1">AI-powered vulnerability remediation — 10 fix types, automatic PR generation</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchData} className="border-gray-600/50">↻ Refresh</Button>
          {highConfidenceFixes.length > 0 && (
            <Button
              variant="outline"
              onClick={async () => {
                for (const fix of highConfidenceFixes) {
                  await handleApply(fix.fix_id);
                }
              }}
              className="border-green-500/30 text-green-400 hover:bg-green-500/10"
            >
              ⚡ Apply All HIGH ({highConfidenceFixes.length})
            </Button>
          )}
          <Button
            onClick={() => handleGenerate('demo-finding-' + Date.now())}
            disabled={!!generating}
            className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-500 hover:to-emerald-500 text-white shadow-lg shadow-green-500/20"
          >
            {generating ? (
              <span className="flex items-center gap-2"><span className="animate-spin">⚙️</span> Generating...</span>
            ) : '✨ Generate Fix'}
          </Button>
        </div>
      </motion.div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Total Fixes', value: stats?.total_fixes ?? 0, color: 'text-blue-400', icon: '🔧' },
          { label: 'Success Rate', value: `${Math.round((stats?.success_rate ?? 0) * 100)}%`, color: 'text-green-400', icon: '✅' },
          { label: 'HIGH Confidence', value: stats?.by_confidence?.HIGH ?? 0, color: 'text-emerald-400', icon: '🟢' },
          { label: 'PRs Created', value: stats?.by_status?.PR_CREATED ?? stats?.total_prs_created ?? 0, color: 'text-purple-400', icon: '📝' },
          { label: 'Merged', value: stats?.by_status?.MERGED ?? stats?.total_merged ?? 0, color: 'text-cyan-400', icon: '🎯' },
          { label: 'Failed', value: stats?.by_status?.FAILED ?? 0, color: 'text-red-400', icon: '❌' },
        ].map((s, i) => (
          <motion.div key={s.label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05, ease: appleEase }}>
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md hover:border-gray-600/50 transition-colors">
              <CardContent className="pt-4 pb-3 text-center">
                {loading ? (
                  <div className="animate-pulse">
                    <div className="h-8 bg-gray-700/30 rounded w-16 mx-auto mb-1" />
                    <div className="h-3 bg-gray-700/20 rounded w-20 mx-auto" />
                  </div>
                ) : (
                  <>
                    <div className="text-xs mb-0.5">{s.icon}</div>
                    <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{s.label}</div>
                  </>
                )}
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Tabs */}
      <Tabs defaultValue="suggestions" className="space-y-4">
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="suggestions">🔧 Pending Fixes ({pendingFixes.length})</TabsTrigger>
          <TabsTrigger value="history">📜 All Fixes ({fixes.length})</TabsTrigger>
          <TabsTrigger value="types">📊 Fix Types ({fixTypes.length})</TabsTrigger>
          <TabsTrigger value="confidence">🎯 Confidence</TabsTrigger>
        </TabsList>

        {/* Pending Suggestions */}
        <TabsContent value="suggestions">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="text-lg text-gray-200">Pending Fix Suggestions</CardTitle>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="space-y-3">
                  {[1, 2, 3].map(i => (
                    <div key={i} className="animate-pulse p-4 rounded-lg bg-gray-800/30 border border-gray-700/20">
                      <div className="h-5 bg-gray-700/30 rounded w-48 mb-2" />
                      <div className="h-3 bg-gray-700/20 rounded w-full mb-1" />
                      <div className="h-3 bg-gray-700/20 rounded w-2/3" />
                    </div>
                  ))}
                </div>
              ) : pendingFixes.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <div className="text-4xl mb-3">✨</div>
                  <p className="text-lg mb-1">No pending fix suggestions</p>
                  <p className="text-sm">Click "Generate Fix" to create a new AI-powered fix suggestion</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {pendingFixes.map((fix, i) => (
                    <FixCard
                      key={fix.fix_id}
                      fix={fix}
                      index={i}
                      onApply={handleApply}
                      onRollback={handleRollback}
                      onViewDiff={toggleDiff}
                      expandedDiff={expandedDiff}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* All Fixes History */}
        <TabsContent value="history">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="text-lg text-gray-200">All Fixes</CardTitle>
            </CardHeader>
            <CardContent>
              {fixes.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <div className="text-4xl mb-3">📦</div>
                  <p>No fixes generated yet</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {fixes.map((fix, i) => (
                    <FixCard
                      key={fix.fix_id}
                      fix={fix}
                      index={i}
                      onApply={handleApply}
                      onRollback={handleRollback}
                      onViewDiff={toggleDiff}
                      expandedDiff={expandedDiff}
                    />
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Fix Type Distribution */}
        <TabsContent value="types">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Distribution Chart */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardHeader>
                <CardTitle className="text-lg text-gray-200">Fix Type Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <FixTypeDistribution byType={stats?.by_type || {}} />
              </CardContent>
            </Card>

            {/* Fix Type Grid */}
            <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
              <CardHeader>
                <CardTitle className="text-lg text-gray-200">Available Fix Types (10)</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 gap-3">
                  {fixTypes.map((t, i) => (
                    <motion.div
                      key={t}
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: i * 0.04, ease: appleEase }}
                    >
                      <div className="flex items-center gap-3 p-3 rounded-lg border border-gray-700/30 bg-gray-800/30 hover:bg-gray-800/50 transition-colors">
                        <span className="text-xl">{FIX_TYPE_ICONS[t] || '🔧'}</span>
                        <div>
                          <div className="text-sm font-medium text-gray-200 capitalize">{t.replace(/_/g, ' ')}</div>
                          <div className="text-xs text-muted-foreground">{stats?.by_type?.[t] ?? 0} fixes</div>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                  {fixTypes.length === 0 && (
                    <div className="col-span-2 grid grid-cols-2 gap-3">
                      {Array.from({ length: 4 }).map((_, i) => (
                        <div key={i} className="border border-border/30 rounded-lg p-4 space-y-2">
                          <div className="h-5 w-32 bg-gray-700/20 rounded animate-pulse" />
                          <div className="h-8 w-16 bg-gray-700/25 rounded animate-pulse" />
                          <div className="h-2 w-full bg-gray-700/15 rounded-full animate-pulse" />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Confidence Distribution */}
        <TabsContent value="confidence">
          <Card className="border-gray-700/30 bg-gray-900/40 backdrop-blur-md">
            <CardHeader>
              <CardTitle className="text-lg text-gray-200">Confidence Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {(['HIGH', 'MEDIUM', 'LOW'] as const).map((level, i) => {
                  const count = stats?.by_confidence?.[level] ?? 0;
                  const total = stats?.total_fixes || 1;
                  const pct = Math.round((count / total) * 100);
                  return (
                    <motion.div
                      key={level}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.1, ease: appleEase }}
                      className="space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <div className={`w-3 h-3 rounded-full ${confidenceDotColor(level)}`} />
                          <Badge variant="outline" className={`w-24 justify-center ${confidenceColor(level)}`}>{level}</Badge>
                          <span className="text-sm text-gray-300">
                            {level === 'HIGH' && 'Safe to auto-apply — AI is confident'}
                            {level === 'MEDIUM' && 'Review recommended before applying'}
                            {level === 'LOW' && 'Manual review required — potential side effects'}
                          </span>
                        </div>
                        <span className="text-sm font-mono text-gray-400">{count} ({pct}%)</span>
                      </div>
                      <Progress value={pct} className="h-3 bg-gray-800" />
                    </motion.div>
                  );
                })}
              </div>

              {/* Confidence legend */}
              <div className="mt-8 p-4 rounded-lg border border-gray-700/20 bg-gray-800/20">
                <h3 className="text-sm font-semibold text-gray-300 mb-2">Confidence Level Guide</h3>
                <div className="grid grid-cols-3 gap-4 text-xs text-muted-foreground">
                  <div>
                    <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30 mb-1">HIGH</Badge>
                    <p>One-click apply. AI is confident the fix is correct and safe. Suitable for automation.</p>
                  </div>
                  <div>
                    <Badge variant="outline" className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30 mb-1">MEDIUM</Badge>
                    <p>Review the diff before applying. Fix is likely correct but may need minor adjustments.</p>
                  </div>
                  <div>
                    <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30 mb-1">LOW</Badge>
                    <p>Manual review required. Complex fix with potential side effects. Use diff view to verify.</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AutoFixDashboard;
