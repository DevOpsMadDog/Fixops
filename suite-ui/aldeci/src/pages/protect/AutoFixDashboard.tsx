import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';

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
}

const confidenceColor = (c: string) => {
  switch (c) {
    case 'HIGH': return 'bg-green-500/20 text-green-400 border-green-500/30';
    case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'LOW': return 'bg-red-500/20 text-red-400 border-red-500/30';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
  }
};

const statusColor = (s: string) => {
  switch (s) {
    case 'MERGED': return 'bg-green-500/20 text-green-400';
    case 'PR_CREATED': return 'bg-blue-500/20 text-blue-400';
    case 'APPLIED': return 'bg-cyan-500/20 text-cyan-400';
    case 'VALIDATED': return 'bg-indigo-500/20 text-indigo-400';
    case 'GENERATED': return 'bg-purple-500/20 text-purple-400';
    case 'FAILED': return 'bg-red-500/20 text-red-400';
    case 'REJECTED': return 'bg-orange-500/20 text-orange-400';
    case 'ROLLED_BACK': return 'bg-gray-500/20 text-gray-400';
    default: return 'bg-gray-500/20 text-gray-400';
  }
};

const AutoFixDashboard = () => {
  const [stats, setStats] = useState<any>(null);
  const [fixes, setFixes] = useState<FixSuggestion[]>([]);
  const [fixTypes, setFixTypes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [statsRes, historyRes, typesRes] = await Promise.all([
        api.get('/api/v1/autofix/stats').catch(() => ({ data: { total_fixes: 0, by_status: {}, by_type: {}, by_confidence: {}, success_rate: 0 } })),
        api.get('/api/v1/autofix/history').catch(() => ({ data: { fixes: [] } })),
        api.get('/api/v1/autofix/fix-types').catch(() => ({ data: { fix_types: [] } })),
      ]);
      setStats(statsRes.data);
      setFixes(historyRes.data?.fixes || []);
      const rawTypes = typesRes.data?.fix_types || [];
      // Normalise: API may return strings or {value,name} objects
      setFixTypes(rawTypes.map((t: any) => (typeof t === 'string' ? t : t?.name ?? t?.value ?? String(t))));
    } catch (e) { console.error('AutoFix fetch error', e); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleGenerate = async (findingId: string) => {
    setGenerating(findingId);
    try {
      await api.post('/api/v1/autofix/generate', { finding_id: findingId, severity: 'high', title: 'Security vulnerability', cve_id: findingId });
      await fetchData();
    } catch (e) { console.error('Generate fix error', e); }
    finally { setGenerating(null); }
  };

  const handleApply = async (fixId: string) => {
    try {
      await api.post('/api/v1/autofix/apply', { fix_id: fixId, repository: 'main', create_pr: true });
      await fetchData();
    } catch (e) { console.error('Apply fix error', e); }
  };

  const handleRollback = async (fixId: string) => {
    try {
      await api.post('/api/v1/autofix/rollback', { fix_id: fixId });
      await fetchData();
    } catch (e) { console.error('Rollback error', e); }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-green-400 to-emerald-500 bg-clip-text text-transparent">AutoFix Dashboard</h1>
          <p className="text-muted-foreground mt-1">AI-powered vulnerability remediation with automatic PR generation</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchData}>Refresh</Button>
          <Button onClick={() => handleGenerate('demo-finding-' + Date.now())} disabled={!!generating}>
            {generating ? 'Generating...' : '✨ Generate Fix'}
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {[
          { label: 'Total Fixes', value: stats?.total_fixes ?? 0, color: 'text-blue-400' },
          { label: 'Success Rate', value: `${Math.round((stats?.success_rate ?? 0) * 100)}%`, color: 'text-green-400' },
          { label: 'PRs Created', value: stats?.by_status?.PR_CREATED ?? 0, color: 'text-purple-400' },
          { label: 'Merged', value: stats?.by_status?.MERGED ?? 0, color: 'text-emerald-400' },
          { label: 'Failed', value: stats?.by_status?.FAILED ?? 0, color: 'text-red-400' },
        ].map((s, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <Card className="border-border/50 bg-card/50 backdrop-blur">
              <CardContent className="pt-6">
                <div className={`text-3xl font-bold ${s.color}`}>{s.value}</div>
                <div className="text-xs text-muted-foreground mt-1">{s.label}</div>
              </CardContent>
            </Card>
          </motion.div>
        ))}
      </div>

      {/* Tabs: Suggestions / History / Fix Types */}
      <Tabs defaultValue="suggestions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="suggestions">Fix Suggestions</TabsTrigger>
          <TabsTrigger value="history">Fix History</TabsTrigger>
          <TabsTrigger value="types">Fix Types</TabsTrigger>
        </TabsList>

        <TabsContent value="suggestions">
          <Card className="border-border/50">
            <CardHeader><CardTitle>Pending Fix Suggestions</CardTitle></CardHeader>
            <CardContent>
              {loading ? <div className="text-center py-8 text-muted-foreground">Loading...</div> : (
                <AnimatePresence>
                  <div className="space-y-3">
                    {fixes.filter(f => f.status === 'GENERATED' || f.status === 'VALIDATED').map((fix, i) => (
                      <FixCard key={fix.fix_id} fix={fix} index={i} onApply={handleApply} onRollback={handleRollback} />
                    ))}
                    {fixes.filter(f => f.status === 'GENERATED' || f.status === 'VALIDATED').length === 0 && (
                      <div className="text-center py-12 text-muted-foreground">No pending fix suggestions. Click "Generate Fix" to create one.</div>
                    )}
                  </div>
                </AnimatePresence>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history">
          <Card className="border-border/50">
            <CardHeader><CardTitle>All Fixes</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-3">
                {fixes.map((fix, i) => (
                  <FixCard key={fix.fix_id} fix={fix} index={i} onApply={handleApply} onRollback={handleRollback} />
                ))}
                {fixes.length === 0 && <div className="text-center py-12 text-muted-foreground">No fixes generated yet.</div>}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="types">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            {fixTypes.map((t, i) => (
              <motion.div key={t} initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.04 }}>
                <Card className="border-border/50 bg-card/50 hover:bg-card/80 transition-colors cursor-pointer">
                  <CardContent className="pt-4 pb-4 text-center">
                    <div className="text-sm font-medium text-foreground">{t.replace(/_/g, ' ')}</div>
                    <div className="text-xs text-muted-foreground mt-1">{stats?.by_type?.[t] ?? 0} fixes</div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Confidence Distribution */}
      {stats && (
        <Card className="border-border/50">
          <CardHeader><CardTitle>Confidence Distribution</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-4">
              {['HIGH', 'MEDIUM', 'LOW'].map(level => {
                const count = stats.by_confidence?.[level] ?? 0;
                const total = stats.total_fixes || 1;
                return (
                  <div key={level} className="flex items-center gap-4">
                    <Badge className={`w-20 justify-center ${confidenceColor(level)}`}>{level}</Badge>
                    <Progress value={(count / total) * 100} className="flex-1 h-2" />
                    <span className="text-sm text-muted-foreground w-12 text-right">{count}</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

/* Fix suggestion card */
function FixCard({ fix, index, onApply, onRollback }: { fix: FixSuggestion; index: number; onApply: (id: string) => void; onRollback: (id: string) => void }) {
  return (
    <motion.div initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: index * 0.03 }}
      className="p-4 border border-border/50 rounded-lg bg-card/30 hover:bg-card/60 transition-colors">
      <div className="flex justify-between items-start">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className="font-semibold text-foreground">{fix.title || fix.fix_type?.replace(/_/g, ' ') || 'Fix'}</span>
            <Badge className={confidenceColor(fix.confidence)}>{fix.confidence} ({Math.round(fix.confidence_score * 100)}%)</Badge>
            <Badge className={statusColor(fix.status)}>{fix.status}</Badge>
          </div>
          <p className="text-sm text-muted-foreground">{fix.description || `Auto-generated ${fix.fix_type} fix for finding ${fix.finding_id}`}</p>
          <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
            <span>Type: {fix.fix_type}</span>
            <span>Format: {fix.patch_format}</span>
            {fix.pr_url && <a href={fix.pr_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">View PR →</a>}
          </div>
        </div>
        <div className="flex gap-2 ml-4">
          {(fix.status === 'GENERATED' || fix.status === 'VALIDATED') && (
            <Button size="sm" onClick={() => onApply(fix.fix_id)} className="bg-green-600 hover:bg-green-700">Apply</Button>
          )}
          {(fix.status === 'APPLIED' || fix.status === 'PR_CREATED') && (
            <Button size="sm" variant="outline" onClick={() => onRollback(fix.fix_id)}>Rollback</Button>
          )}
        </div>
      </div>
    </motion.div>
  );
}



export default AutoFixDashboard;