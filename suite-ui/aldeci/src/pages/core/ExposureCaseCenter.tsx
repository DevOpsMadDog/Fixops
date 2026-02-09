import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';

const STATUS_COLUMNS = ['open', 'triaging', 'fixing', 'resolved', 'closed'] as const;
type CaseStatus = typeof STATUS_COLUMNS[number] | 'accepted_risk' | 'false_positive';

interface ExposureCase {
  case_id: string;
  org_id: string;
  title: string;
  status: CaseStatus;
  priority: string;
  severity: string;
  clusters: unknown[];
  finding_ids: string[];
  created_at: string;
  updated_at: string;
  assigned_to?: string;
  sla_due?: string;
  transitions?: { from: string; to: string; at: string; actor: string }[];
}

interface CaseStats {
  total: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
  by_severity?: Record<string, number>;
}

const priorityColor = (p: string) => {
  switch (p?.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-500/20 text-red-400 border-red-500/40';
    case 'HIGH': return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    case 'MEDIUM': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
    case 'LOW': return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    default: return 'bg-gray-500/20 text-gray-400 border-gray-500/40';
  }
};

const statusColor = (s: string) => {
  switch (s) {
    case 'open': return 'from-red-900/20 to-red-800/5 border-red-500/30';
    case 'triaging': return 'from-yellow-900/20 to-yellow-800/5 border-yellow-500/30';
    case 'fixing': return 'from-blue-900/20 to-blue-800/5 border-blue-500/30';
    case 'resolved': return 'from-green-900/20 to-green-800/5 border-green-500/30';
    case 'closed': return 'from-gray-900/20 to-gray-800/5 border-gray-600/30';
    default: return 'from-gray-900/20 to-gray-800/5 border-gray-600/30';
  }
};

const statusHeaderColor = (s: string) => {
  switch (s) {
    case 'open': return 'text-red-400';
    case 'triaging': return 'text-yellow-400';
    case 'fixing': return 'text-blue-400';
    case 'resolved': return 'text-green-400';
    case 'closed': return 'text-gray-400';
    default: return 'text-gray-400';
  }
};

const statusEmoji = (s: string) => {
  switch (s) {
    case 'open': return '🔴';
    case 'triaging': return '🟡';
    case 'fixing': return '🔵';
    case 'resolved': return '🟢';
    case 'closed': return '⚪';
    default: return '⚫';
  }
};

const ExposureCaseCenter = () => {
  const [cases, setCases] = useState<ExposureCase[]>([]);
  const [stats, setStats] = useState<CaseStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<ExposureCase | null>(null);
  const [activeTab, setActiveTab] = useState('kanban');
  const [filterOrg, setFilterOrg] = useState('');

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [casesRes, statsRes] = await Promise.all([
        api.get('/api/v1/cases', { params: filterOrg ? { org_id: filterOrg } : {} }).catch(() => ({ data: { cases: [] } })),
        api.get('/api/v1/cases/stats/summary').catch(() => ({ data: { total: 0, by_status: {}, by_priority: {} } })),
      ]);
      setCases(casesRes.data?.cases || []);
      setStats(statsRes.data);
    } catch { /* ignore */ }
    setLoading(false);
  }, [filterOrg]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const transitionCase = async (caseId: string, newStatus: string) => {
    try {
      await api.post(`/api/v1/cases/${caseId}/transition`, { new_status: newStatus, actor: 'ui_user' });
      fetchData();
    } catch { /* ignore */ }
  };

  const casesByStatus = (status: string) => cases.filter(c => c.status === status);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 via-red-400 to-purple-400 bg-clip-text text-transparent">
            🗂️ Exposure Case Command Center
          </h1>
          <p className="text-muted-foreground mt-1">Collapse noisy findings into actionable cases — track lifecycle from open to closed</p>
        </div>
        <div className="flex items-center gap-3">
          <Input placeholder="Filter by org..." value={filterOrg} onChange={e => setFilterOrg(e.target.value)}
            className="w-48 bg-gray-800/50 border-gray-600/50" />
          <Badge variant="outline" className="text-lg px-4 py-2 border-orange-500/30 bg-orange-500/10 text-orange-300">
            {stats?.total ?? 0} Cases
          </Badge>
        </div>
      </motion.div>

      {/* Stats Row */}
      {stats && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
          className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {STATUS_COLUMNS.map(s => (
            <Card key={s} className={`border bg-gradient-to-br ${statusColor(s)}`}>
              <CardContent className="p-4 text-center">
                <div className="text-2xl font-bold">{stats.by_status?.[s] ?? 0}</div>
                <div className="text-xs text-muted-foreground capitalize flex items-center justify-center gap-1">
                  {statusEmoji(s)} {s}
                </div>
              </CardContent>
            </Card>
          ))}
        </motion.div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="kanban">📋 Kanban Board</TabsTrigger>
          <TabsTrigger value="list">📄 List View</TabsTrigger>
          {selectedCase && <TabsTrigger value="detail">🔬 Case Detail</TabsTrigger>}
        </TabsList>

        {/* ════════ KANBAN TAB ════════ */}
        <TabsContent value="kanban" className="mt-4">
          {loading ? (
            <div className="text-center py-16 text-muted-foreground animate-pulse">Loading cases...</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
              {STATUS_COLUMNS.map(status => (
                <div key={status} className="space-y-2">
                  <div className={`text-sm font-semibold uppercase tracking-wider ${statusHeaderColor(status)} flex items-center gap-2 mb-3`}>
                    {statusEmoji(status)} {status} <span className="text-xs font-normal text-muted-foreground">({casesByStatus(status).length})</span>
                  </div>
                  <AnimatePresence>
                    {casesByStatus(status).map((c, i) => (
                      <motion.div
                        key={c.case_id}
                        layout
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.9 }}
                        transition={{ delay: i * 0.03 }}
                        onClick={() => { setSelectedCase(c); setActiveTab('detail'); }}
                        className="cursor-pointer"
                      >
                        <Card className={`border bg-gradient-to-br ${statusColor(status)} hover:scale-[1.02] transition-transform`}>
                          <CardContent className="p-3 space-y-2">
                            <div className="flex items-start justify-between">
                              <span className="text-xs font-mono text-gray-500">{c.case_id}</span>
                              <Badge variant="outline" className={`text-[9px] ${priorityColor(c.priority)}`}>
                                {c.priority?.toUpperCase()}
                              </Badge>
                            </div>
                            <div className="text-sm font-medium text-gray-200 leading-tight">{c.title}</div>
                            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                              <span>{c.finding_ids?.length ?? 0} findings</span>
                              <span>{c.clusters?.length ?? 0} clusters</span>
                            </div>
                          </CardContent>
                        </Card>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                  {casesByStatus(status).length === 0 && (
                    <div className="text-xs text-muted-foreground text-center py-6 border border-dashed border-gray-700/30 rounded-lg">
                      No cases
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ════════ LIST TAB ════════ */}
        <TabsContent value="list" className="mt-4">
          <Card className="glass-card border-gray-700/50">
            <CardContent className="p-0">
              {cases.length === 0 ? (
                <div className="text-center py-16 text-muted-foreground">
                  <div className="text-4xl mb-3">🗂️</div>
                  <p>No exposure cases found. Run the Brain Pipeline to generate cases.</p>
                </div>
              ) : (
                <div className="divide-y divide-gray-800/50">
                  {cases.map((c, i) => (
                    <motion.div
                      key={c.case_id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      onClick={() => { setSelectedCase(c); setActiveTab('detail'); }}
                      className="flex items-center justify-between p-4 hover:bg-gray-800/20 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-4">
                        <span className="text-lg">{statusEmoji(c.status)}</span>
                        <div>
                          <div className="text-sm font-medium text-gray-200">{c.title}</div>
                          <div className="text-xs text-muted-foreground">{c.case_id} · {c.org_id}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className={`text-[10px] ${priorityColor(c.priority)}`}>
                          {c.priority?.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] bg-gray-800/50 text-gray-300">
                          {c.finding_ids?.length ?? 0} findings
                        </Badge>
                        <span className="text-xs text-muted-foreground capitalize">{c.status}</span>
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ════════ DETAIL TAB ════════ */}
        <TabsContent value="detail" className="space-y-4 mt-4">
          {selectedCase ? (
            <>
              <Card className="glass-card border-orange-500/20">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg flex items-center gap-3">
                    <span>{statusEmoji(selectedCase.status)}</span>
                    <span className="text-gray-200">{selectedCase.title}</span>
                    <Badge variant="outline" className={priorityColor(selectedCase.priority)}>
                      {selectedCase.priority?.toUpperCase()}
                    </Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm mb-4">
                    <div><span className="text-muted-foreground">ID:</span> <span className="font-mono text-gray-200">{selectedCase.case_id}</span></div>
                    <div><span className="text-muted-foreground">Org:</span> <span className="text-gray-200">{selectedCase.org_id}</span></div>
                    <div><span className="text-muted-foreground">Status:</span> <span className="text-gray-200 capitalize">{selectedCase.status}</span></div>
                    <div><span className="text-muted-foreground">Findings:</span> <span className="text-gray-200">{selectedCase.finding_ids?.length ?? 0}</span></div>
                  </div>

                  {/* Transition buttons */}
                  <div className="flex gap-2 flex-wrap">
                    <span className="text-xs text-muted-foreground self-center mr-2">Transition to:</span>
                    {STATUS_COLUMNS.filter(s => s !== selectedCase.status).map(s => (
                      <Button key={s} size="sm" variant="outline"
                        className={`text-xs capitalize border-gray-600/50 hover:bg-gray-800/50`}
                        onClick={() => transitionCase(selectedCase.case_id, s)}>
                        {statusEmoji(s)} {s}
                      </Button>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Lifecycle timeline */}
              {selectedCase.transitions && selectedCase.transitions.length > 0 && (
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">Lifecycle Timeline</CardTitle></CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {selectedCase.transitions.map((t, i) => (
                        <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.05 }}
                          className="flex items-center gap-3 text-xs">
                          <span className="font-mono text-muted-foreground">{new Date(t.at).toLocaleString()}</span>
                          <Badge variant="outline" className="text-[9px]">{t.from}</Badge>
                          <span className="text-gray-500">→</span>
                          <Badge variant="outline" className="text-[9px]">{t.to}</Badge>
                          <span className="text-gray-500">by {t.actor}</span>
                        </motion.div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <div className="text-center py-12 text-muted-foreground">Select a case to view details</div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ExposureCaseCenter;

