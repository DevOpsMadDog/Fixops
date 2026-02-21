import { useEffect, useState, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../lib/api';
import { toast } from 'sonner';

const STATUS_COLUMNS = ['open', 'triaging', 'fixing', 'resolved', 'closed', 'accepted_risk', 'false_positive'] as const;
type CaseStatusType = typeof STATUS_COLUMNS[number];

/* ── Interface matching EXACT backend ExposureCase.to_dict() output ── */
interface ExposureCase {
  case_id: string;
  title: string;
  description: string;
  status: CaseStatusType;
  priority: string;
  org_id: string;
  root_cve: string | null;
  root_cwe: string | null;
  root_component: string | null;
  affected_assets: string[];
  cluster_ids: string[];
  finding_count: number;
  risk_score: number;
  epss_score: number | null;
  in_kev: boolean;
  blast_radius: number;
  assigned_to: string | null;
  assigned_team: string | null;
  sla_due: string | null;
  sla_breached: boolean;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  remediation_plan: string | null;
  playbook_id: string | null;
  autofix_pr_url: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
}

/* ── Stats interface matching backend stats() output ── */
interface CaseStats {
  total_cases: number;
  by_status: Record<string, number>;
  by_priority: Record<string, number>;
  avg_risk_score: number;
  kev_cases: number;
}

const priorityColor = (p: string) => {
  switch (p?.toLowerCase()) {
    case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/40';
    case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40';
    case 'low': return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
    case 'info': return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40';
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
    case 'accepted_risk': return 'from-purple-900/20 to-purple-800/5 border-purple-500/30';
    case 'false_positive': return 'from-slate-900/20 to-slate-800/5 border-slate-500/30';
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
    case 'accepted_risk': return 'text-purple-400';
    case 'false_positive': return 'text-slate-400';
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
    case 'accepted_risk': return '🟣';
    case 'false_positive': return '⬜';
    default: return '⚫';
  }
};

const riskColor = (score: number) => {
  if (score >= 8) return 'text-red-400';
  if (score >= 6) return 'text-orange-400';
  if (score >= 4) return 'text-yellow-400';
  return 'text-green-400';
};

/* ── Valid transitions from backend state machine ── */
const VALID_TRANSITIONS: Record<string, string[]> = {
  open: ['triaging', 'accepted_risk', 'false_positive'],
  triaging: ['fixing', 'accepted_risk', 'false_positive', 'open'],
  fixing: ['resolved', 'triaging', 'open'],
  resolved: ['closed', 'open'],
  closed: ['open'],
  accepted_risk: ['open'],
  false_positive: ['open'],
};

const ExposureCaseCenter = () => {
  const [cases, setCases] = useState<ExposureCase[]>([]);
  const [stats, setStats] = useState<CaseStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedCase, setSelectedCase] = useState<ExposureCase | null>(null);
  const [activeTab, setActiveTab] = useState('kanban');
  const [filterOrg, setFilterOrg] = useState('');
  const [filterPriority, setFilterPriority] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [newCase, setNewCase] = useState({ title: '', description: '', priority: 'medium', org_id: '', root_cve: '', root_cwe: '' });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string> = {};
      if (filterOrg) params.org_id = filterOrg;
      if (filterPriority) params.priority = filterPriority;
      const [casesRes, statsRes] = await Promise.all([
        api.get('/api/v1/cases', { params }).catch(() => ({ data: { cases: [] } })),
        api.get('/api/v1/cases/stats/summary').catch(() => ({ data: { total_cases: 0, by_status: {}, by_priority: {}, avg_risk_score: 0, kev_cases: 0 } })),
      ]);
      setCases(casesRes.data?.cases || []);
      setStats(statsRes.data);
    } catch { /* ignore */ }
    setLoading(false);
  }, [filterOrg, filterPriority]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const transitionCase = async (caseId: string, newStatus: string) => {
    try {
      await api.post(`/api/v1/cases/${caseId}/transition`, { new_status: newStatus, actor: 'ui_user' });
      toast.success(`Case transitioned to ${newStatus}`);
      fetchData();
      if (selectedCase?.case_id === caseId) {
        const res = await api.get(`/api/v1/cases/${caseId}`).catch(() => null);
        if (res?.data) setSelectedCase(res.data);
      }
    } catch (err: any) {
      const msg = err?.response?.data?.detail || err?.message || 'Unknown error';
      toast.error(`Transition failed: ${msg}`);
    }
  };

  const createCase = async () => {
    try {
      await api.post('/api/v1/cases', { ...newCase, root_cve: newCase.root_cve || null, root_cwe: newCase.root_cwe || null });
      toast.success('Case created');
      setShowCreate(false);
      setNewCase({ title: '', description: '', priority: 'medium', org_id: '', root_cve: '', root_cwe: '' });
      fetchData();
    } catch (err: any) {
      toast.error(err?.response?.data?.detail || 'Failed to create case');
    }
  };

  const casesByStatus = (status: string) => cases.filter(c => c.status === status);
  const timeAgo = (iso: string) => {
    if (!iso) return '—';
    const d = Date.now() - new Date(iso).getTime();
    if (d < 3600000) return `${Math.floor(d / 60000)}m ago`;
    if (d < 86400000) return `${Math.floor(d / 3600000)}h ago`;
    return `${Math.floor(d / 86400000)}d ago`;
  };

  return (
    <div className="space-y-6 p-6">
      {/* ═══════════ HEADER ═══════════ */}
      <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 via-red-400 to-purple-400 bg-clip-text text-transparent">
            🛡️ Exposure Case Command Center
          </h1>
          <p className="text-muted-foreground mt-1">Triage, track, and resolve security exposures across your organization</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <Input placeholder="Filter org..." value={filterOrg} onChange={e => setFilterOrg(e.target.value)}
            className="w-36 bg-gray-800/50 border-gray-600/50 h-9 text-sm" />
          <select value={filterPriority} onChange={e => setFilterPriority(e.target.value)}
            className="h-9 rounded-md border border-gray-600/50 bg-gray-800/50 px-3 text-sm text-gray-300">
            <option value="">All priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <Button size="sm" variant="outline" onClick={() => setShowCreate(!showCreate)}
            className="border-orange-500/40 text-orange-300 hover:bg-orange-500/10">
            ＋ New Case
          </Button>
          <Badge variant="outline" className="text-base px-3 py-1.5 border-orange-500/30 bg-orange-500/10 text-orange-300">
            {stats?.total_cases ?? 0} Cases
          </Badge>
        </div>
      </motion.div>

      {/* ═══════════ CREATE CASE PANEL ═══════════ */}
      <AnimatePresence>
        {showCreate && (
          <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}>
            <Card className="border border-orange-500/30 bg-gray-900/60">
              <CardContent className="p-4 space-y-3">
                <div className="text-sm font-semibold text-orange-300">Create New Exposure Case</div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  <Input placeholder="Title *" value={newCase.title} onChange={e => setNewCase(p => ({ ...p, title: e.target.value }))}
                    className="bg-gray-800/50 border-gray-600/50" />
                  <Input placeholder="Org ID" value={newCase.org_id} onChange={e => setNewCase(p => ({ ...p, org_id: e.target.value }))}
                    className="bg-gray-800/50 border-gray-600/50" />
                  <select value={newCase.priority} onChange={e => setNewCase(p => ({ ...p, priority: e.target.value }))}
                    className="h-10 rounded-md border border-gray-600/50 bg-gray-800/50 px-3 text-sm text-gray-300">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <Input placeholder="Description" value={newCase.description} onChange={e => setNewCase(p => ({ ...p, description: e.target.value }))}
                  className="bg-gray-800/50 border-gray-600/50" />
                <div className="grid grid-cols-2 gap-3">
                  <Input placeholder="Root CVE (e.g. CVE-2024-1234)" value={newCase.root_cve}
                    onChange={e => setNewCase(p => ({ ...p, root_cve: e.target.value }))} className="bg-gray-800/50 border-gray-600/50" />
                  <Input placeholder="Root CWE (e.g. CWE-79)" value={newCase.root_cwe}
                    onChange={e => setNewCase(p => ({ ...p, root_cwe: e.target.value }))} className="bg-gray-800/50 border-gray-600/50" />
                </div>
                <div className="flex gap-2">
                  <Button size="sm" onClick={createCase} disabled={!newCase.title}
                    className="bg-orange-600 hover:bg-orange-500 text-white">Create Case</Button>
                  <Button size="sm" variant="ghost" onClick={() => setShowCreate(false)}>Cancel</Button>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ═══════════ STATS ROW ═══════════ */}
      {stats && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
          className="grid grid-cols-3 md:grid-cols-5 lg:grid-cols-9 gap-2">
          {STATUS_COLUMNS.map(s => (
            <Card key={s} className={`border bg-gradient-to-br ${statusColor(s)} cursor-pointer hover:scale-105 transition-transform`}
              onClick={() => { setFilterPriority(''); setFilterOrg(''); }}>
              <CardContent className="p-3 text-center">
                <div className="text-xl font-bold">{stats.by_status?.[s] ?? 0}</div>
                <div className="text-[10px] text-muted-foreground capitalize flex items-center justify-center gap-1">
                  {statusEmoji(s)} {s.replace('_', ' ')}
                </div>
              </CardContent>
            </Card>
          ))}
          <Card className="border border-amber-500/20 bg-gradient-to-br from-amber-900/10 to-amber-800/5">
            <CardContent className="p-3 text-center">
              <div className={`text-xl font-bold ${riskColor(stats.avg_risk_score)}`}>{stats.avg_risk_score.toFixed(1)}</div>
              <div className="text-[10px] text-muted-foreground">⚡ Avg Risk</div>
            </CardContent>
          </Card>
          <Card className="border border-red-500/20 bg-gradient-to-br from-red-900/10 to-red-800/5">
            <CardContent className="p-3 text-center">
              <div className="text-xl font-bold text-red-400">{stats.kev_cases}</div>
              <div className="text-[10px] text-muted-foreground">🔥 KEV</div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-gray-900/50 border border-gray-700/50">
          <TabsTrigger value="kanban">📋 Kanban</TabsTrigger>
          <TabsTrigger value="list">📄 List</TabsTrigger>
          {selectedCase && <TabsTrigger value="detail">🔬 Detail</TabsTrigger>}
        </TabsList>

        {/* ════════ KANBAN TAB ════════ */}
        <TabsContent value="kanban" className="mt-4">
          {loading ? (
            <div className="text-center py-16 text-muted-foreground animate-pulse">Loading cases...</div>
          ) : cases.length === 0 ? (
            <div className="text-center py-20 text-muted-foreground">
              <div className="text-5xl mb-4">🛡️</div>
              <p className="text-lg">No exposure cases yet</p>
              <p className="text-sm mt-1">Create a case manually or run the Brain Pipeline to auto-generate.</p>
              <Button size="sm" variant="outline" className="mt-4 border-orange-500/40 text-orange-300" onClick={() => setShowCreate(true)}>
                ＋ Create First Case
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-7 gap-3 overflow-x-auto">
              {STATUS_COLUMNS.map(status => {
                const col = casesByStatus(status);
                return (
                  <div key={status} className="min-w-[180px] space-y-2">
                    <div className={`text-xs font-semibold uppercase tracking-wider ${statusHeaderColor(status)} flex items-center gap-1.5 mb-2 px-1`}>
                      {statusEmoji(status)} {status.replace('_', ' ')}
                      <span className="ml-auto text-[10px] font-normal bg-gray-800/60 px-1.5 py-0.5 rounded-full">{col.length}</span>
                    </div>
                    <AnimatePresence>
                      {col.map((c, i) => (
                        <motion.div key={c.case_id} layout
                          initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.9 }} transition={{ delay: i * 0.03 }}
                          onClick={() => { setSelectedCase(c); setActiveTab('detail'); }}
                          className="cursor-pointer">
                          <Card className={`border bg-gradient-to-br ${statusColor(status)} hover:scale-[1.02] transition-transform`}>
                            <CardContent className="p-3 space-y-1.5">
                              <div className="flex items-start justify-between gap-1">
                                <Badge variant="outline" className={`text-[8px] shrink-0 ${priorityColor(c.priority)}`}>
                                  {c.priority?.toUpperCase()}
                                </Badge>
                                {c.in_kev && <span className="text-[9px]" title="In CISA KEV">🔥</span>}
                                {c.risk_score > 0 && (
                                  <span className={`text-[10px] font-mono font-bold ml-auto ${riskColor(c.risk_score)}`}>
                                    {c.risk_score.toFixed(1)}
                                  </span>
                                )}
                              </div>
                              <div className="text-xs font-medium text-gray-200 leading-tight line-clamp-2">{c.title}</div>
                              {c.root_cve && <div className="text-[10px] font-mono text-cyan-400/80">{c.root_cve}</div>}
                              <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-0.5">
                                <span>{c.finding_count} findings</span>
                                <span>{c.cluster_ids?.length ?? 0} clusters</span>
                              </div>
                              {c.sla_due && (
                                <div className={`text-[9px] ${c.sla_breached ? 'text-red-400 font-bold' : 'text-gray-500'}`}>
                                  {c.sla_breached ? '⏰ SLA BREACHED' : `SLA: ${timeAgo(c.sla_due)}`}
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        </motion.div>
                      ))}
                    </AnimatePresence>
                    {col.length === 0 && (
                      <div className="text-[10px] text-muted-foreground text-center py-8 border border-dashed border-gray-700/20 rounded-lg">
                        Empty
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* ════════ LIST TAB ════════ */}
        <TabsContent value="list" className="mt-4">
          <Card className="glass-card border-gray-700/50">
            <CardContent className="p-0">
              {cases.length === 0 ? (
                <div className="text-center py-16 text-muted-foreground">
                  <div className="text-5xl mb-4">🛡️</div>
                  <p className="text-lg">No exposure cases yet</p>
                  <Button size="sm" variant="outline" className="mt-3 border-orange-500/40 text-orange-300"
                    onClick={() => setShowCreate(true)}>＋ Create First Case</Button>
                </div>
              ) : (
                <div className="divide-y divide-gray-800/50">
                  {cases.map((c, i) => (
                    <motion.div key={c.case_id}
                      initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.02 }}
                      onClick={() => { setSelectedCase(c); setActiveTab('detail'); }}
                      className="flex items-center justify-between p-4 hover:bg-gray-800/20 cursor-pointer transition-colors">
                      <div className="flex items-center gap-4">
                        <span className="text-lg">{statusEmoji(c.status)}</span>
                        <div>
                          <div className="text-sm font-medium text-gray-200">{c.title}</div>
                          <div className="text-xs text-muted-foreground flex items-center gap-2">
                            <span className="font-mono">{c.case_id.slice(0, 8)}</span>
                            {c.org_id && <span>· {c.org_id}</span>}
                            {c.root_cve && <span className="text-cyan-400/80 font-mono">{c.root_cve}</span>}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        {c.in_kev && <span title="In CISA KEV">🔥</span>}
                        {c.risk_score > 0 && (
                          <span className={`text-xs font-mono font-bold ${riskColor(c.risk_score)}`}>
                            {c.risk_score.toFixed(1)}
                          </span>
                        )}
                        <Badge variant="outline" className={`text-[10px] ${priorityColor(c.priority)}`}>
                          {c.priority?.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-[10px] bg-gray-800/50 text-gray-300">
                          {c.finding_count} findings
                        </Badge>
                        {c.sla_breached && <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400">⏰ SLA</Badge>}
                        <span className="text-[10px] text-muted-foreground">{timeAgo(c.updated_at)}</span>
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
              {/* ── Header Card ── */}
              <Card className="glass-card border-orange-500/20">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <CardTitle className="text-lg flex items-center gap-3 flex-wrap">
                      <span>{statusEmoji(selectedCase.status)}</span>
                      <span className="text-gray-200">{selectedCase.title}</span>
                      <Badge variant="outline" className={priorityColor(selectedCase.priority)}>{selectedCase.priority?.toUpperCase()}</Badge>
                      {selectedCase.in_kev && <Badge variant="outline" className="border-red-500/40 text-red-400 text-[10px]">🔥 CISA KEV</Badge>}
                    </CardTitle>
                    <Button size="sm" variant="ghost" className="text-xs text-muted-foreground" onClick={() => { setSelectedCase(null); setActiveTab('kanban'); }}>
                      ✕ Close
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {selectedCase.description && (
                    <p className="text-sm text-gray-300 bg-gray-800/30 rounded-lg p-3 border border-gray-700/30">{selectedCase.description}</p>
                  )}
                  {/* Key metrics row */}
                  <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3 text-sm">
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Case ID</div>
                      <div className="font-mono text-gray-200 text-xs">{selectedCase.case_id}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Risk Score</div>
                      <div className={`font-bold text-lg ${riskColor(selectedCase.risk_score)}`}>{selectedCase.risk_score.toFixed(1)}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">EPSS Score</div>
                      <div className="text-gray-200">{selectedCase.epss_score != null ? `${(selectedCase.epss_score * 100).toFixed(1)}%` : '—'}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Findings</div>
                      <div className="text-gray-200 font-bold">{selectedCase.finding_count}</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Blast Radius</div>
                      <div className="text-gray-200">{selectedCase.blast_radius} assets</div>
                    </div>
                    <div className="bg-gray-800/30 rounded-lg p-2.5 border border-gray-700/20">
                      <div className="text-[10px] text-muted-foreground uppercase">Clusters</div>
                      <div className="text-gray-200">{selectedCase.cluster_ids?.length ?? 0}</div>
                    </div>
                  </div>
                  {/* Transition buttons */}
                  <div className="flex gap-2 flex-wrap items-center">
                    <span className="text-xs text-muted-foreground mr-2">Transition →</span>
                    {(VALID_TRANSITIONS[selectedCase.status] || []).map(s => (
                      <Button key={s} size="sm" variant="outline"
                        className="text-xs capitalize border-gray-600/50 hover:bg-gray-800/50"
                        onClick={() => transitionCase(selectedCase.case_id, s)}>
                        {statusEmoji(s)} {s.replace('_', ' ')}
                      </Button>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* ── Root Cause & Assignment ── */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">🎯 Root Cause</CardTitle></CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">CVE:</span><span className="font-mono text-cyan-400">{selectedCase.root_cve || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">CWE:</span><span className="font-mono text-purple-400">{selectedCase.root_cwe || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Component:</span><span className="text-gray-200">{selectedCase.root_component || '—'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Org:</span><span className="text-gray-200">{selectedCase.org_id || '—'}</span></div>
                  </CardContent>
                </Card>
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">👤 Assignment & SLA</CardTitle></CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-muted-foreground">Assigned to:</span><span className="text-gray-200">{selectedCase.assigned_to || 'Unassigned'}</span></div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Team:</span><span className="text-gray-200">{selectedCase.assigned_team || '—'}</span></div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">SLA Due:</span>
                      <span className={selectedCase.sla_breached ? 'text-red-400 font-bold' : 'text-gray-200'}>
                        {selectedCase.sla_due ? `${new Date(selectedCase.sla_due).toLocaleDateString()} ${selectedCase.sla_breached ? '⏰ BREACHED' : ''}` : '—'}
                      </span>
                    </div>
                    <div className="flex justify-between"><span className="text-muted-foreground">Created:</span><span className="text-gray-200">{timeAgo(selectedCase.created_at)}</span></div>
                  </CardContent>
                </Card>
              </div>

              {/* ── Affected Assets ── */}
              {selectedCase.affected_assets?.length > 0 && (
                <Card className="glass-card border-gray-700/30">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-gray-400">🖥️ Affected Assets ({selectedCase.affected_assets.length})</CardTitle></CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {selectedCase.affected_assets.map((a, i) => (
                        <Badge key={i} variant="outline" className="text-xs bg-gray-800/50 border-gray-600/40 text-gray-300">{a}</Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* ── Remediation ── */}
              {(selectedCase.remediation_plan || selectedCase.playbook_id || selectedCase.autofix_pr_url) && (
                <Card className="glass-card border-green-500/20">
                  <CardHeader className="pb-2"><CardTitle className="text-sm text-green-400">🔧 Remediation</CardTitle></CardHeader>
                  <CardContent className="space-y-2 text-sm">
                    {selectedCase.remediation_plan && (
                      <div className="bg-gray-800/30 rounded-lg p-3 border border-gray-700/20 text-gray-300 whitespace-pre-wrap">{selectedCase.remediation_plan}</div>
                    )}
                    {selectedCase.playbook_id && <div className="flex justify-between"><span className="text-muted-foreground">Playbook:</span><span className="font-mono text-gray-200">{selectedCase.playbook_id}</span></div>}
                    {selectedCase.autofix_pr_url && (
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">AutoFix PR:</span>
                        <a href={selectedCase.autofix_pr_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline text-xs">{selectedCase.autofix_pr_url}</a>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* ── Tags ── */}
              {selectedCase.tags?.length > 0 && (
                <div className="flex gap-2 flex-wrap">
                  {selectedCase.tags.map((t, i) => (
                    <Badge key={i} variant="outline" className="text-[10px] bg-blue-500/10 border-blue-500/30 text-blue-300">🏷️ {t}</Badge>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-16 text-muted-foreground">
              <div className="text-4xl mb-3">👈</div>
              <p>Select a case from the Kanban board or list to view details</p>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ExposureCaseCenter;