import { useState, useEffect, useCallback, useRef, useSyncExternalStore } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import {
  Activity, Download, Trash2, RefreshCw, Search, Copy,
  ChevronDown, ChevronUp, Filter, Wifi, WifiOff,
  CheckCircle2, XCircle, Loader2, Clock, ArrowUpDown,
  Navigation, MousePointerClick, FileText
} from 'lucide-react';
import api, {
  getApiLogs, subscribeApiLogs, clearApiLogs,
  type ApiLogEntry, type LogEntryType
} from '../../lib/api';

/* ── Helpers ────────────────────────────────────────── */

function statusBg(s: number | null): string {
  if (s == null) return 'bg-yellow-500/15 text-yellow-300';
  if (s >= 200 && s < 300) return 'bg-green-500/15 text-green-300';
  if (s >= 300 && s < 400) return 'bg-blue-500/15 text-blue-300';
  if (s >= 400 && s < 500) return 'bg-orange-500/15 text-orange-300';
  return 'bg-red-500/15 text-red-300';
}

function methodColor(m: string): string {
  const map: Record<string, string> = {
    GET: 'bg-blue-500/20 text-blue-300', POST: 'bg-green-500/20 text-green-300',
    PUT: 'bg-yellow-500/20 text-yellow-300', PATCH: 'bg-orange-500/20 text-orange-300',
    DELETE: 'bg-red-500/20 text-red-300', NAV: 'bg-cyan-500/20 text-cyan-300',
    CLICK: 'bg-purple-500/20 text-purple-300', FORM: 'bg-amber-500/20 text-amber-300',
  };
  return map[m] || 'bg-muted text-muted-foreground';
}

function fmtTs(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString('en-GB', { hour12: false }) + '.' + String(ts % 1000).padStart(3, '0');
}

function fmtSize(bytes: number | null): string {
  if (bytes == null) return '—';
  if (bytes < 1024) return `${bytes}B`;
  return `${(bytes / 1024).toFixed(1)}KB`;
}

function StatusIcon({ entry }: { entry: ApiLogEntry }) {
  if (entry.type === 'navigation') return <Navigation className="w-3.5 h-3.5 text-cyan-400" />;
  if (entry.type === 'click') return <MousePointerClick className="w-3.5 h-3.5 text-purple-400" />;
  if (entry.type === 'form') return <FileText className="w-3.5 h-3.5 text-amber-400" />;
  if (entry.state === 'pending') return <Loader2 className="w-3.5 h-3.5 animate-spin text-yellow-400" />;
  if (entry.state === 'error') return <XCircle className="w-3.5 h-3.5 text-red-400" />;
  return <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />;
}

function JsonViewer({ data, label }: { data: string | null; label: string }) {
  if (!data) return null;
  let formatted: string;
  try { formatted = JSON.stringify(JSON.parse(data), null, 2); } catch { formatted = data; }
  return (
    <div className="mt-2">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        <button onClick={() => navigator.clipboard.writeText(formatted)}
          className="text-muted-foreground hover:text-primary transition-colors" title="Copy">
          <Copy className="w-3 h-3" />
        </button>
      </div>
      <pre className="bg-black/40 rounded-md p-3 overflow-x-auto max-h-[300px] overflow-y-auto text-xs leading-relaxed whitespace-pre-wrap break-all font-mono">
        {formatted.length > 5000 ? formatted.slice(0, 5000) + '\n…[truncated]' : formatted}
      </pre>
    </div>
  );
}

/* ── Backend Log Types ──────────────────────────────── */

interface BackendLog {
  id: number; ts: string; method: string; path: string; query_params: string;
  status_code: number; duration_ms: number; client_ip: string; user_agent: string;
  correlation_id: string; req_headers: string; req_body: string;
  resp_headers: string; resp_body: string; req_size: number; resp_size: number;
  error: string | null; error_type: string | null; level: string;
}

interface BackendLogStats {
  total: number; errors: number; avg_duration_ms: number;
  by_method: Record<string, number>; by_status: Record<string, number>;
}

type FilterType = 'all' | 'api' | 'navigation' | 'click';
type SortField = 'timestamp' | 'duration' | 'status' | 'method';
type SortDir = 'asc' | 'desc';
type ViewTab = 'frontend' | 'backend';

/* ── Component ──────────────────────────────────────── */

export default function LogViewer() {
  // Frontend logs from in-memory store
  const feLogs = useSyncExternalStore(subscribeApiLogs, getApiLogs, getApiLogs);

  // Backend logs
  const [beLogs, setBeLogs] = useState<BackendLog[]>([]);
  const [beStats, setBeStats] = useState<BackendLogStats | null>(null);
  const [beLoading, setBeLoading] = useState(false);
  const [beTotal, setBeTotal] = useState(0);
  const [bePage, setBePage] = useState(0);
  const bePageSize = 50;

  // Shared UI state
  const [tab, setTab] = useState<ViewTab>('frontend');
  const [filter, setFilter] = useState<FilterType>('all');
  const [search, setSearch] = useState('');
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const sseRef = useRef<EventSource | null>(null);

  // Backend methods
  const [beMethodFilter, setBeMethodFilter] = useState('');
  const [beStatusMin, setBeStatusMin] = useState('');
  const [beStatusMax, setBeStatusMax] = useState('');
  const [beSearch, setBeSearch] = useState('');

  /* ── Backend fetchers ──────────────────────────── */

  const fetchBackendLogs = useCallback(async () => {
    setBeLoading(true);
    try {
      const params: Record<string, string | number> = { limit: bePageSize, offset: bePage * bePageSize };
      if (beMethodFilter) params.method = beMethodFilter;
      if (beStatusMin) params.status_min = Number(beStatusMin);
      if (beStatusMax) params.status_max = Number(beStatusMax);
      if (beSearch) params.search = beSearch;
      const res = await api.get('/api/v1/logs', { params });
      const data = res.data;
      setBeLogs(Array.isArray(data) ? data : data?.items || []);
      setBeTotal(data?.total ?? (Array.isArray(data) ? data.length : 0));
    } catch (e) { console.error('Failed to fetch backend logs', e); }
    finally { setBeLoading(false); }
  }, [bePage, beMethodFilter, beStatusMin, beStatusMax, beSearch]);

  const fetchBackendStats = useCallback(async () => {
    try {
      const res = await api.get('/api/v1/logs/stats');
      setBeStats(res.data);
    } catch { /* ignore */ }
  }, []);

  useEffect(() => { if (tab === 'backend') { fetchBackendLogs(); fetchBackendStats(); } },
    [tab, fetchBackendLogs, fetchBackendStats]);

  /* ── SSE streaming ───────────────────────────────── */

  const toggleStreaming = useCallback(() => {
    if (streaming && sseRef.current) { sseRef.current.close(); sseRef.current = null; setStreaming(false); return; }
    try {
      const es = new EventSource('/api/v1/logs/stream');
      es.onmessage = () => { fetchBackendLogs(); fetchBackendStats(); };
      es.onerror = () => { es.close(); setStreaming(false); };
      sseRef.current = es;
      setStreaming(true);
    } catch { setStreaming(false); }
  }, [streaming, fetchBackendLogs, fetchBackendStats]);

  useEffect(() => { return () => { sseRef.current?.close(); }; }, []);

  /* ── Frontend filtering & sorting ──────────────── */

  const filtered = (() => {
    let out = filter === 'all' ? feLogs : feLogs.filter(l => l.type === filter);
    if (search) {
      const q = search.toLowerCase();
      out = out.filter(l =>
        l.url.toLowerCase().includes(q) || l.method.toLowerCase().includes(q) ||
        (l.target || '').toLowerCase().includes(q) || (l.page || '').toLowerCase().includes(q) ||
        (l.responseBody || '').toLowerCase().includes(q)
      );
    }
    const dir = sortDir === 'asc' ? 1 : -1;
    out = [...out].sort((a, b) => {
      if (sortField === 'timestamp') return dir * (a.timestamp - b.timestamp);
      if (sortField === 'duration') return dir * ((a.duration ?? 0) - (b.duration ?? 0));
      if (sortField === 'status') return dir * ((a.status ?? 0) - (b.status ?? 0));
      return dir * a.method.localeCompare(b.method);
    });
    return out;
  })();

  const feStats = {
    total: feLogs.length,
    api: feLogs.filter(l => l.type === 'api').length,
    nav: feLogs.filter(l => l.type === 'navigation').length,
    click: feLogs.filter(l => l.type === 'click').length,
    errors: feLogs.filter(l => l.state === 'error').length,
    avgDuration: feLogs.filter(l => l.duration != null).length > 0
      ? Math.round(feLogs.filter(l => l.duration != null).reduce((s, l) => s + (l.duration ?? 0), 0) / feLogs.filter(l => l.duration != null).length)
      : 0,
  };

  /* ── Export ──────────────────────────────────────── */

  const exportLogs = useCallback((format: 'json' | 'csv') => {
    const data = tab === 'frontend' ? filtered : beLogs;
    let blob: Blob;
    if (format === 'json') {
      blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    } else {
      const keys = data.length > 0 ? Object.keys(data[0]) : [];
      const csv = [keys.join(','), ...data.map((r: Record<string, unknown>) => keys.map(k => JSON.stringify(r[k] ?? '')).join(','))].join('\n');
      blob = new Blob([csv], { type: 'text/csv' });
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `aldeci-logs-${tab}-${Date.now()}.${format}`;
    a.click(); URL.revokeObjectURL(url);
  }, [tab, filtered, beLogs]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortField(field); setSortDir('desc'); }
  };

  /* ── Render ─────────────────────────────────────── */

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Activity className="w-8 h-8 text-primary" /> Log Viewer
          </h1>
          <p className="text-muted-foreground mt-1">Full request/response logging — every screen, every button, every API call</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => exportLogs('json')}>
            <Download className="w-4 h-4 mr-1" /> JSON
          </Button>
          <Button variant="outline" size="sm" onClick={() => exportLogs('csv')}>
            <Download className="w-4 h-4 mr-1" /> CSV
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Card><CardContent className="pt-4 pb-3 text-center">
          <div className="text-2xl font-bold">{tab === 'frontend' ? feStats.total : beStats?.total ?? '—'}</div>
          <div className="text-xs text-muted-foreground">Total Logs</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4 pb-3 text-center">
          <div className="text-2xl font-bold text-red-400">{tab === 'frontend' ? feStats.errors : beStats?.errors ?? '—'}</div>
          <div className="text-xs text-muted-foreground">Errors</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4 pb-3 text-center">
          <div className="text-2xl font-bold text-blue-400">{tab === 'frontend' ? feStats.api : beStats?.by_method?.GET ?? '—'}</div>
          <div className="text-xs text-muted-foreground">{tab === 'frontend' ? 'API Calls' : 'GET Requests'}</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4 pb-3 text-center">
          <div className="text-2xl font-bold text-cyan-400">{tab === 'frontend' ? feStats.nav : beStats?.by_method?.POST ?? '—'}</div>
          <div className="text-xs text-muted-foreground">{tab === 'frontend' ? 'Navigations' : 'POST Requests'}</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4 pb-3 text-center">
          <div className="text-2xl font-bold text-purple-400">{tab === 'frontend' ? feStats.click : Object.values(beStats?.by_status ?? {}).reduce((a, b) => a + b, 0) || '—'}</div>
          <div className="text-xs text-muted-foreground">{tab === 'frontend' ? 'Clicks' : 'Total by Status'}</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4 pb-3 text-center">
          <div className="text-2xl font-bold text-green-400">{tab === 'frontend' ? `${feStats.avgDuration}ms` : `${Math.round(beStats?.avg_duration_ms ?? 0)}ms`}</div>
          <div className="text-xs text-muted-foreground">Avg Duration</div>
        </CardContent></Card>
      </div>

      {/* Tabs */}
      <Tabs value={tab} onValueChange={(v) => setTab(v as ViewTab)}>
        <div className="flex items-center justify-between">
          <TabsList>
            <TabsTrigger value="frontend">🖥️ Frontend Logs ({feLogs.length})</TabsTrigger>
            <TabsTrigger value="backend">🖧 Backend Logs ({beStats?.total ?? '…'})</TabsTrigger>
          </TabsList>
          <div className="flex items-center gap-2">
            {tab === 'frontend' && (
              <Button variant="ghost" size="sm" onClick={() => clearApiLogs()}>
                <Trash2 className="w-4 h-4 mr-1" /> Clear
              </Button>
            )}
            {tab === 'backend' && (
              <>
                <Button variant={streaming ? 'default' : 'outline'} size="sm" onClick={toggleStreaming}>
                  {streaming ? <><Wifi className="w-4 h-4 mr-1 animate-pulse" /> Live</> : <><WifiOff className="w-4 h-4 mr-1" /> Stream</>}
                </Button>
                <Button variant="ghost" size="sm" onClick={() => { fetchBackendLogs(); fetchBackendStats(); }}>
                  <RefreshCw className={`w-4 h-4 mr-1 ${beLoading ? 'animate-spin' : ''}`} /> Refresh
                </Button>
              </>
            )}
          </div>
        </div>

        {/* ── Frontend Tab ──────────────────────────── */}
        <TabsContent value="frontend" className="space-y-4 mt-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="w-4 h-4 text-muted-foreground" />
            {(['all', 'api', 'navigation', 'click'] as FilterType[]).map(f => (
              <Button key={f} variant={filter === f ? 'default' : 'outline'} size="sm"
                onClick={() => setFilter(f)} className="capitalize h-7 text-xs">
                {f === 'all' ? `All (${feLogs.length})` : `${f} (${feLogs.filter(l => l.type === f).length})`}
              </Button>
            ))}
            <div className="flex-1" />
            <div className="relative w-64">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input placeholder="Search logs…" value={search} onChange={e => setSearch(e.target.value)}
                className="pl-8 h-7 text-xs" />
            </div>
          </div>

          {/* Table Header */}
          <div className="grid grid-cols-[40px_70px_1fr_70px_80px_60px] gap-2 px-3 py-2 text-xs font-medium text-muted-foreground border-b border-border">
            <span />
            <button className="flex items-center gap-1" onClick={() => toggleSort('method')}>Method <ArrowUpDown className="w-3 h-3" /></button>
            <span>URL / Target</span>
            <button className="flex items-center gap-1" onClick={() => toggleSort('status')}>Status <ArrowUpDown className="w-3 h-3" /></button>
            <button className="flex items-center gap-1" onClick={() => toggleSort('duration')}>Duration <ArrowUpDown className="w-3 h-3" /></button>
            <span>Size</span>
          </div>

          {/* Rows */}
          <div className="max-h-[60vh] overflow-y-auto space-y-0.5">
            {filtered.length === 0 && (
              <div className="text-center text-muted-foreground py-12">No log entries match your filters. Interact with the UI to generate logs.</div>
            )}
            {filtered.map(entry => (
              <div key={entry.id}>
                <button
                  onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                  className={`w-full grid grid-cols-[40px_70px_1fr_70px_80px_60px] gap-2 px-3 py-1.5 text-xs rounded hover:bg-accent/50 transition-colors items-center ${entry.state === 'error' ? 'bg-red-500/5' : ''}`}
                >
                  <StatusIcon entry={entry} />
                  <span className={`font-mono px-1.5 py-0.5 rounded text-[11px] text-center ${methodColor(entry.method)}`}>{entry.method}</span>
                  <span className="truncate text-left font-mono text-muted-foreground">
                    {entry.type === 'click' ? (entry.target || '') : entry.type === 'navigation' ? entry.page : entry.url.replace(/(https?:\/\/[^/]+)/, '')}
                  </span>
                  <span className={`text-center px-1 py-0.5 rounded ${statusBg(entry.status)}`}>{entry.status ?? '—'}</span>
                  <span className="text-center text-muted-foreground flex items-center justify-center gap-1">
                    <Clock className="w-3 h-3" />{entry.duration != null ? `${entry.duration}ms` : '—'}
                  </span>
                  <span className="text-center text-muted-foreground/60">{fmtSize(entry.responseSize)}</span>
                </button>
                {expandedId === entry.id && (
                  <div className="ml-10 mr-4 mb-2 p-3 rounded-md bg-card/50 border border-border/50 space-y-2 text-xs font-mono">
                    <div className="grid grid-cols-2 gap-x-6 gap-y-1">
                      <p><span className="text-muted-foreground">Time:</span> {fmtTs(entry.timestamp)}</p>
                      <p><span className="text-muted-foreground">Type:</span> {entry.type}</p>
                      <p><span className="text-muted-foreground">URL:</span> {entry.url}</p>
                      {entry.duration != null && <p><span className="text-muted-foreground">Duration:</span> {entry.duration}ms</p>}
                      {entry.page && <p><span className="text-muted-foreground">Page:</span> {entry.page}</p>}
                      {entry.target && <p><span className="text-muted-foreground">Target:</span> {entry.target}</p>}
                      {entry.error && <p className="text-red-400 col-span-2"><span className="text-red-400/60">Error:</span> {entry.error}</p>}
                    </div>
                    {Object.keys(entry.requestHeaders).length > 0 && (
                      <JsonViewer data={JSON.stringify(entry.requestHeaders)} label="Request Headers" />
                    )}
                    <JsonViewer data={entry.requestBody} label="Request Body" />
                    {Object.keys(entry.responseHeaders).length > 0 && (
                      <JsonViewer data={JSON.stringify(entry.responseHeaders)} label="Response Headers" />
                    )}
                    <JsonViewer data={entry.responseBody} label="Response Body" />
                    {entry.metadata && <JsonViewer data={JSON.stringify(entry.metadata)} label="Metadata" />}
                  </div>
                )}
              </div>
            ))}
          </div>
        </TabsContent>

        {/* ── Backend Tab (placeholder — will be added) ── */}
        <TabsContent value="backend" className="space-y-4 mt-4">
          <div>Backend tab content</div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

