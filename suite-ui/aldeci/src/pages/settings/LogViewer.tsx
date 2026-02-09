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

  /* placeholder — rest of component will be added */
  return <div className="p-6 space-y-6"><h1 className="text-3xl font-bold">Log Viewer</h1></div>;
}

