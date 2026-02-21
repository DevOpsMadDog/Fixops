import { useState, useSyncExternalStore, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity, X, Trash2, ChevronUp, Minimize2,
  CheckCircle2, XCircle, Loader2, Clock, Copy,
  Navigation, MousePointerClick, FileText, Filter
} from 'lucide-react';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import {
  getApiLogs, subscribeApiLogs, clearApiLogs,
  type ApiLogEntry
} from '../lib/api';

function statusColor(entry: ApiLogEntry) {
  if (entry.state === 'pending') return 'text-yellow-400';
  if (entry.state === 'error') return 'text-red-400';
  if (entry.status && entry.status >= 200 && entry.status < 300) return 'text-green-400';
  if (entry.status && entry.status >= 400) return 'text-orange-400';
  return 'text-muted-foreground';
}

function StatusIcon({ entry }: { entry: ApiLogEntry }) {
  if (entry.type === 'navigation') return <Navigation className="w-3 h-3 text-cyan-400" />;
  if (entry.type === 'click') return <MousePointerClick className="w-3 h-3 text-purple-400" />;
  if (entry.type === 'form') return <FileText className="w-3 h-3 text-amber-400" />;
  if (entry.state === 'pending') return <Loader2 className="w-3 h-3 animate-spin text-yellow-400" />;
  if (entry.state === 'error') return <XCircle className="w-3 h-3 text-red-400" />;
  return <CheckCircle2 className="w-3 h-3 text-green-400" />;
}

function methodBadge(method: string) {
  const colors: Record<string, string> = {
    GET: 'bg-blue-500/20 text-blue-300',
    POST: 'bg-green-500/20 text-green-300',
    PUT: 'bg-yellow-500/20 text-yellow-300',
    PATCH: 'bg-orange-500/20 text-orange-300',
    DELETE: 'bg-red-500/20 text-red-300',
    NAV: 'bg-cyan-500/20 text-cyan-300',
    CLICK: 'bg-purple-500/20 text-purple-300',
    FORM: 'bg-amber-500/20 text-amber-300',
  };
  return colors[method] || 'bg-muted text-muted-foreground';
}

/** Pretty-print JSON with truncation */
function JsonBlock({ data, label }: { data: string | null; label: string }) {
  if (!data) return null;
  let formatted: string;
  try { formatted = JSON.stringify(JSON.parse(data), null, 2) } catch { formatted = data }
  const lines = formatted.split('\n');
  const truncated = lines.length > 30;
  const display = truncated ? lines.slice(0, 30).join('\n') + '\n…' : formatted;
  return (
    <div className="mt-1">
      <div className="flex items-center justify-between">
        <span className="text-muted-foreground/70 uppercase text-[9px]">{label}</span>
        <button
          className="text-muted-foreground/50 hover:text-primary transition-colors"
          onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(formatted) }}
          title="Copy to clipboard"
        ><Copy className="w-2.5 h-2.5" /></button>
      </div>
      <pre className="bg-black/30 rounded p-1.5 overflow-x-auto max-h-[200px] overflow-y-auto text-[9px] leading-tight whitespace-pre-wrap break-all">{display}</pre>
    </div>
  );
}

type FilterType = 'all' | 'api' | 'navigation' | 'click' | 'form';

export default function ApiActivityPanel() {
  const logs = useSyncExternalStore(subscribeApiLogs, getApiLogs, getApiLogs);
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<FilterType>('all');

  const filtered = filter === 'all' ? logs : logs.filter(l => l.type === filter);
  const errorCount = logs.filter(l => l.state === 'error').length;
  const pendingCount = logs.filter(l => l.state === 'pending').length;
  const apiCount = logs.filter(l => l.type === 'api').length;
  const navCount = logs.filter(l => l.type === 'navigation').length;
  const clickCount = logs.filter(l => l.type === 'click').length;

  const copyAll = useCallback(() => {
    navigator.clipboard.writeText(JSON.stringify(logs, null, 2));
  }, [logs]);

  if (!isOpen) {
    return (
      <motion.button
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        onClick={() => setIsOpen(true)}
        className="fixed bottom-4 right-4 z-[9999] flex items-center gap-2 px-3 py-2 rounded-full bg-card border border-border shadow-lg hover:bg-accent transition-colors"
        title="Activity Monitor — API calls, navigations, clicks"
      >
        <Activity className="w-4 h-4 text-primary" />
        <span className="text-xs font-medium">{logs.length}</span>
        {errorCount > 0 && <Badge variant="destructive" className="text-[9px] px-1 h-4">{errorCount} err</Badge>}
        {pendingCount > 0 && <Badge className="text-[9px] px-1 h-4 bg-yellow-500/20 text-yellow-300">{pendingCount}</Badge>}
      </motion.button>
    );
  }

  return (
    <motion.div
      initial={{ y: 300, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      exit={{ y: 300, opacity: 0 }}
      className="fixed bottom-4 right-4 z-[9999] w-[560px] bg-card border border-border rounded-lg shadow-2xl flex flex-col"
      style={{ maxHeight: isMinimized ? 44 : '70vh' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-border bg-card/80 backdrop-blur rounded-t-lg">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-primary" />
          <span className="text-sm font-semibold">Activity Monitor</span>
          <Badge variant="outline" className="text-[9px] h-4">{logs.length}</Badge>
          {errorCount > 0 && <Badge variant="destructive" className="text-[9px] h-4">{errorCount} err</Badge>}
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={copyAll} title="Copy all logs as JSON">
            <Copy className="w-3 h-3" />
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => clearApiLogs()} title="Clear logs">
            <Trash2 className="w-3 h-3" />
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => setIsMinimized(!isMinimized)}>
            {isMinimized ? <ChevronUp className="w-3 h-3" /> : <Minimize2 className="w-3 h-3" />}
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => setIsOpen(false)}>
            <X className="w-3 h-3" />
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      {!isMinimized && (
        <div className="flex items-center gap-1 px-2 py-1 border-b border-border/50 bg-card/50">
          <Filter className="w-3 h-3 text-muted-foreground" />
          {([['all', `All (${logs.length})`], ['api', `API (${apiCount})`], ['navigation', `Nav (${navCount})`], ['click', `Click (${clickCount})`]] as const).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setFilter(key as FilterType)}
              className={`px-2 py-0.5 rounded text-[10px] transition-colors ${filter === key ? 'bg-primary/20 text-primary' : 'text-muted-foreground hover:text-foreground'}`}
            >{label}</button>
          ))}
        </div>
      )}

      {/* Log entries */}
      {!isMinimized && (
        <div className="flex-1 overflow-y-auto p-1 space-y-0.5 scrollbar-thin">
          {filtered.length === 0 && (
            <div className="text-center text-muted-foreground text-xs py-8">No activity yet. Interact with the UI to see events.</div>
          )}
          {filtered.map((entry) => (
            <div key={entry.id} className="group">
              <button
                onClick={() => setExpandedId(expandedId === entry.id ? null : entry.id)}
                className={`w-full flex items-center gap-2 px-2 py-1 rounded text-left text-xs hover:bg-accent/50 transition-colors ${entry.state === 'error' ? 'bg-red-500/5' : ''}`}
              >
                <StatusIcon entry={entry} />
                <span className={`font-mono px-1 rounded text-[10px] ${methodBadge(entry.method)}`}>{entry.method}</span>
                <span className={`flex-1 truncate font-mono ${statusColor(entry)}`}>
                  {entry.type === 'click' ? (entry.target || '') : entry.type === 'navigation' ? entry.page : entry.url.replace(/(https?:\/\/[^/]+)/, '')}
                </span>
                {entry.status != null && <span className="text-muted-foreground tabular-nums">{entry.status}</span>}
                {entry.duration != null && (
                  <span className="text-muted-foreground tabular-nums flex items-center gap-0.5">
                    <Clock className="w-2.5 h-2.5" />{entry.duration}ms
                  </span>
                )}
                {entry.responseSize != null && (
                  <span className="text-muted-foreground/60 tabular-nums text-[9px]">{(entry.responseSize / 1024).toFixed(1)}K</span>
                )}
              </button>
              <AnimatePresence>
                {expandedId === entry.id && (
                  <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                    <div className="ml-6 px-2 py-1.5 text-[10px] font-mono text-muted-foreground space-y-1 border-l-2 border-primary/30">
                      <p><span className="text-muted-foreground/60">URL:</span> {entry.url}</p>
                      <p><span className="text-muted-foreground/60">Time:</span> {new Date(entry.timestamp).toLocaleTimeString()}.{String(entry.timestamp % 1000).padStart(3, '0')}</p>
                      {entry.type === 'api' && <p><span className="text-muted-foreground/60">API Key:</span> {entry.requestHeaders['X-API-Key']}</p>}
                      {entry.duration != null && <p><span className="text-muted-foreground/60">Duration:</span> {entry.duration}ms</p>}
                      {entry.error && <p className="text-red-400"><span className="text-red-400/60">Error:</span> {entry.error}</p>}
                      {entry.page && <p><span className="text-muted-foreground/60">Page:</span> {entry.page}</p>}
                      {entry.target && entry.type === 'click' && <p><span className="text-muted-foreground/60">Target:</span> {entry.target}</p>}
                      {entry.metadata && <p><span className="text-muted-foreground/60">Meta:</span> {JSON.stringify(entry.metadata)}</p>}
                      {Object.keys(entry.responseHeaders).length > 0 && (
                        <div className="mt-1">
                          <span className="text-muted-foreground/70 uppercase text-[9px]">Response Headers</span>
                          <div className="bg-black/20 rounded p-1 text-[9px]">
                            {Object.entries(entry.responseHeaders).map(([k, v]) => (
                              <div key={k}><span className="text-blue-400">{k}:</span> {v}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      <JsonBlock data={entry.requestBody} label="Request Body" />
                      <JsonBlock data={entry.responseBody} label="Response Body" />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}
        </div>
      )}
    </motion.div>
  );
}

