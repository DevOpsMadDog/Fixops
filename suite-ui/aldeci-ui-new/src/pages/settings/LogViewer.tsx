import { useState, useRef, useCallback, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  FileText,
  Search,
  Download,
  Filter,
  RefreshCw,
  ChevronDown,
  AlertCircle,
  Info,
  Bug,
  XOctagon,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { systemApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
type LogLevel = "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";

interface LogEntry {
  id: string;
  timestamp: string;
  level: LogLevel;
  service: string;
  message: string;
  trace_id?: string;
  user?: string;
}

function makeTimestamp(minsAgo: number): string {
  const d = new Date(Date.now() - minsAgo * 60000);
  return d.toISOString().replace("T", " ").slice(0, 23);
}

const MOCK_LOGS: LogEntry[] = [
  { id: "l001", timestamp: makeTimestamp(0), level: "INFO", service: "api", message: "GET /api/v1/cases?severity=critical — 200 OK (42ms)", trace_id: "tr-8f3k2" },
  { id: "l002", timestamp: makeTimestamp(0), level: "INFO", service: "scanner-ingest", message: "Snyk SARIF parsed: 1247 findings ingested, 3 deduped", trace_id: "tr-9d2p1" },
  { id: "l003", timestamp: makeTimestamp(1), level: "WARNING", service: "scanner-ingest", message: "Qualys sync latency elevated: 184ms (threshold: 100ms)", trace_id: "tr-7b1x" },
  { id: "l004", timestamp: makeTimestamp(1), level: "INFO", service: "queue", message: "Task autofix.generate completed in 2341ms — job_id: job_92bca", trace_id: "tr-4c8n" },
  { id: "l005", timestamp: makeTimestamp(2), level: "ERROR", service: "api", message: "POST /api/v1/integrations/anchore/test — 503 Service Unavailable", trace_id: "tr-5d9m", user: "s.chen@acme.com" },
  { id: "l006", timestamp: makeTimestamp(2), level: "INFO", service: "auth", message: "SSO login successful — user: m.williams@acme.com via Okta", trace_id: "tr-6e0n", user: "m.williams@acme.com" },
  { id: "l007", timestamp: makeTimestamp(3), level: "DEBUG", service: "graph", message: "Attack path traversal: 847 nodes, 2341 edges, depth=6 in 891ms", trace_id: "tr-1f2a" },
  { id: "l008", timestamp: makeTimestamp(3), level: "INFO", service: "copilot", message: "LLM inference complete: 1847 tokens, model=gpt-4o, latency=892ms", trace_id: "tr-2g3b" },
  { id: "l009", timestamp: makeTimestamp(4), level: "CRITICAL", service: "api", message: "Rate limit exceeded for IP 203.0.113.42 — 1000 req/min threshold", trace_id: "tr-3h4c", user: "anonymous" },
  { id: "l010", timestamp: makeTimestamp(5), level: "INFO", service: "compliance", message: "SOC2 evidence bundle generated: 147 controls, 89 passing", trace_id: "tr-5i6d" },
  { id: "l011", timestamp: makeTimestamp(6), level: "WARNING", service: "db", message: "Slow query detected: SELECT * FROM findings WHERE... (823ms)", trace_id: "tr-6j7e" },
  { id: "l012", timestamp: makeTimestamp(7), level: "INFO", service: "audit", message: "Hash chain verified: block 12847, prev=sha256:a3f4b2..., current=sha256:9d8e1f...", trace_id: "tr-7k8f" },
  { id: "l013", timestamp: makeTimestamp(8), level: "ERROR", service: "queue", message: "Task evidence.generate failed: timeout after 30000ms — retrying (1/3)", trace_id: "tr-8l9g" },
  { id: "l014", timestamp: makeTimestamp(9), level: "INFO", service: "scanner-ingest", message: "Trivy container scan completed: 892 findings, 14 critical", trace_id: "tr-9m0h" },
  { id: "l015", timestamp: makeTimestamp(10), level: "DEBUG", service: "cache", message: "Cache miss ratio: 4.2% (target: <10%) — hot keys: findings:critical", trace_id: "tr-0n1i" },
  { id: "l016", timestamp: makeTimestamp(11), level: "INFO", service: "api", message: "POST /api/v1/bulk/triage — 43 findings triaged by p.sharma@acme.com", trace_id: "tr-1o2j", user: "p.sharma@acme.com" },
  { id: "l017", timestamp: makeTimestamp(12), level: "WARNING", service: "auth", message: "MFA challenge failed for d.stone@acme.com (attempt 2/3)", trace_id: "tr-2p3k", user: "d.stone@acme.com" },
  { id: "l018", timestamp: makeTimestamp(13), level: "INFO", service: "api", message: "Scheduled scan triggered: daily-full — apps=87, scanners=19", trace_id: "tr-3q4l" },
  { id: "l019", timestamp: makeTimestamp(14), level: "CRITICAL", service: "db", message: "Replication lag spike: 4200ms — primary:replica skew detected", trace_id: "tr-4r5m" },
  { id: "l020", timestamp: makeTimestamp(15), level: "INFO", service: "api", message: "DELETE /api/v1/users/u10 — user d.stone@acme.com suspended by s.chen@acme.com", trace_id: "tr-5s6n", user: "s.chen@acme.com" },
  { id: "l021", timestamp: makeTimestamp(16), level: "DEBUG", service: "graph", message: "Knowledge graph sync: 12847 assets, 34921 relationships updated", trace_id: "tr-6t7o" },
  { id: "l022", timestamp: makeTimestamp(17), level: "INFO", service: "notifications", message: "PagerDuty incident created: INC-20891 for CRITICAL finding CVE-2025-0001", trace_id: "tr-7u8p" },
  { id: "l023", timestamp: makeTimestamp(18), level: "WARNING", service: "scanner-ingest", message: "TruffleHog connector last sync: 6h ago — connection may be stale", trace_id: "tr-8v9q" },
  { id: "l024", timestamp: makeTimestamp(19), level: "INFO", service: "compliance", message: "CIS Benchmark assessment started: 847 controls, 12 cloud accounts", trace_id: "tr-9w0r" },
  { id: "l025", timestamp: makeTimestamp(20), level: "ERROR", service: "ai", message: "OpenAI API error: 429 Too Many Requests — falling back to local model", trace_id: "tr-0x1s" },
  { id: "l026", timestamp: makeTimestamp(22), level: "INFO", service: "auth", message: "API key ak_prod_8f3k2j accessed from new IP 198.51.100.88 — notified", trace_id: "tr-1y2t" },
  { id: "l027", timestamp: makeTimestamp(24), level: "INFO", service: "queue", message: "Worker celery@worker-2 started — queues: default, high_priority", trace_id: "tr-2z3u" },
  { id: "l028", timestamp: makeTimestamp(26), level: "DEBUG", service: "api", message: "Health check OK — db: 3ms, redis: 1ms, neo4j: 67ms", trace_id: "tr-3a4v" },
  { id: "l029", timestamp: makeTimestamp(28), level: "INFO", service: "scanner-ingest", message: "Wiz CNAPP sync: 2341 cloud findings, 187 new, 54 resolved", trace_id: "tr-4b5w" },
  { id: "l030", timestamp: makeTimestamp(30), level: "WARNING", service: "api", message: "Slow endpoint: GET /api/v1/graph/visualize?depth=8 — 3421ms", trace_id: "tr-5c6x" },
  ...Array.from({ length: 70 }, (_, i): LogEntry => ({
    id: `l${String(i + 31).padStart(3, "0")}`,
    timestamp: makeTimestamp(30 + i * 2),
    level: (["INFO", "INFO", "DEBUG", "INFO", "WARNING", "INFO", "INFO", "ERROR"][i % 8]) as LogLevel,
    service: ["api", "db", "queue", "scanner-ingest", "auth", "compliance", "graph", "cache"][i % 8],
    message: [
      "Request processed successfully",
      "Query executed in 4ms",
      "Cache warmed: 1200 keys",
      "Scanner results normalized: 45 findings",
      "Session timeout warning for idle user",
      "Evidence record created: ev_" + Math.random().toString(36).slice(2, 8),
      "Graph traversal depth: " + (i % 6 + 2),
      "Cache hit ratio: 96.2%",
    ][i % 8],
    trace_id: "tr-" + Math.random().toString(36).slice(2, 7),
  })),
];

const LEVEL_STYLES: Record<LogLevel, { color: string; bg: string; icon: React.ReactNode }> = {
  DEBUG: { color: "text-slate-400", bg: "text-slate-400", icon: <Bug className="h-3 w-3" /> },
  INFO: { color: "text-blue-400", bg: "text-blue-400", icon: <Info className="h-3 w-3" /> },
  WARNING: { color: "text-yellow-400", bg: "text-yellow-400", icon: <AlertCircle className="h-3 w-3" /> },
  ERROR: { color: "text-red-400", bg: "text-red-400", icon: <XOctagon className="h-3 w-3" /> },
  CRITICAL: { color: "text-red-300 font-bold", bg: "text-red-300", icon: <Zap className="h-3 w-3" /> },
};

const LOG_LEVELS: LogLevel[] = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];

export default function LogViewer() {
  const [search, setSearch] = useState("");
  const [levelFilter, setLevelFilter] = useState<"all" | LogLevel>("all");
  const [serviceFilter, setServiceFilter] = useState("all");
  const [visibleCount, setVisibleCount] = useState(50);
  const containerRef = useRef<HTMLDivElement>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["system-logs"],
    queryFn: () => systemApi.metrics(),
    refetchInterval: 15000,
  });

  const logs: LogEntry[] = MOCK_LOGS;

  const services = useMemo(() => {
    const s = new Set(logs.map((l) => l.service));
    return ["all", ...Array.from(s)];
  }, []);

  const filtered = useMemo(() => logs.filter((log) => {
    const matchLevel = levelFilter === "all" || log.level === levelFilter;
    const matchService = serviceFilter === "all" || log.service === serviceFilter;
    const matchSearch = !search || log.message.toLowerCase().includes(search.toLowerCase()) || log.service.includes(search.toLowerCase()) || (log.trace_id || "").includes(search);
    return matchLevel && matchService && matchSearch;
  }), [levelFilter, serviceFilter, search]);

  const visibleLogs = filtered.slice(0, visibleCount);

  const levelCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    LOG_LEVELS.forEach((l) => { counts[l] = logs.filter((e) => e.level === l).length; });
    return counts;
  }, []);

  const handleExport = () => {
    const content = filtered.map((l) => `[${l.timestamp}] ${l.level.padEnd(8)} [${l.service}] ${l.message}`).join("\n");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aldeci-logs-${new Date().toISOString().slice(0, 10)}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${filtered.length} log entries`);
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Log Viewer"
        description="Application logs with structured search and severity filtering"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { refetch(); toast.info("Refreshing logs…"); }}>
              <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-3.5 w-3.5 mr-1.5" />
              Export
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <KpiCard title="Total Entries" value={logs.length} icon={FileText} trend="flat" />
        {LOG_LEVELS.slice(2).map((level) => (
          <KpiCard
            key={level}
            title={level}
            value={levelCounts[level]}
            icon={Filter}
            trend={level === "ERROR" || level === "CRITICAL" ? "down" : "flat"}
          />
        ))}
      </div>

      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search messages, services, trace IDs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-8 pl-8 text-sm font-mono"
          />
        </div>
        <Select value={levelFilter} onValueChange={(v) => setLevelFilter(v as any)}>
          <SelectTrigger className="h-8 w-36 text-xs">
            <SelectValue placeholder="All levels" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Levels</SelectItem>
            {LOG_LEVELS.map((l) => <SelectItem key={l} value={l}>{l}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={serviceFilter} onValueChange={setServiceFilter}>
          <SelectTrigger className="h-8 w-40 text-xs">
            <SelectValue placeholder="All services" />
          </SelectTrigger>
          <SelectContent>
            {services.map((s) => <SelectItem key={s} value={s}>{s === "all" ? "All Services" : s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Badge variant="secondary" className="h-8 flex items-center px-3 text-xs">
          {filtered.length} entries
        </Badge>
      </div>

      {/* Log Output */}
      <Card>
        <CardHeader className="pb-2 border-b border-border/30">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileText className="h-4 w-4 text-primary" />
              Application Logs
            </CardTitle>
            <div className="flex gap-1">
              {LOG_LEVELS.map((level) => {
                const style = LEVEL_STYLES[level];
                return (
                  <button
                    key={level}
                    onClick={() => setLevelFilter(levelFilter === level ? "all" : level)}
                    className={`flex items-center gap-1 rounded px-2 py-0.5 text-xs transition-colors ${levelFilter === level ? "bg-muted" : "hover:bg-muted/50"} ${style.color}`}
                  >
                    {style.icon}
                    {level}
                  </button>
                );
              })}
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div
            ref={containerRef}
            className="h-[520px] overflow-y-auto bg-[#0d1117] rounded-b-lg"
          >
            {visibleLogs.length === 0 ? (
              <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">No logs match the current filters</div>
            ) : (
              <div className="font-mono text-xs leading-5">
                {visibleLogs.map((log) => {
                  const style = LEVEL_STYLES[log.level];
                  return (
                    <div
                      key={log.id}
                      className={`flex gap-3 px-4 py-1 border-b border-white/[0.03] hover:bg-white/[0.03] transition-colors ${log.level === "CRITICAL" ? "bg-red-500/5" : log.level === "ERROR" ? "bg-red-500/3" : ""}`}
                    >
                      <span className="text-slate-600 shrink-0 select-none">{log.timestamp}</span>
                      <span className={`shrink-0 w-14 ${style.color} flex items-center gap-1`}>
                        {style.icon}
                        {log.level}
                      </span>
                      <span className="text-cyan-600 shrink-0 w-20 truncate">[{log.service}]</span>
                      <span className={`flex-1 ${log.level === "CRITICAL" ? "text-red-300 font-semibold" : log.level === "ERROR" ? "text-red-400" : log.level === "WARNING" ? "text-yellow-300" : "text-slate-300"}`}>
                        {log.message}
                      </span>
                      {log.trace_id && (
                        <span className="text-slate-600 shrink-0 hidden xl:block">{log.trace_id}</span>
                      )}
                    </div>
                  );
                })}
                {visibleCount < filtered.length && (
                  <div className="flex justify-center py-3">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs text-muted-foreground"
                      onClick={() => setVisibleCount((c) => Math.min(c + 50, filtered.length))}
                    >
                      <ChevronDown className="h-3.5 w-3.5 mr-1" />
                      Load 50 more ({filtered.length - visibleCount} remaining)
                    </Button>
                  </div>
                )}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
