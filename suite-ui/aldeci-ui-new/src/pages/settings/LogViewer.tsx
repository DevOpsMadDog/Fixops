import { useState, useCallback, useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Terminal, Search, RefreshCw, Download, AlertTriangle,
  Info, Bug, AlertCircle, ChevronRight, BarChart2, Clock
} from "lucide-react";
import { useAuditLog } from "@/hooks/use-api";

type LogLevel = "ALL" | "ERROR" | "WARN" | "INFO" | "DEBUG";

const LEVEL_COLORS: Record<string, { bg: string; text: string; badge: string }> = {
  ERROR: { bg: "bg-red-950/20", text: "text-red-400", badge: "bg-red-900/40 text-red-400 border-red-700" },
  WARN: { bg: "bg-yellow-950/20", text: "text-yellow-400", badge: "bg-yellow-900/40 text-yellow-400 border-yellow-700" },
  INFO: { bg: "", text: "text-blue-400", badge: "bg-blue-900/40 text-blue-400 border-blue-700" },
  DEBUG: { bg: "", text: "text-muted-foreground", badge: "bg-muted text-muted-foreground border-border" },
};

const LEVEL_ICONS: Record<string, React.ElementType> = {
  ERROR: AlertCircle,
  WARN: AlertTriangle,
  INFO: Info,
  DEBUG: Bug,
};

export default function LogViewer() {
  const auditQuery = useAuditLog();
  const refetch = useCallback(() => auditQuery.refetch(), [auditQuery]);

  const [level, setLevel] = useState<LogLevel>("ALL");
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [autoScroll]);

  if (auditQuery.isLoading) return <PageSkeleton />;
  if (auditQuery.isError) return <ErrorState message="Failed to load logs" onRetry={refetch} />;

  const rawLogs: any[] = auditQuery.data?.data ?? auditQuery.data ?? [];

  // Map audit logs to log viewer format
  const logs = rawLogs.map((l: any, i: number) => ({
    id: l.id ?? i,
    timestamp: l.timestamp ?? l.created_at ?? new Date().toISOString(),
    level: l.level ?? (l.status === "failed" ? "ERROR" : l.severity === "warning" ? "WARN" : "INFO"),
    source: l.source ?? l.service ?? "api",
    message: l.message ?? l.action ?? `${l.actor ?? "system"} performed ${l.action ?? "operation"} on ${l.resource ?? "resource"}`,
    details: l.details ?? l.metadata,
  }));

  const sources = Array.from(new Set(logs.map((l) => l.source).filter(Boolean)));

  const filtered = logs.filter((l) => {
    const matchesLevel = level === "ALL" || l.level === level;
    const matchesSearch = !search ||
      l.message.toLowerCase().includes(search.toLowerCase()) ||
      l.source.toLowerCase().includes(search.toLowerCase());
    const matchesSource = source === "all" || l.source === source;
    return matchesLevel && matchesSearch && matchesSource;
  });

  const errorCount = logs.filter((l) => l.level === "ERROR").length;
  const warnCount = logs.filter((l) => l.level === "WARN").length;
  const infoCount = logs.filter((l) => l.level === "INFO").length;
  const debugCount = logs.filter((l) => l.level === "DEBUG").length;

  const handleExport = () => {
    const content = filtered.map((l) =>
      `[${l.timestamp}] [${l.level}] [${l.source}] ${l.message}`
    ).join("\n");
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "application-logs.txt";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Log Viewer"
        description="Real-time application log stream with level filtering and search"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button variant="outline" size="sm" onClick={handleExport} className="gap-2">
          <Download className="h-4 w-4" />
          Export
        </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Errors" value={errorCount} icon={AlertCircle} />
        <KpiCard title="Warnings" value={warnCount} icon={AlertTriangle} />
        <KpiCard title="Info" value={infoCount} icon={Info} />
        <KpiCard title="Debug" value={debugCount} icon={Bug} />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        {/* Level filter buttons */}
        <div className="flex gap-1">
          {(["ALL", "ERROR", "WARN", "INFO", "DEBUG"] as LogLevel[]).map((lvl) => {
            const colors = LEVEL_COLORS[lvl] ?? LEVEL_COLORS.INFO;
            return (
              <Button
                key={lvl}
                size="sm"
                variant={level === lvl ? "default" : "outline"}
                className={`text-xs h-7 px-2.5 ${level === lvl ? "" : ""}`}
                onClick={() => setLevel(lvl)}
              >
                {lvl}
              </Button>
            );
          })}
        </div>
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search messages, sources…"
            className="pl-9 h-8"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={source} onValueChange={setSource}>
          <SelectTrigger className="w-36 h-8">
            <SelectValue placeholder="Source" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Sources</SelectItem>
            {sources.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="flex items-center gap-2">
          <Switch id="autoscroll" checked={autoScroll} onCheckedChange={setAutoScroll} />
          <Label htmlFor="autoscroll" className="text-xs cursor-pointer">Auto-scroll</Label>
        </div>
      </div>

      {/* Log level breakdown */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {([
          { level: "ERROR", count: errorCount, icon: AlertCircle, color: "text-red-400", bg: "bg-red-950/20 border-red-700/30" },
          { level: "WARN", count: warnCount, icon: AlertTriangle, color: "text-yellow-400", bg: "bg-yellow-950/20 border-yellow-700/30" },
          { level: "INFO", count: infoCount, icon: Info, color: "text-blue-400", bg: "bg-blue-950/20 border-blue-700/30" },
          { level: "DEBUG", count: debugCount, icon: Bug, color: "text-muted-foreground", bg: "bg-muted/20 border-border/30" },
        ]).map(({ level, count, icon: Icon, color, bg }) => (
          <Card
            key={level}
            className={`cursor-pointer border ${bg} ${
              level === (level as string) ? "ring-1 ring-primary/30" : ""
            }`}
            onClick={() => setLevel(level as LogLevel)}
          >
            <CardContent className="p-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon className={`h-4 w-4 ${color}`} />
                <span className={`text-xs font-bold ${color}`}>{level}</span>
              </div>
              <p className="text-2xl font-bold">{count}</p>
              <p className="text-xs text-muted-foreground mt-0.5">events</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Log terminal */}
      <Card>
        <CardHeader className="pb-3 border-b border-border/40">
          <CardTitle className="text-base flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" />
              Log Stream
            </span>
            <span className="text-xs font-normal text-muted-foreground">
              {filtered.length} entries shown
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div
            ref={scrollRef}
            className="h-[500px] overflow-y-auto font-mono text-xs bg-[#0a0f1a] rounded-b-lg"
          >
            {filtered.length === 0 ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                No log entries match your filters
              </div>
            ) : (
              filtered.slice(0, 500).map((log) => {
                const lvlColors = LEVEL_COLORS[log.level] ?? LEVEL_COLORS.INFO;
                const Icon = LEVEL_ICONS[log.level] ?? ChevronRight;
                return (
                  <div
                    key={log.id}
                    className={`flex items-start gap-2 px-4 py-1.5 hover:bg-white/5 transition-colors ${lvlColors.bg}`}
                  >
                    <Icon className={`h-3 w-3 mt-0.5 shrink-0 ${lvlColors.text}`} />
                    <span className="text-muted-foreground/60 shrink-0 tabular-nums">
                      {(log.timestamp ?? "").slice(0, 19).replace("T", " ")}
                    </span>
                    <span className={`shrink-0 font-bold w-12 ${lvlColors.text}`}>
                      {log.level}
                    </span>
                    <span className="text-violet-400/70 shrink-0 w-20 truncate">{log.source}</span>
                    <span className="text-muted-foreground flex-1 break-all">{log.message}</span>
                  </div>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>

      {/* Log source breakdown */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart2 className="h-4 w-4 text-primary" />
            Log Sources
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {sources.length === 0 ? (
            <p className="text-sm text-muted-foreground">No sources found in current log set</p>
          ) : (
            sources.slice(0, 10).map((src) => {
              const count = logs.filter((l) => l.source === src).length;
              const errorCnt = logs.filter((l) => l.source === src && l.level === "ERROR").length;
              const pct = logs.length > 0 ? Math.round((count / logs.length) * 100) : 0;
              return (
                <div key={src} className="flex items-center gap-3">
                  <span className="text-xs text-muted-foreground font-mono w-28 shrink-0 truncate">{src}</span>
                  <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full bg-primary/60 rounded-full transition-all"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs font-medium w-10 text-right">{count}</span>
                  {errorCnt > 0 && (
                    <span className="text-xs text-red-400 w-16 text-right">{errorCnt} errors</span>
                  )}
                </div>
              );
            })
          )}
        </CardContent>
      </Card>

      {/* Log timeline summary */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Clock className="h-4 w-4 text-primary" />
            Log Stats
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Total Logs", value: logs.length },
              { label: "Filtered", value: filtered.length },
              { label: "Sources", value: sources.length },
              { label: "Error Rate", value: logs.length > 0 ? `${Math.round((errorCount / logs.length) * 100)}%` : "0%" },
            ].map(({ label, value }) => (
              <div key={label} className="text-center p-3 rounded-lg bg-muted/30 border border-border/40">
                <p className="text-xl font-bold">{value}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
