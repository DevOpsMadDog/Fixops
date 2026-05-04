/**
 * Integration Health — /integrations
 *
 * Operational status board for all platform connectors and integrations.
 * Designed for platform engineers and SOC leads who need instant visibility
 * into feed health, connector latency, and outage impact.
 *
 * Aesthetic: terminal-industrial — monospaced readouts, pulse animations
 * on live checks, amber/red/green signal system against a deep slate canvas.
 */

import { useState, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Clock,
  Wifi,
  WifiOff,
  Zap,
  Shield,
  Cloud,
  Database,
  GitBranch,
  Package,
  Ticket,
  Rss,
  Server,
  Lock,
  ChevronDown,
  ChevronRight,
  TrendingUp,
  TrendingDown,
  Minus,
  Bell,
  BellOff,
  Terminal,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type IntegrationStatus = "HEALTHY" | "DEGRADED" | "DOWN";
type IntegrationType =
  | "scanner"
  | "ticketing"
  | "cloud"
  | "feed"
  | "siem"
  | "secrets"
  | "registry"
  | "git"
  | "notification";

interface HealthCheckEntry {
  timestamp: Date;
  status: IntegrationStatus;
  responseMs: number;
  message?: string;
}

interface Integration {
  id: string;
  name: string;
  type: IntegrationType;
  status: IntegrationStatus;
  responseMs: number;
  uptimePct: number;
  lastChecked: Date;
  endpoint: string;
  version?: string;
  history: HealthCheckEntry[];
  alerts?: string[];
}

interface AlertEntry {
  id: string;
  integrationId: string;
  integrationName: string;
  status: IntegrationStatus;
  message: string;
  since: Date;
  acknowledged: boolean;
}

// ═══════════════════════════════════════════════════════════
// API config
// ═══════════════════════════════════════════════════════════

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

const TYPE_META: Record<IntegrationType, { icon: React.ElementType; label: string }> = {
  scanner:      { icon: Shield,    label: "Scanner" },
  ticketing:    { icon: Ticket,    label: "Ticketing" },
  cloud:        { icon: Cloud,     label: "Cloud" },
  feed:         { icon: Rss,       label: "Feed" },
  siem:         { icon: Database,  label: "SIEM" },
  secrets:      { icon: Lock,      label: "Secrets" },
  registry:     { icon: Package,   label: "Registry" },
  git:          { icon: GitBranch, label: "Git" },
  notification: { icon: Bell,      label: "Notify" },
};

const STATUS_CONFIG: Record<IntegrationStatus, {
  label: string;
  dot: string;
  text: string;
  bg: string;
  border: string;
  icon: React.ElementType;
}> = {
  HEALTHY:  {
    label: "HEALTHY",
    dot:    "bg-emerald-400",
    text:   "text-emerald-400",
    bg:     "bg-emerald-500/10",
    border: "border-emerald-500/20",
    icon:   CheckCircle2,
  },
  DEGRADED: {
    label: "DEGRADED",
    dot:    "bg-amber-400",
    text:   "text-amber-400",
    bg:     "bg-amber-500/10",
    border: "border-amber-500/25",
    icon:   AlertTriangle,
  },
  DOWN: {
    label: "DOWN",
    dot:    "bg-red-500",
    text:   "text-red-400",
    bg:     "bg-red-500/10",
    border: "border-red-500/25",
    icon:   XCircle,
  },
};

function formatRelative(date: Date): string {
  const diffMs = Date.now() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) return `${diffH}h ago`;
  return `${Math.floor(diffH / 24)}d ago`;
}

function formatMs(ms: number): string {
  if (ms === 0) return "—";
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)}s`;
  return `${ms}ms`;
}

// ═══════════════════════════════════════════════════════════
// History Sparkbar
// ═══════════════════════════════════════════════════════════

function HistorySparkbar({ history }: { history: HealthCheckEntry[] }) {
  return (
    <div className="flex items-end gap-[2px] h-6">
      {history.map((entry, i) => {
        const cfg = STATUS_CONFIG[entry.status];
        return (
          <TooltipProvider key={i} delayDuration={100}>
            <Tooltip>
              <TooltipTrigger asChild>
                <div
                  className={cn(
                    "w-2 rounded-sm cursor-default transition-opacity hover:opacity-80",
                    cfg.dot,
                    entry.status === "HEALTHY" ? "h-3" : entry.status === "DEGRADED" ? "h-5" : "h-6"
                  )}
                />
              </TooltipTrigger>
              <TooltipContent side="top" className="text-xs font-mono">
                <div>{entry.status} — {formatMs(entry.responseMs)}</div>
                <div className="text-muted-foreground">{formatRelative(entry.timestamp)}</div>
                {entry.message && <div className="text-amber-400">{entry.message}</div>}
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        );
      })}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Pulsing status dot
// ═══════════════════════════════════════════════════════════

function StatusDot({ status }: { status: IntegrationStatus }) {
  const cfg = STATUS_CONFIG[status];
  return (
    <span className="relative flex h-2.5 w-2.5 shrink-0">
      {status !== "DOWN" && (
        <span className={cn("animate-ping absolute inline-flex h-full w-full rounded-full opacity-50", cfg.dot)} />
      )}
      <span className={cn("relative inline-flex rounded-full h-2.5 w-2.5", cfg.dot)} />
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// Integration Card
// ═══════════════════════════════════════════════════════════

interface IntegrationCardProps {
  integration: Integration;
  onCheck: (id: string) => void;
  checking: boolean;
}

function IntegrationCard({ integration: ig, onCheck, checking }: IntegrationCardProps) {
  const [expanded, setExpanded] = useState(false);
  const cfg = STATUS_CONFIG[ig.status];
  const TypeMeta = TYPE_META[ig.type];
  const TypeIcon = TypeMeta.icon;
  const StatusIcon = cfg.icon;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
    >
      <Card
        className={cn(
          "border transition-colors duration-200",
          ig.status === "DOWN"
            ? "border-red-500/30 bg-red-950/10"
            : ig.status === "DEGRADED"
              ? "border-amber-500/25 bg-amber-950/10"
              : "border-border"
        )}
      >
        <CardContent className="p-4 space-y-3">
          {/* Header row */}
          <div className="flex items-start gap-3">
            {/* Type icon */}
            <div className={cn("rounded-md p-2 shrink-0 mt-0.5", cfg.bg)}>
              <TypeIcon className={cn("h-4 w-4", cfg.text)} />
            </div>

            {/* Name + endpoint */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-semibold text-sm tracking-tight truncate">{ig.name}</span>
                <span className={cn(
                  "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-bold tracking-widest uppercase border",
                  cfg.bg, cfg.text, cfg.border
                )}>
                  <StatusDot status={ig.status} />
                  {cfg.label}
                </span>
                <span className="rounded-sm bg-muted/60 px-1.5 py-0.5 text-[10px] text-muted-foreground font-mono">
                  {TypeMeta.label}
                </span>
              </div>
              <div className="flex items-center gap-1 mt-0.5">
                <Terminal className="h-3 w-3 text-muted-foreground shrink-0" />
                <span className="text-[11px] font-mono text-muted-foreground truncate">{ig.endpoint}</span>
                {ig.version && (
                  <span className="text-[10px] text-muted-foreground/60 shrink-0">v{ig.version}</span>
                )}
              </div>
            </div>

            {/* Actions */}
            <TooltipProvider delayDuration={200}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 shrink-0"
                    onClick={() => onCheck(ig.id)}
                    disabled={checking}
                  >
                    <RefreshCw className={cn("h-3.5 w-3.5", checking && "animate-spin")} />
                  </Button>
                </TooltipTrigger>
                <TooltipContent side="left" className="text-xs">Run health check</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </div>

          {/* Metrics row */}
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-0.5">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Response</p>
              <p className={cn(
                "text-sm font-bold font-mono tabular-nums",
                ig.status === "DOWN" ? "text-red-400"
                  : ig.status === "DEGRADED" ? "text-amber-400"
                    : "text-foreground"
              )}>
                {formatMs(ig.responseMs)}
              </p>
            </div>
            <div className="space-y-0.5">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Uptime</p>
              <p className={cn(
                "text-sm font-bold font-mono tabular-nums",
                ig.uptimePct >= 99 ? "text-emerald-400"
                  : ig.uptimePct >= 95 ? "text-amber-400"
                    : "text-red-400"
              )}>
                {ig.uptimePct.toFixed(2)}%
              </p>
            </div>
            <div className="space-y-0.5">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Checked</p>
              <p className="text-sm font-mono text-muted-foreground tabular-nums">
                {formatRelative(ig.lastChecked)}
              </p>
            </div>
          </div>

          {/* Sparkbar + expand */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <p className="text-[10px] uppercase tracking-wider text-muted-foreground">Last 60 min</p>
              <button
                onClick={() => setExpanded((v) => !v)}
                className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
              >
                {expanded ? "Hide" : "Details"}
                {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              </button>
            </div>
            <HistorySparkbar history={ig.history} />
          </div>

          {/* Alerts inline */}
          {ig.alerts && ig.alerts.length > 0 && (
            <div className="space-y-1">
              {ig.alerts.map((alert, i) => (
                <div key={i} className={cn(
                  "flex items-start gap-2 rounded-md px-2.5 py-1.5 text-xs",
                  ig.status === "DOWN" ? "bg-red-500/10 text-red-300" : "bg-amber-500/10 text-amber-300"
                )}>
                  <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                  <span>{alert}</span>
                </div>
              ))}
            </div>
          )}

          {/* Expanded history timeline */}
          <AnimatePresence>
            {expanded && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.2 }}
                className="overflow-hidden"
              >
                <div className="border-t border-border pt-3 space-y-1.5">
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">Check history</p>
                  {[...ig.history].reverse().slice(0, 8).map((entry, i) => {
                    const ecfg = STATUS_CONFIG[entry.status];
                    return (
                      <div key={i} className="flex items-center gap-3 text-xs font-mono">
                        <StatusDot status={entry.status} />
                        <span className={cn("w-20 shrink-0", ecfg.text)}>{ecfg.label}</span>
                        <span className="text-muted-foreground w-14 shrink-0 tabular-nums">{formatMs(entry.responseMs)}</span>
                        <span className="text-muted-foreground/60">{formatRelative(entry.timestamp)}</span>
                        {entry.message && (
                          <span className="text-amber-400/80 truncate">{entry.message}</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Alerts Panel
// ═══════════════════════════════════════════════════════════

function AlertsPanel({ alerts, onAcknowledge }: {
  alerts: AlertEntry[];
  onAcknowledge: (id: string) => void;
}) {
  const active = alerts.filter((a) => !a.acknowledged);
  const acked = alerts.filter((a) => a.acknowledged);

  return (
    <Card className="border-border">
      <CardHeader className="pb-3 pt-4 px-4">
        <CardTitle className="text-sm font-semibold flex items-center gap-2">
          <Bell className="h-4 w-4 text-amber-400" />
          Active Alerts
          {active.length > 0 && (
            <span className="ml-auto rounded-full bg-red-500/20 px-2 py-0.5 text-[11px] font-bold text-red-400">
              {active.length}
            </span>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-4 space-y-2">
        {alerts.length === 0 && (
          <div className="flex flex-col items-center gap-2 py-6 text-muted-foreground">
            <CheckCircle2 className="h-8 w-8 text-emerald-500/50" />
            <p className="text-xs">All integrations nominal</p>
          </div>
        )}

        {active.map((alert) => {
          const cfg = STATUS_CONFIG[alert.status];
          return (
            <motion.div
              key={alert.id}
              layout
              initial={{ opacity: 0, x: 8 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -8 }}
              className={cn(
                "rounded-lg border p-3 space-y-1.5",
                alert.status === "DOWN" ? "border-red-500/25 bg-red-950/15" : "border-amber-500/20 bg-amber-950/10"
              )}
            >
              <div className="flex items-center gap-2">
                <StatusDot status={alert.status} />
                <span className={cn("text-xs font-bold", cfg.text)}>{alert.status}</span>
                <span className="text-xs font-medium text-foreground">{alert.integrationName}</span>
                <span className="ml-auto text-[10px] font-mono text-muted-foreground">
                  {formatRelative(alert.since)}
                </span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">{alert.message}</p>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 text-[10px] px-2 text-muted-foreground hover:text-foreground"
                onClick={() => onAcknowledge(alert.id)}
              >
                <BellOff className="h-3 w-3 mr-1" />
                Acknowledge
              </Button>
            </motion.div>
          );
        })}

        {acked.length > 0 && (
          <details className="mt-2">
            <summary className="text-[10px] uppercase tracking-wider text-muted-foreground cursor-pointer hover:text-foreground transition-colors">
              {acked.length} acknowledged
            </summary>
            <div className="mt-2 space-y-1.5 opacity-50">
              {acked.map((alert) => (
                <div key={alert.id} className="flex items-center gap-2 text-xs text-muted-foreground">
                  <BellOff className="h-3 w-3 shrink-0" />
                  <span className="font-medium">{alert.integrationName}</span>
                  <span className="truncate">{alert.message.slice(0, 60)}…</span>
                </div>
              ))}
            </div>
          </details>
        )}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Filter bar types
// ═══════════════════════════════════════════════════════════

type FilterStatus = "ALL" | IntegrationStatus;
type FilterType = "ALL" | IntegrationType;

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function IntegrationHealth() {
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [alerts, setAlerts] = useState<AlertEntry[]>([]);
  const [checkingIds, setCheckingIds] = useState<Set<string>>(new Set());
  const [checkingAll, setCheckingAll] = useState(false);
  const [filterStatus, setFilterStatus] = useState<FilterStatus>("ALL");
  const [filterType, setFilterType] = useState<FilterType>("ALL");
  const [lastRefresh, setLastRefresh] = useState(new Date());

  useEffect(() => {
    const headers = { "X-API-Key": API_KEY };
    Promise.allSettled([
      fetch(`${API_BASE}/api/v1/integration-health/integrations?org_id=${ORG_ID}`, { headers })
        .then(r => r.ok ? r.json() : Promise.reject()),
      fetch(`${API_BASE}/api/v1/integration-health/alerts?org_id=${ORG_ID}`, { headers })
        .then(r => r.ok ? r.json() : Promise.reject()),
    ]).then(([intRes, alertRes]) => {
      if (intRes.status === "fulfilled") {
        const d = intRes.value;
        setIntegrations(Array.isArray(d) ? d : (d?.integrations ?? d?.items ?? []));
      }
      if (alertRes.status === "fulfilled") {
        const d = alertRes.value;
        setAlerts(Array.isArray(d) ? d : (d?.alerts ?? d?.items ?? []));
      }
      setLastRefresh(new Date());
    });
  }, []);

  // KPI derivations
  const total = integrations.length;
  const healthy = integrations.filter((i) => i.status === "HEALTHY").length;
  const degraded = integrations.filter((i) => i.status === "DEGRADED").length;
  const down = integrations.filter((i) => i.status === "DOWN").length;
  const avgUptime = total > 0
    ? (integrations.reduce((s, i) => s + i.uptimePct, 0) / total).toFixed(2)
    : "0.00";
  const withResponse = integrations.filter((i) => i.responseMs > 0);
  const avgResponse = withResponse.length > 0
    ? Math.round(withResponse.reduce((s, i) => s + i.responseMs, 0) / withResponse.length)
    : 0;

  // Filtered list
  const filtered = integrations.filter((ig) => {
    if (filterStatus !== "ALL" && ig.status !== filterStatus) return false;
    if (filterType !== "ALL" && ig.type !== filterType) return false;
    return true;
  });

  // Sort: DOWN first, then DEGRADED, then HEALTHY; within group by name
  const sorted = [...filtered].sort((a, b) => {
    const order = { DOWN: 0, DEGRADED: 1, HEALTHY: 2 };
    if (order[a.status] !== order[b.status]) return order[a.status] - order[b.status];
    return a.name.localeCompare(b.name);
  });

  const runCheck = useCallback((id: string) => {
    setCheckingIds((prev) => new Set([...prev, id]));
    // Simulate 800–1500ms check
    const delay = 800 + Math.random() * 700;
    setTimeout(() => {
      setIntegrations((prev) =>
        prev.map((ig) => {
          if (ig.id !== id) return ig;
          const newEntry: HealthCheckEntry = {
            timestamp: new Date(),
            status: ig.status,
            responseMs: ig.status === "HEALTHY"
              ? ig.responseMs + Math.floor(Math.random() * 40) - 20
              : ig.status === "DEGRADED"
                ? ig.responseMs + Math.floor(Math.random() * 200) - 100
                : 0,
          };
          return {
            ...ig,
            lastChecked: new Date(),
            history: [...ig.history.slice(-11), newEntry],
          };
        })
      );
      setCheckingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }, delay);
  }, []);

  const runAllChecks = useCallback(() => {
    setCheckingAll(true);
    const ids = integrations.map((i) => i.id);
    setCheckingIds(new Set(ids));
    setTimeout(() => {
      setIntegrations((prev) =>
        prev.map((ig) => ({
          ...ig,
          lastChecked: new Date(),
          history: [
            ...ig.history.slice(-11),
            {
              timestamp: new Date(),
              status: ig.status,
              responseMs: ig.status === "HEALTHY"
                ? ig.responseMs + Math.floor(Math.random() * 30) - 15
                : ig.responseMs,
            },
          ],
        }))
      );
      setCheckingIds(new Set());
      setCheckingAll(false);
      setLastRefresh(new Date());
    }, 1800);
  }, [integrations]);

  const acknowledgeAlert = useCallback((id: string) => {
    setAlerts((prev) => prev.map((a) => a.id === id ? { ...a, acknowledged: true } : a));
  }, []);

  const unackedAlerts = alerts.filter((a) => !a.acknowledged).length;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <PageHeader
        title="Integration Health"
        description="Real-time status for all platform connectors, feeds, and external services."
        badge="OPS"
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground font-mono hidden sm:block">
              Last refresh: {formatRelative(lastRefresh)}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={runAllChecks}
              disabled={checkingAll}
              className="gap-1.5"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", checkingAll && "animate-spin")} />
              {checkingAll ? "Checking…" : "Check All"}
            </Button>
          </div>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <KpiCard
          title="Total"
          value={total}
          icon={Layers}
          description="Configured integrations"
        />
        <KpiCard
          title="Healthy"
          value={healthy}
          icon={CheckCircle2}
          trendLabel={`${((healthy / total) * 100).toFixed(0)}% operational`}
          trend="up"
          className="border-emerald-500/20"
        />
        <KpiCard
          title="Degraded"
          value={degraded}
          icon={AlertTriangle}
          trendLabel={degraded > 0 ? "Needs attention" : "None"}
          trend={degraded > 0 ? "down" : "flat"}
          className={degraded > 0 ? "border-amber-500/25" : ""}
        />
        <KpiCard
          title="Down"
          value={down}
          icon={XCircle}
          trendLabel={down > 0 ? "Action required" : "None"}
          trend={down > 0 ? "down" : "flat"}
          className={down > 0 ? "border-red-500/30" : ""}
        />
        <KpiCard
          title="Avg Uptime"
          value={`${avgUptime}%`}
          icon={TrendingUp}
          trendLabel="30-day rolling"
          trend="flat"
        />
        <KpiCard
          title="Avg Response"
          value={formatMs(avgResponse)}
          icon={Zap}
          description="Across healthy services"
        />
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1 rounded-lg border border-border bg-muted/30 p-1">
          {(["ALL", "HEALTHY", "DEGRADED", "DOWN"] as FilterStatus[]).map((s) => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={cn(
                "rounded-md px-3 py-1 text-xs font-medium transition-colors",
                filterStatus === s
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {s === "ALL" ? "All" : s}
              {s !== "ALL" && (
                <span className={cn(
                  "ml-1.5 text-[10px]",
                  s === "HEALTHY" ? "text-emerald-400"
                    : s === "DEGRADED" ? "text-amber-400"
                      : "text-red-400"
                )}>
                  {s === "HEALTHY" ? healthy : s === "DEGRADED" ? degraded : down}
                </span>
              )}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1 rounded-lg border border-border bg-muted/30 p-1 flex-wrap">
          {(["ALL", ...Object.keys(TYPE_META)] as ("ALL" | IntegrationType)[]).map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={cn(
                "rounded-md px-2.5 py-1 text-xs font-medium transition-colors capitalize",
                filterType === t
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t === "ALL" ? "All types" : TYPE_META[t as IntegrationType].label}
            </button>
          ))}
        </div>

        <span className="ml-auto text-xs text-muted-foreground">
          {sorted.length} of {total}
        </span>
      </div>

      {/* Main content: grid + alerts panel */}
      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-6 items-start">
        {/* Integration cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <AnimatePresence mode="popLayout">
            {sorted.map((ig) => (
              <IntegrationCard
                key={ig.id}
                integration={ig}
                onCheck={runCheck}
                checking={checkingIds.has(ig.id)}
              />
            ))}
          </AnimatePresence>
          {sorted.length === 0 && (
            <div className="col-span-2 flex flex-col items-center gap-3 py-16 text-muted-foreground">
              <WifiOff className="h-10 w-10 opacity-30" />
              <p className="text-sm">No integrations match the current filters</p>
            </div>
          )}
        </div>

        {/* Right panel: alerts */}
        <div className="space-y-4 xl:sticky xl:top-4">
          <AlertsPanel alerts={alerts} onAcknowledge={acknowledgeAlert} />

          {/* Overall health summary */}
          <Card className="border-border">
            <CardHeader className="pb-2 pt-4 px-4">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary" />
                Platform Status
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-3">
              {(["scanner", "cloud", "feed", "siem", "ticketing", "secrets", "registry", "git", "notification"] as IntegrationType[]).map((type) => {
                const group = integrations.filter((i) => i.type === type);
                if (group.length === 0) return null;
                const groupDown = group.filter((i) => i.status === "DOWN").length;
                const groupDegraded = group.filter((i) => i.status === "DEGRADED").length;
                const overallStatus: IntegrationStatus =
                  groupDown > 0 ? "DOWN" : groupDegraded > 0 ? "DEGRADED" : "HEALTHY";
                const cfg = STATUS_CONFIG[overallStatus];
                const TypeMeta = TYPE_META[type];
                const TypeIcon = TypeMeta.icon;
                return (
                  <div key={type} className="flex items-center gap-2.5">
                    <TypeIcon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span className="text-xs text-muted-foreground flex-1 capitalize">{TypeMeta.label}</span>
                    <span className="text-xs font-mono text-muted-foreground/60">{group.length}</span>
                    <span className={cn("text-[10px] font-bold tracking-wider", cfg.text)}>
                      {cfg.label}
                    </span>
                    <StatusDot status={overallStatus} />
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
