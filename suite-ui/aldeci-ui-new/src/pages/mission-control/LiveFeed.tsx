import { useState, useCallback, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity, AlertTriangle, Zap, Shield, GitBranch, FileText,
  Circle, RefreshCw, Filter, Clock, Wifi, WifiOff, ChevronDown,
  Eye, Bell, CheckCircle2, XCircle, Radio, Search, BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useNervePulse,
  useNerveState,
} from "@/hooks/use-api";
import { streamApi } from "@/lib/api";
import { cn } from "@/lib/utils";

type EventType = "all" | "finding" | "decision" | "mpte" | "deployment" | "policy" | "fix";
type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

const EVENT_TYPE_CONFIG: Record<string, {
  label: string;
  icon: React.ElementType;
  className: string;
  dotColor: string;
}> = {
  finding: {
    label: "Finding",
    icon: AlertTriangle,
    className: "border-red-500/30 text-red-400 bg-red-500/10",
    dotColor: "#ef4444",
  },
  decision: {
    label: "Decision",
    icon: FileText,
    className: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    dotColor: "#a855f7",
  },
  mpte: {
    label: "MPTE",
    icon: Zap,
    className: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    dotColor: "#06b6d4",
  },
  deployment: {
    label: "Deployment",
    icon: GitBranch,
    className: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    dotColor: "#3b82f6",
  },
  policy: {
    label: "Policy",
    icon: Shield,
    className: "border-gray-500/30 text-gray-400 bg-gray-500/10",
    dotColor: "#6b7280",
  },
  fix: {
    label: "Fix",
    icon: CheckCircle2,
    className: "border-green-500/30 text-green-400 bg-green-500/10",
    dotColor: "#22c55e",
  },
  alert: {
    label: "Alert",
    icon: Bell,
    className: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    dotColor: "#eab308",
  },
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

function EventTypeBadge({ type }: { type: string }) {
  const cfg = EVENT_TYPE_CONFIG[type?.toLowerCase()] ?? {
    label: type || "Event",
    icon: Activity,
    className: "border-border text-muted-foreground bg-muted/10",
    dotColor: "#6b7280",
  };
  const Icon = cfg.icon;
  return (
    <Badge className={cn("text-[10px] border px-1.5 py-0 h-4 font-medium flex items-center gap-1", cfg.className)}>
      <Icon className="h-2.5 w-2.5" />
      {cfg.label}
    </Badge>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity?.toLowerCase()] ?? "#6b7280";
  return (
    <span
      className="h-2 w-2 rounded-full inline-block shrink-0 mt-1"
      style={{ backgroundColor: color }}
    />
  );
}

function ConnectionStatus({ connected, lastUpdate }: { connected: boolean; lastUpdate: Date }) {
  return (
    <div className={cn(
      "flex items-center gap-1.5 text-xs px-2 py-1 rounded-full border",
      connected
        ? "border-green-500/30 bg-green-500/10 text-green-400"
        : "border-red-500/30 bg-red-500/10 text-red-400"
    )}>
      {connected
        ? <Wifi className="h-3 w-3 animate-pulse" />
        : <WifiOff className="h-3 w-3" />
      }
      <span className="hidden sm:block">{connected ? "Live" : "Disconnected"}</span>
      <Separator orientation="vertical" className="h-3 mx-0.5" />
      <span className="text-[10px] opacity-70">{lastUpdate.toLocaleTimeString()}</span>
    </div>
  );
}

interface FeedEvent {
  id?: string;
  type: string;
  severity?: string;
  message?: string;
  description?: string;
  component?: string;
  timestamp?: string;
  created_at?: string;
  [key: string]: unknown;
}

export default function LiveFeed() {
  const [eventType, setEventType] = useState<EventType>("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const [paused, setPaused] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [streamConnected, setStreamConnected] = useState(false);
  const [wsConnected, setWsConnected] = useState(false);
  const [streamEvents, setStreamEvents] = useState<FeedEvent[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const wsReconnectAttemptRef = useRef(0);

  const pulse = useNervePulse();
  const state = useNerveState();

  const isLoading = pulse.isLoading;
  const isError = pulse.isError;
  const refetch = useCallback(() => {
    pulse.refetch();
    state.refetch();
    setLastUpdate(new Date());
  }, [pulse, state]);

  // Auto-refresh every 30 seconds when not paused
  useEffect(() => {
    if (paused) return;
    const interval = setInterval(refetch, 30_000);
    return () => clearInterval(interval);
  }, [paused, refetch]);

  // FEATURE-3 — TrustGraph WebSocket live event feed at /ws/events.
  // Subscribes alongside the SSE stream so we receive both the legacy nerve-pulse
  // events (SSE) and the canonical TrustGraphEventBus events (WebSocket).
  useEffect(() => {
    if (paused) {
      wsRef.current?.close();
      wsRef.current = null;
      setWsConnected(false);
      wsReconnectAttemptRef.current = 0;
      return;
    }

    let cancelled = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    // Map TrustGraph event_type ("finding.created", "asset.discovered", etc.)
    // to the LiveFeed `type` taxonomy already used for badges/colors.
    const TG_TYPE_MAP: Record<string, string> = {
      "finding.created": "finding",
      "finding.updated": "finding",
      "asset.discovered": "deployment",
      "asset.updated": "deployment",
      "incident.created": "alert",
      "control.assessed": "policy",
      "policy.updated": "policy",
      "vendor.updated": "policy",
      "actor.identified": "alert",
      "scan.completed": "fix",
      "cve.discovered": "finding",
      "threat.detected": "alert",
      "risk.assessed": "decision",
      "evidence.collected": "decision",
      "playbook.executed": "fix",
      "alert.created": "alert",
    };

    const connect = () => {
      if (cancelled) return;
      try {
        const url = streamApi.trustGraphWsUrl();
        const ws = new WebSocket(url);
        wsRef.current = ws;

        ws.onopen = () => {
          if (cancelled) return;
          setWsConnected(true);
          wsReconnectAttemptRef.current = 0;
          setLastUpdate(new Date());
        };

        ws.onmessage = (msg: MessageEvent<string>) => {
          if (cancelled) return;
          try {
            const frame = JSON.parse(msg.data);
            if (!frame || typeof frame !== "object") return;
            // Server sends three frame kinds: connected, ping, event
            if (frame.type === "ping" || frame.type === "connected") {
              setWsConnected(true);
              setLastUpdate(new Date());
              return;
            }
            if (frame.type !== "event") return;

            const tgType = String(frame.event_type ?? "");
            const payload = (frame.payload ?? {}) as Record<string, unknown>;
            const mappedType = TG_TYPE_MAP[tgType] ?? "alert";

            const fe: FeedEvent = {
              id: String(payload.id ?? payload.finding_id ?? payload.asset_id ?? payload.event_id ?? `${tgType}-${frame.timestamp ?? Date.now()}`),
              type: mappedType,
              severity: typeof payload.severity === "string" ? payload.severity : "info",
              message: typeof payload.title === "string"
                ? payload.title
                : typeof payload.message === "string"
                  ? payload.message
                  : tgType.replace(".", " "),
              component: typeof payload.engine === "string"
                ? payload.engine
                : typeof payload.source === "string" ? payload.source : tgType,
              timestamp: typeof frame.timestamp === "string" ? frame.timestamp : new Date().toISOString(),
              event_type: tgType,
            };

            setStreamEvents((prev) => {
              // FIFO cap at 50 (founder spec) — newest at end.
              const next = [...prev, fe];
              return next.slice(-50);
            });
            setLastUpdate(new Date());
          } catch {
            // Drop malformed frames silently
          }
        };

        ws.onerror = () => {
          if (cancelled) return;
          setWsConnected(false);
        };

        ws.onclose = () => {
          if (cancelled) return;
          setWsConnected(false);
          wsRef.current = null;
          // Exponential backoff: 1s → 2s → 4s → 8s → 16s → 30s cap
          const attempt = wsReconnectAttemptRef.current;
          const delay = Math.min(30000, 1000 * Math.pow(2, attempt));
          wsReconnectAttemptRef.current = attempt + 1;
          reconnectTimer = setTimeout(connect, delay);
        };
      } catch {
        // Construction failed (bad URL etc.) — back off and retry
        const attempt = wsReconnectAttemptRef.current;
        const delay = Math.min(30000, 1000 * Math.pow(2, attempt));
        wsReconnectAttemptRef.current = attempt + 1;
        reconnectTimer = setTimeout(connect, delay);
      }
    };

    connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      wsRef.current?.close();
      wsRef.current = null;
      setWsConnected(false);
    };
  }, [paused]);

  useEffect(() => {
    if (paused) {
      eventSourceRef.current?.close();
      eventSourceRef.current = null;
      setStreamConnected(false);
      return;
    }

    const types = eventType === "all" ? undefined : eventType;
    const source = new EventSource(streamApi.eventsUrl(types));
    eventSourceRef.current = source;

    source.addEventListener("event", (event) => {
      try {
        const parsed = JSON.parse(event.data) as FeedEvent;
        setStreamEvents((prev) => {
          const next = [...prev, parsed];
          return next.slice(-250);
        });
        setStreamConnected(true);
        setLastUpdate(new Date());
      } catch {
        // Ignore malformed events and preserve polling fallback.
      }
    });

    source.addEventListener("heartbeat", () => {
      setStreamConnected(true);
      setLastUpdate(new Date());
    });

    source.onerror = () => {
      setStreamConnected(false);
    };

    return () => {
      source.close();
      if (eventSourceRef.current === source) {
        eventSourceRef.current = null;
      }
    };
  }, [eventType, paused]);

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [pulse.data, autoScroll]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to connect to live feed" onRetry={refetch} />;

  const pulseData = pulse.data ?? {};
  const stateData = state.data ?? {};

  const baselineEvents: FeedEvent[] = pulseData.events ?? pulseData.recent_events ?? stateData.events ?? [];
  const mergedEvents = [...baselineEvents, ...streamEvents];
  const dedupedEvents = Array.from(
    new Map(
      mergedEvents.map((event, index) => [
        String(event.id ?? `${event.type}-${event.timestamp ?? event.created_at ?? ""}-${event.message ?? event.description ?? ""}-${index}`),
        event,
      ])
    ).values()
  );
  const allEvents: FeedEvent[] = dedupedEvents;

  // Event type counts
  const findingCount = allEvents.filter((e) => e.type === "finding").length;
  const decisionCount = allEvents.filter((e) => e.type === "decision").length;
  const mpteCount = allEvents.filter((e) => e.type === "mpte").length;
  const deployCount = allEvents.filter((e) => e.type === "deployment").length;
  const totalCount = allEvents.length;
  const criticalCount = allEvents.filter((e) => e.severity === "critical").length;

  // Apply filters
  const filteredEvents = allEvents.filter((ev) => {
    const typeMatch = eventType === "all" || ev.type?.toLowerCase() === eventType;
    const sevMatch = severityFilter === "all" || ev.severity?.toLowerCase() === severityFilter;
    const searchMatch = !searchQuery || (
      String(ev.message ?? ev.description ?? "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      String(ev.component ?? "").toLowerCase().includes(searchQuery.toLowerCase()) ||
      String(ev.type ?? "").toLowerCase().includes(searchQuery.toLowerCase())
    );
    return typeMatch && sevMatch && searchMatch;
  });

  // Reverse for newest-first display
  const displayEvents = [...filteredEvents].reverse();

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { staggerChildren: 0.04 } },
  };
  const itemVariants = {
    hidden: { opacity: 0, y: 8 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.25 } },
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Live Feed"
        description="Real-time event stream: findings, decisions, MPTE verifications, and deployments"
        badge="LIVE"
        actions={
          <div className="flex items-center gap-2">
            <ConnectionStatus connected={wsConnected || streamConnected || !pulse.isError} lastUpdate={lastUpdate} />
            <div className="flex items-center gap-1.5">
              <Radio className={cn("h-3.5 w-3.5", !paused ? "text-green-400 animate-pulse" : "text-muted-foreground")} />
              <span className="text-xs text-muted-foreground hidden sm:block">Auto-refresh</span>
              <Switch checked={!paused} onCheckedChange={(v) => setPaused(!v)} />
            </div>
            <Button variant="outline" size="sm" onClick={refetch} disabled={paused}>
              <RefreshCw className={cn("h-4 w-4", pulse.isFetching && "animate-spin")} />
            </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6"
      >
        <motion.div variants={itemVariants}>
          <KpiCard title="Total Events" value={totalCount} icon={Activity} trend="flat" />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Findings"
            value={findingCount}
            icon={AlertTriangle}         trend={findingCount > 5 ? "up" : "flat"}
            className={cn(findingCount > 0 && "border-red-500/20")}
          />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard title="Decisions" value={decisionCount} icon={FileText} trend="flat" />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard title="MPTE Events" value={mpteCount} icon={Zap} trend="flat" />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard title="Deployments" value={deployCount} icon={GitBranch} trend="flat" />
        </motion.div>
        <motion.div variants={itemVariants}>
          <KpiCard
            title="Critical Events"
            value={criticalCount}
            icon={XCircle}         trend={criticalCount > 0 ? "up" : "down"}
            className={cn(criticalCount > 0 && "border-red-500/30 bg-red-500/5")}
          />
        </motion.div>
      </motion.div>

      {/* Filter Bar */}
      <motion.div
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.18 }}
        className="flex flex-wrap items-center gap-2"
      >
        <div className="relative flex-1 min-w-[200px] max-w-[320px]">
          <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search events..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-8 text-xs"
          />
        </div>
        <Select value={eventType} onValueChange={(v) => setEventType(v as EventType)}>
          <SelectTrigger className="h-8 w-[130px] text-xs">
            <Filter className="h-3.5 w-3.5 mr-1.5" />
            <SelectValue placeholder="Event Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="finding">Findings</SelectItem>
            <SelectItem value="decision">Decisions</SelectItem>
            <SelectItem value="mpte">MPTE</SelectItem>
            <SelectItem value="deployment">Deployments</SelectItem>
            <SelectItem value="policy">Policy</SelectItem>
            <SelectItem value="fix">Fixes</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v as SeverityFilter)}>
          <SelectTrigger className="h-8 w-[120px] text-xs">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex items-center gap-1.5 ml-auto text-xs text-muted-foreground">
          <span>Auto-scroll</span>
          <Switch
            checked={autoScroll}
            onCheckedChange={setAutoScroll}
            className="scale-75"
          />
        </div>
        <Badge variant="outline" className="text-[10px]">
          {filteredEvents.length} / {totalCount} events
        </Badge>
      </motion.div>

      {/* Event Stream */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.22 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-blue-400" />
                Event Stream
              </CardTitle>
              <div className="flex items-center gap-2">
                {paused && (
                  <Badge variant="outline" className="text-[10px] border-yellow-500/30 text-yellow-400">
                    Paused
                  </Badge>
                )}
                <span className="text-[10px] text-muted-foreground">newest first</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[480px]" ref={scrollRef as React.RefObject<HTMLDivElement>}>
              <div className="px-6 pb-4">
                <AnimatePresence initial={false}>
                  {displayEvents.length > 0 ? displayEvents.map((ev, i) => {
                    const cfg = EVENT_TYPE_CONFIG[ev.type?.toLowerCase() ?? ""] ?? {
                      dotColor: "#6b7280",
                      icon: Activity,
                    };
                    const time = ev.timestamp ?? ev.created_at;
                    const sevColor = SEVERITY_COLORS[ev.severity?.toLowerCase() ?? ""] ?? undefined;

                    return (
                      <motion.div
                        key={`${ev.id ?? i}-${ev.timestamp ?? i}`}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 8 }}
                        transition={{ duration: 0.2 }}
                        className="flex items-start gap-3 py-3 border-b border-border/40 last:border-0 group hover:bg-muted/20 -mx-2 px-2 rounded-lg transition-colors"
                      >
                        {/* Timeline dot */}
                        <div className="flex flex-col items-center mt-1 shrink-0">
                          <span
                            className="h-2.5 w-2.5 rounded-full ring-2 ring-background"
                            style={{ backgroundColor: sevColor ?? cfg.dotColor }}
                          />
                          {i < displayEvents.length - 1 && (
                            <span className="w-px h-6 bg-border/40 mt-1" />
                          )}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0 space-y-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <EventTypeBadge type={ev.type ?? ""} />
                            {ev.severity && (
                              <Badge
                                variant="outline"
                                className={cn(
                                  "text-[9px] h-4 px-1 capitalize border",
                                  ev.severity === "critical" && "border-red-500/30 text-red-400",
                                  ev.severity === "high" && "border-orange-500/30 text-orange-400",
                                  ev.severity === "medium" && "border-yellow-500/30 text-yellow-400",
                                  ev.severity === "low" && "border-green-500/30 text-green-400",
                                )}
                              >
                                {ev.severity}
                              </Badge>
                            )}
                            <span className="text-[10px] text-muted-foreground flex items-center gap-1 ml-auto">
                              <Clock className="h-3 w-3" />
                              {time ? new Date(String(time)).toLocaleTimeString() : "—"}
                            </span>
                          </div>
                          <p className="text-sm text-foreground/90 leading-snug">
                            {String(ev.message ?? ev.description ?? "No description")}
                          </p>
                          {ev.component && (
                            <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
                              <Eye className="h-3 w-3 shrink-0" />
                              <span className="truncate">{String(ev.component)}</span>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    );
                  }) : (
                    <div className="flex flex-col items-center justify-center h-[300px] gap-3 text-muted-foreground">
                      <Activity className="h-10 w-10 opacity-20" />
                      <p className="text-sm">
                        {allEvents.length === 0
                          ? "No events yet — waiting for activity"
                          : "No events match the current filters"
                        }
                      </p>
                      {allEvents.length > 0 && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setEventType("all");
                            setSeverityFilter("all");
                            setSearchQuery("");
                          }}
                        >
                          Clear filters
                        </Button>
                      )}
                    </div>
                  )}
                </AnimatePresence>
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </motion.div>

      {/* Status bar */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.35 }}
        className="flex items-center justify-between rounded-lg border border-border/50 bg-muted/20 px-4 py-2 text-[11px] text-muted-foreground"
      >
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className={cn(
              "h-2 w-2 rounded-full",
              !paused ? "bg-green-400 animate-pulse" : "bg-yellow-400"
            )} />
            {paused ? "Feed paused" : "Auto-refreshing every 30s"}
          </span>
          <Separator orientation="vertical" className="h-3" />
          <span>{filteredEvents.length} events shown</span>
          {searchQuery && (
            <>
              <Separator orientation="vertical" className="h-3" />
              <span>Filter: &ldquo;{searchQuery}&rdquo;</span>
            </>
          )}
        </div>
        <span>
          {wsConnected ? "TrustGraph WS Live" : streamConnected ? "SSE" : "Polling fallback"} · Updated {lastUpdate.toLocaleTimeString()}
        </span>
      </motion.div>
    </motion.div>
  );
}
