/**
 * LiveEventFeed — Real-time WebSocket event feed widget
 *
 * Connects to ws://localhost:8000/api/v1/ws/events?api_key=TOKEN
 * Shows last 10 events with severity badge, title, timestamp, source.
 * Animated slide-in entrance for new events.
 * Connection status indicator with auto-reconnect.
 */

import { useEffect, useRef, useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  AlertCircle,
  Info,
  WifiOff,
  Wifi,
  Radio,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

// ── Config ──────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

const WS_BASE = API_BASE.replace(/^http/, "ws");
const WS_URL = `${WS_BASE}/api/v1/ws/events?api_key=${API_KEY}`;

const MAX_EVENTS = 10;
const RECONNECT_DELAY_MS = 3_000;
const MAX_RECONNECT_ATTEMPTS = 8;

// ── Types ────────────────────────────────────────────────────────────
export interface LiveEvent {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  source: string;
  timestamp: string;
}

type ConnectionStatus = "connected" | "connecting" | "disconnected" | "unavailable";

// ── Mock events (shown when WS is unavailable) ───────────────────────
function makeMockEvent(idx: number): LiveEvent {
  const severities: LiveEvent["severity"][] = ["critical", "high", "medium", "low", "info"];
  const titles = [
    "Ransomware pattern detected on endpoint",
    "Suspicious login attempt blocked",
    "CVE-2024-3094 exploit attempt",
    "Cloud misconfiguration remediated",
    "Threat intel feed updated",
    "Privilege escalation attempt flagged",
    "DLP policy violation — PII export",
    "New IOC ingested from AlienVault",
    "Phishing URL blocked by gateway",
    "Container runtime anomaly detected",
  ];
  const sources = ["EDR", "SIEM", "WAF", "CloudWatch", "TI Feed", "IDS", "DLP", "OTX", "Gateway", "K8s"];
  const sev = severities[idx % severities.length];
  return {
    id: `mock-${Date.now()}-${idx}`,
    severity: sev,
    title: titles[idx % titles.length],
    source: sources[idx % sources.length],
    timestamp: new Date().toISOString(),
  };
}

// ── Helpers ──────────────────────────────────────────────────────────
function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

const SEV_CONFIG: Record<
  LiveEvent["severity"],
  { label: string; icon: React.ReactNode; badgeCls: string; dotCls: string }
> = {
  critical: {
    label: "CRIT",
    icon: <AlertTriangle className="w-3 h-3" />,
    badgeCls: "border-red-500/40 text-red-300 bg-red-500/10",
    dotCls: "bg-red-500",
  },
  high: {
    label: "HIGH",
    icon: <AlertCircle className="w-3 h-3" />,
    badgeCls: "border-orange-500/40 text-orange-300 bg-orange-500/10",
    dotCls: "bg-orange-500",
  },
  medium: {
    label: "MED",
    icon: <AlertCircle className="w-3 h-3" />,
    badgeCls: "border-amber-500/40 text-amber-300 bg-amber-500/10",
    dotCls: "bg-amber-500",
  },
  low: {
    label: "LOW",
    icon: <Info className="w-3 h-3" />,
    badgeCls: "border-zinc-500/40 text-zinc-400 bg-zinc-500/10",
    dotCls: "bg-zinc-500",
  },
  info: {
    label: "INFO",
    icon: <Info className="w-3 h-3" />,
    badgeCls: "border-cyan-500/40 text-cyan-300 bg-cyan-500/10",
    dotCls: "bg-cyan-500",
  },
};

// ── Connection status indicator ───────────────────────────────────────
function StatusDot({ status }: { status: ConnectionStatus }) {
  if (status === "connected") {
    return (
      <div className="flex items-center gap-1.5">
        <div className="relative">
          <span className="absolute inline-flex h-2 w-2 rounded-full bg-emerald-400 opacity-75 animate-ping" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
        </div>
        <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wide">Live</span>
      </div>
    );
  }
  if (status === "connecting") {
    return (
      <div className="flex items-center gap-1.5">
        <Radio className="w-3 h-3 text-amber-400 animate-pulse" />
        <span className="text-[10px] font-semibold text-amber-400 uppercase tracking-wide">Connecting</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1.5">
      <WifiOff className="w-3 h-3 text-zinc-500" />
      <span className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wide">
        {status === "unavailable" ? "Unavailable" : "Disconnected"}
      </span>
    </div>
  );
}

// ── Single event row ──────────────────────────────────────────────────
function EventRow({ event }: { event: LiveEvent }) {
  const cfg = SEV_CONFIG[event.severity] ?? SEV_CONFIG.info;
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: -12, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, height: 0, marginBottom: 0 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
      className="flex items-start gap-2.5 px-3 py-2 rounded-lg hover:bg-zinc-800/40 transition-colors group"
    >
      {/* Severity dot */}
      <div className="mt-1.5 shrink-0">
        <span className={cn("inline-flex w-1.5 h-1.5 rounded-full", cfg.dotCls)} />
      </div>

      {/* Main content */}
      <div className="flex-1 min-w-0 flex flex-col gap-0.5">
        <span className="text-xs text-zinc-200 font-medium leading-tight truncate group-hover:text-white transition-colors">
          {event.title}
        </span>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-zinc-600 font-mono">{event.source}</span>
          <span className="text-[9px] text-zinc-700">·</span>
          <span className="text-[10px] text-zinc-600">{timeAgo(event.timestamp)}</span>
        </div>
      </div>

      {/* Severity badge */}
      <Badge
        className={cn(
          "shrink-0 text-[9px] border px-1.5 py-0 h-4 font-bold flex items-center gap-0.5",
          cfg.badgeCls
        )}
      >
        {cfg.icon}
        {cfg.label}
      </Badge>
    </motion.div>
  );
}

// ── Main widget ───────────────────────────────────────────────────────
interface LiveEventFeedProps {
  className?: string;
}

export function LiveEventFeed({ className }: LiveEventFeedProps) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [status, setStatus] = useState<ConnectionStatus>("connecting");
  const [isMockMode, setIsMockMode] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mockTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const mockIdxRef = useRef(0);
  const mountedRef = useRef(true);

  // Prepend an event and keep only last MAX_EVENTS
  const addEvent = useCallback((ev: LiveEvent) => {
    setEvents((prev) => [ev, ...prev].slice(0, MAX_EVENTS));
  }, []);

  // Start mock feed when WS is unavailable
  const startMockFeed = useCallback(() => {
    if (mockTimerRef.current) return; // already running
    setIsMockMode(true);
    setStatus("unavailable");
    // Seed with a few events immediately
    const seed: LiveEvent[] = Array.from({ length: 5 }, (_, i) => makeMockEvent(i));
    setEvents(seed);
    mockIdxRef.current = seed.length;
    // Then trickle new events every 4s
    mockTimerRef.current = setInterval(() => {
      if (!mountedRef.current) return;
      addEvent(makeMockEvent(mockIdxRef.current++));
    }, 4_000);
  }, [addEvent]);

  const stopMockFeed = useCallback(() => {
    if (mockTimerRef.current) {
      clearInterval(mockTimerRef.current);
      mockTimerRef.current = null;
    }
    setIsMockMode(false);
  }, []);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    // Close existing socket if any
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
      wsRef.current = null;
    }

    setStatus("connecting");
    let ws: WebSocket;
    try {
      ws = new WebSocket(WS_URL);
    } catch {
      // WebSocket construction failed (e.g. bad URL in test env)
      startMockFeed();
      return;
    }

    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) return;
      reconnectAttemptsRef.current = 0;
      setStatus("connected");
      stopMockFeed();
      setEvents([]); // clear mock events on real connect
    };

    ws.onmessage = (evt) => {
      if (!mountedRef.current) return;
      try {
        const raw = JSON.parse(evt.data as string);
        // Normalise whatever shape the backend sends
        const ev: LiveEvent = {
          id: raw.id ?? raw.event_id ?? `${Date.now()}-${Math.random()}`,
          severity: raw.severity ?? raw.level ?? "info",
          title: raw.title ?? raw.message ?? raw.description ?? "Security event",
          source: raw.source ?? raw.engine ?? raw.service ?? "Platform",
          timestamp: raw.timestamp ?? raw.created_at ?? new Date().toISOString(),
        };
        addEvent(ev);
      } catch {
        // Non-JSON message — ignore
      }
    };

    ws.onerror = () => {
      // onerror always precedes onclose — let onclose handle reconnect
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setStatus("disconnected");
      wsRef.current = null;

      const attempts = ++reconnectAttemptsRef.current;
      if (attempts >= MAX_RECONNECT_ATTEMPTS) {
        // Give up on WS, fall back to mock
        startMockFeed();
        return;
      }

      // Exponential-ish backoff capped at 15s
      const delay = Math.min(RECONNECT_DELAY_MS * Math.pow(1.5, attempts - 1), 15_000);
      reconnectTimerRef.current = setTimeout(() => {
        if (mountedRef.current) connect();
      }, delay);
    };
  }, [addEvent, startMockFeed, stopMockFeed]);

  // Mount / unmount lifecycle
  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      // Tear down WS
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
      // Cancel pending reconnect
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      // Stop mock feed
      if (mockTimerRef.current) {
        clearInterval(mockTimerRef.current);
        mockTimerRef.current = null;
      }
    };
  }, [connect]);

  const cardBase = "border-zinc-800/80 bg-zinc-900/50 backdrop-blur-sm";

  return (
    <Card className={cn(cardBase, className)}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-violet-400" />
              Live Event Feed
            </CardTitle>
            <CardDescription className="text-xs text-zinc-600 mt-0.5">
              {isMockMode
                ? "Demo mode — WebSocket unavailable"
                : "Real-time security events via WebSocket"}
            </CardDescription>
          </div>
          <StatusDot status={status} />
        </div>
      </CardHeader>

      <CardContent className="pt-0 px-2 pb-2">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-8 text-zinc-600">
            {status === "connecting" ? (
              <>
                <Wifi className="w-5 h-5 animate-pulse text-amber-500/60" />
                <span className="text-xs">Connecting to event stream…</span>
              </>
            ) : (
              <>
                <WifiOff className="w-5 h-5" />
                <span className="text-xs">Live feed unavailable</span>
              </>
            )}
          </div>
        ) : (
          <div className="flex flex-col gap-0.5">
            <AnimatePresence initial={false} mode="popLayout">
              {events.map((ev) => (
                <EventRow key={ev.id} event={ev} />
              ))}
            </AnimatePresence>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
