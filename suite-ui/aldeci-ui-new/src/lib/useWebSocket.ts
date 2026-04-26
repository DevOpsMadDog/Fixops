/**
 * useWebSocket — React hook for the ALDECI real-time event stream.
 *
 * Wraps the backend WebSocket endpoint at /api/v1/ws/events. Auth is sent via
 * query params because the browser WebSocket API cannot set custom headers.
 *
 * Features:
 *   - Auto-reconnect with capped exponential backoff (max 30s)
 *   - Event-type filter passed as comma-separated query string
 *   - Org-scoped via ?org_id query param
 *   - Pings server with {"type":"pong"} on receipt of {"type":"ping"}
 *   - Buffers up to `maxEvents` recent events for in-page display
 *
 * Usage:
 *   const { events, status, lastEvent, clear } = useWebSocket({
 *     eventTypes: ["finding", "alert"],
 *     maxEvents: 50,
 *   });
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { getStoredAuthToken, getStoredOrgId } from "./api";

export type WsConnectionStatus = "connecting" | "connected" | "disconnected" | "error";

export interface WsEvent {
  type: string; // "event" | "connected" | "ping" | "pong"
  event_id?: string;
  event_type?: string; // alert | finding | incident | sla_breach | anomaly | threat | compliance | audit
  severity?: string;
  title?: string;
  message?: string;
  payload?: Record<string, unknown>;
  org_id?: string;
  timestamp?: string;
  [k: string]: unknown;
}

export interface UseWebSocketOptions {
  /** Comma-separated event types or array; omit for all events */
  eventTypes?: string | string[];
  /** Override org_id; default = getStoredOrgId() || "default" */
  orgId?: string;
  /** Max ring-buffer length of recent events (default 50) */
  maxEvents?: number;
  /** Disable connection (for tests / hidden pages) */
  enabled?: boolean;
}

export interface UseWebSocketReturn {
  events: WsEvent[];
  status: WsConnectionStatus;
  lastEvent: WsEvent | null;
  clear: () => void;
  reconnectCount: number;
}

function buildWsUrl(filters: { eventTypes?: string; orgId?: string }): string {
  const apiUrl = (import.meta as unknown as { env?: { VITE_API_URL?: string } }).env?.VITE_API_URL?.trim() || "";
  // Convert http(s) → ws(s); fall back to current page origin if API_URL is empty
  let base: string;
  if (apiUrl) {
    base = apiUrl.replace(/^http/i, "ws");
  } else if (typeof window !== "undefined") {
    base = window.location.origin.replace(/^http/i, "ws");
  } else {
    base = "ws://localhost:8000";
  }
  const url = new URL("/api/v1/ws/events", base);
  const apiKey = getStoredAuthToken();
  if (apiKey) {
    url.searchParams.set("api_key", apiKey);
    url.searchParams.set("token", apiKey);
  }
  if (filters.orgId) url.searchParams.set("org_id", filters.orgId);
  if (filters.eventTypes) url.searchParams.set("event_type", filters.eventTypes);
  return url.toString();
}

export function useWebSocket(opts: UseWebSocketOptions = {}): UseWebSocketReturn {
  const { eventTypes, orgId, maxEvents = 50, enabled = true } = opts;
  const eventTypesStr = Array.isArray(eventTypes) ? eventTypes.join(",") : eventTypes;
  const resolvedOrg = orgId || getStoredOrgId() || "default";

  const [events, setEvents] = useState<WsEvent[]>([]);
  const [status, setStatus] = useState<WsConnectionStatus>(enabled ? "connecting" : "disconnected");
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null);
  const [reconnectCount, setReconnectCount] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef<number>(1000); // start at 1s
  const closedByUser = useRef<boolean>(false);

  const clear = useCallback(() => {
    setEvents([]);
    setLastEvent(null);
  }, []);

  useEffect(() => {
    if (!enabled || typeof window === "undefined" || typeof WebSocket === "undefined") {
      setStatus("disconnected");
      return;
    }

    closedByUser.current = false;

    const connect = () => {
      try {
        const url = buildWsUrl({ eventTypes: eventTypesStr, orgId: resolvedOrg });
        const ws = new WebSocket(url);
        wsRef.current = ws;
        setStatus("connecting");

        ws.onopen = () => {
          setStatus("connected");
          backoffRef.current = 1000;
        };

        ws.onmessage = (msg: MessageEvent<string>) => {
          let data: WsEvent;
          try {
            data = JSON.parse(msg.data) as WsEvent;
          } catch {
            return;
          }
          // Reply to server pings to keep the connection alive
          if (data.type === "ping") {
            try {
              ws.send(JSON.stringify({ type: "pong" }));
            } catch {
              /* socket already closing */
            }
            return;
          }
          // Ignore the welcome frame for the events list (still surfaces via lastEvent)
          if (data.type === "connected") {
            setLastEvent(data);
            return;
          }
          // Standard event frame
          if (data.type === "event") {
            setLastEvent(data);
            setEvents((prev) => {
              const next = [data, ...prev];
              return next.length > maxEvents ? next.slice(0, maxEvents) : next;
            });
          }
        };

        ws.onerror = () => {
          setStatus("error");
        };

        ws.onclose = () => {
          setStatus("disconnected");
          if (closedByUser.current) return;
          // Schedule reconnect with capped exponential backoff
          const delay = Math.min(backoffRef.current, 30_000);
          backoffRef.current = Math.min(backoffRef.current * 2, 30_000);
          reconnectTimer.current = setTimeout(() => {
            setReconnectCount((c) => c + 1);
            connect();
          }, delay);
        };
      } catch {
        setStatus("error");
        const delay = Math.min(backoffRef.current, 30_000);
        backoffRef.current = Math.min(backoffRef.current * 2, 30_000);
        reconnectTimer.current = setTimeout(connect, delay);
      }
    };

    connect();

    return () => {
      closedByUser.current = true;
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      if (wsRef.current && wsRef.current.readyState !== WebSocket.CLOSED) {
        try {
          wsRef.current.close();
        } catch {
          /* noop */
        }
      }
      wsRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, eventTypesStr, resolvedOrg, maxEvents]);

  return { events, status, lastEvent, clear, reconnectCount };
}

export default useWebSocket;
