/**
 * LiveEventStream — drop-in real-time event feed widget.
 *
 * Renders a fixed-height scrollable list of incoming security events from the
 * /api/v1/ws/events WebSocket. Shows a connection-status pill and an
 * EmptyState when no events have arrived yet. Designed to slot into any
 * dashboard's right-rail / sidebar.
 */
import { Activity, Wifi, WifiOff } from "lucide-react";
import type { ReactNode } from "react";
import { useWebSocket, type WsEvent, type WsConnectionStatus } from "@/lib/useWebSocket";

const sevColor: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
  info: "bg-gray-600 text-gray-200",
};

const statusPill: Record<WsConnectionStatus, { color: string; label: string; Icon: typeof Wifi }> = {
  connected: { color: "bg-green-700/60 text-green-100", label: "Live", Icon: Wifi },
  connecting: { color: "bg-amber-700/60 text-amber-100", label: "Connecting…", Icon: Wifi },
  disconnected: { color: "bg-gray-700 text-gray-200", label: "Offline", Icon: WifiOff },
  error: { color: "bg-red-700/60 text-red-100", label: "Error", Icon: WifiOff },
};

export interface LiveEventStreamProps {
  /** Restrict to specific event types; omit for all */
  eventTypes?: string[];
  /** Override the visible title */
  title?: string;
  /** Optional callback fired for each event received (e.g. to refetch a table) */
  onEvent?: (e: WsEvent) => void;
  /** Empty-state body */
  emptyMessage?: string;
  /** Height class — default h-96 */
  heightClass?: string;
  /** Optional render-prop for custom row rendering */
  renderEvent?: (e: WsEvent) => ReactNode;
}

export function LiveEventStream(props: LiveEventStreamProps) {
  const {
    eventTypes,
    title = "Live Events",
    onEvent,
    emptyMessage = "Waiting for real-time security events. Trigger a scan to see updates flow in.",
    heightClass = "h-96",
    renderEvent,
  } = props;

  const { events, status, lastEvent } = useWebSocket({ eventTypes });

  // Forward each new event to the consumer (driven by lastEvent identity)
  if (onEvent && lastEvent && lastEvent.type === "event") {
    // Defer to next tick so React doesn't see a setState during render in the parent
    queueMicrotask(() => onEvent(lastEvent));
  }

  const pill = statusPill[status];

  return (
    <div className="bg-gray-800 rounded-lg p-4 flex flex-col" data-testid="live-event-stream">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-white flex items-center gap-2">
          <Activity className="w-4 h-4 text-indigo-400" /> {title}
        </h3>
        <span
          className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded ${pill.color}`}
          data-testid="ws-status"
          data-status={status}
        >
          <pill.Icon className="w-3 h-3" /> {pill.label}
        </span>
      </div>

      <div className={`overflow-y-auto ${heightClass} space-y-2 pr-1`} data-testid="live-event-list">
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4">
            <Activity className="w-8 h-8 text-gray-600 mb-2" />
            <p className="text-gray-500 text-xs">{emptyMessage}</p>
          </div>
        ) : (
          events.map((e) =>
            renderEvent ? (
              <div key={e.event_id ?? e.timestamp} data-testid="live-event-item">
                {renderEvent(e)}
              </div>
            ) : (
              <div
                key={e.event_id ?? e.timestamp}
                data-testid="live-event-item"
                className="bg-gray-900/60 border border-gray-700 rounded p-2 text-xs"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className={`px-1.5 py-0.5 rounded font-bold ${sevColor[e.severity ?? "info"] ?? sevColor.info}`}>
                    {e.severity ?? "info"}
                  </span>
                  <span className="text-gray-400 uppercase tracking-wide text-[10px]">{e.event_type}</span>
                  <span className="text-gray-500 ml-auto text-[10px]">
                    {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ""}
                  </span>
                </div>
                <p className="text-gray-200 font-medium truncate">{e.title ?? "Event"}</p>
                {e.message && <p className="text-gray-400 mt-0.5 truncate">{e.message}</p>}
              </div>
            ),
          )
        )}
      </div>
    </div>
  );
}

export default LiveEventStream;
