/**
 * SIEMPanel — IntegrationTargetsHub "siem" tab
 *
 * Wired to real backend:
 *   GET /api/v1/siem/stats          → aggregate KPIs
 *   GET /api/v1/siem/sources        → registered SIEM forwarders
 *   GET /api/v1/siem/alerts         → correlation alerts
 *   GET /api/v1/siem/events         → recent events (last 50)
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Send, RefreshCw, AlertTriangle, Activity, Server } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface SIEMStats {
  total_sources?: number;
  total_events?: number;
  total_alerts?: number;
  active_alerts?: number;
  [key: string]: unknown;
}

interface SIEMSource {
  id?: string;
  name: string;
  source_type: string;
  status?: string;
  host?: string;
  port?: number;
  created_at?: string;
}

interface SIEMAlert {
  id?: string;
  title: string;
  rule_name?: string;
  severity: string;
  status?: string;
  created_at?: string;
}

interface SIEMEvent {
  id?: string;
  source_id?: string;
  event_type?: string;
  severity?: string;
  created_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
  info: "bg-slate-600/80 text-slate-200",
};

const SRC_STATUS_CLASS: Record<string, string> = {
  active: "border-emerald-600 text-emerald-400",
  inactive: "border-amber-600 text-amber-400",
  error: "border-red-600 text-red-400",
};

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown, ...keys: string[]): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of [...keys, "items", "data", "results"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

type SubView = "sources" | "alerts" | "events";

export default function SIEMPanel() {
  const [stats, setStats] = useState<SIEMStats | null>(null);
  const [sources, setSources] = useState<SIEMSource[]>([]);
  const [alerts, setAlerts] = useState<SIEMAlert[]>([]);
  const [events, setEvents] = useState<SIEMEvent[]>([]);
  const [subView, setSubView] = useState<SubView>("sources");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, sourcesRes, alertsRes, eventsRes] = await Promise.all([
        apiFetch<SIEMStats>("/api/v1/siem/stats"),
        apiFetch<unknown>("/api/v1/siem/sources"),
        apiFetch<unknown>("/api/v1/siem/alerts"),
        apiFetch<unknown>("/api/v1/siem/events?sysparm_limit=50"),
      ]);
      setStats(statsRes);
      setSources(extractArray<SIEMSource>(sourcesRes, "sources"));
      setAlerts(extractArray<SIEMAlert>(alertsRes, "alerts"));
      setEvents(extractArray<SIEMEvent>(eventsRes, "events"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load SIEM data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Sources", value: stats?.total_sources ?? sources.length, icon: Server, color: "text-indigo-400" },
    { label: "Events", value: stats?.total_events ?? events.length, icon: Activity, color: "text-blue-400" },
    { label: "Alerts", value: stats?.total_alerts ?? alerts.length, icon: AlertTriangle, color: "text-amber-400" },
    { label: "Active Alerts", value: stats?.active_alerts ?? alerts.filter(a => a.status !== "resolved").length, icon: AlertTriangle, color: "text-red-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Send className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">SIEM Output</span>
          <Badge variant="outline" className="border-emerald-600 text-emerald-400">
            {sources.length} forwarder{sources.length !== 1 ? "s" : ""}
          </Badge>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </span>
          </div>
        ))}
      </div>

      {/* Sub-view tabs */}
      <div className="flex items-center gap-2 border-b border-border pb-2">
        {(["sources", "alerts", "events"] as SubView[]).map(v => (
          <button
            key={v}
            onClick={() => setSubView(v)}
            className={`px-3 py-1.5 rounded text-xs font-medium capitalize transition-colors ${
              subView === v
                ? "bg-indigo-600 text-white"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {v} {v === "sources" ? `(${sources.length})` : v === "alerts" ? `(${alerts.length})` : `(${events.length})`}
          </button>
        ))}
      </div>

      {/* Sources view */}
      {subView === "sources" && (
        sources.length === 0 ? (
          <EmptyState
            icon={<Server className="h-8 w-8 text-indigo-400" />}
            title="No SIEM sources"
            description="Register a SIEM source to start forwarding events."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Name", "Type", "Host", "Port", "Status", "Registered"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sources.map((s, i) => (
                  <tr key={s.id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{s.name}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{s.source_type}</td>
                    <td className="px-3 py-2 font-mono text-muted-foreground">{s.host ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{s.port ?? "—"}</td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className={SRC_STATUS_CLASS[s.status ?? ""] ?? "border-slate-600 text-slate-400"}>
                        {s.status ?? "unknown"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {s.created_at ? new Date(s.created_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Alerts view */}
      {subView === "alerts" && (
        alerts.length === 0 ? (
          <EmptyState
            icon={<AlertTriangle className="h-8 w-8 text-amber-400" />}
            title="No correlation alerts"
            description="No correlation alerts have been triggered yet."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Title", "Rule", "Severity", "Status", "Created"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 100).map((a, i) => (
                  <tr key={a.id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium max-w-[200px] truncate">{a.title}</td>
                    <td className="px-3 py-2 text-muted-foreground">{a.rule_name ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[a.severity?.toLowerCase()] ?? SEV_CLASS.info}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{a.status ?? "open"}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {a.created_at ? new Date(a.created_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Events view */}
      {subView === "events" && (
        events.length === 0 ? (
          <EmptyState
            icon={<Activity className="h-8 w-8 text-blue-400" />}
            title="No SIEM events"
            description="No events have been ingested yet."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Event Type", "Source", "Severity", "Timestamp"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 100).map((e, i) => (
                  <tr key={e.id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{e.event_type ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-muted-foreground text-[10px]">
                      {e.source_id ? e.source_id.slice(0, 8) + "…" : "—"}
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[e.severity?.toLowerCase() ?? ""] ?? SEV_CLASS.info}`}>
                        {e.severity ?? "info"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {e.created_at ? new Date(e.created_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </motion.div>
  );
}
