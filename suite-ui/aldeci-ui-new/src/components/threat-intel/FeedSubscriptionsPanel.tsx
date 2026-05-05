/**
 * FeedSubscriptionsPanel — threat-intel feed subscriptions + ingestion logs
 * API: GET /api/v1/feed-subscriptions/subscriptions + /stats + /logs
 * Used by ThreatIntelOpsHub "feeds" tab.
 */

import { useEffect, useState } from "react";
import { Rss, AlertTriangle, RefreshCw, CheckCircle2, XCircle, Clock } from "lucide-react";
import { feedSubscriptionsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";

interface Subscription {
  subscription_id?: string;
  id?: string;
  feed_name?: string;
  feed_url?: string;
  status?: string;
  last_refresh?: string;
  refresh_interval_minutes?: number;
  ioc_count?: number;
  error_message?: string;
}

interface FeedStats {
  total_feeds?: number;
  active?: number;
  failed?: number;
  total_iocs_ingested?: number;
  last_refresh?: string;
}

interface IngestLog {
  log_id?: string;
  id?: string;
  feed_name?: string;
  ingested_at?: string;
  ioc_count?: number;
  status?: string;
  duration_ms?: number;
}

const STATUS_PILL: Record<string, string> = {
  active:   "bg-green-700/40 text-green-300",
  failed:   "bg-red-700/40 text-red-300",
  paused:   "bg-amber-700/40 text-amber-300",
  pending:  "bg-sky-700/40 text-sky-300",
};

function pill(s: string) {
  return STATUS_PILL[s?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

function StatusIcon({ status }: { status: string }) {
  if (status === "active")  return <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />;
  if (status === "failed")  return <XCircle className="h-3.5 w-3.5 text-red-400" />;
  if (status === "paused")  return <Clock className="h-3.5 w-3.5 text-amber-400" />;
  return null;
}

export function FeedSubscriptionsPanel() {
  const [stats, setStats]               = useState<FeedStats | null>(null);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const [logs, setLogs]                 = useState<IngestLog[]>([]);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState<string | null>(null);
  const [refreshing, setRefreshing]     = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, subsRes, logsRes] = await Promise.allSettled([
        feedSubscriptionsApi.stats(),
        feedSubscriptionsApi.list(),
        feedSubscriptionsApi.logs(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as FeedStats);
      if (subsRes.status === "fulfilled") {
        const d = subsRes.value.data;
        setSubscriptions(Array.isArray(d) ? d : (d?.subscriptions ?? d?.items ?? []));
      }
      if (logsRes.status === "fulfilled") {
        const d = logsRes.value.data;
        setLogs(Array.isArray(d) ? d : (d?.logs ?? d?.items ?? []));
      }
      if (statsRes.status === "rejected" && subsRes.status === "rejected") {
        throw new Error("Failed to load feed subscription data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const triggerRefresh = async (id: string) => {
    setRefreshing(id);
    try {
      await feedSubscriptionsApi.refresh(id);
      await load();
    } catch {
      // silent
    } finally {
      setRefreshing(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-3 p-4 animate-pulse">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-20 rounded-lg bg-muted/40" />)}
        </div>
        {[1, 2, 3].map(i => <div key={i} className="h-10 rounded bg-muted/30" />)}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (!stats && subscriptions.length === 0) {
    return (
      <EmptyState
        icon={Rss}
        title="No feed subscriptions"
        description="Subscribe to threat-intel feeds via POST /api/v1/feed-subscriptions/subscriptions."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Feeds",   value: stats.total_feeds ?? subscriptions.length, color: "text-foreground" },
            { label: "Active",        value: stats.active ?? 0,                         color: "text-green-400" },
            { label: "Failed",        value: stats.failed ?? 0,                         color: "text-red-400" },
            { label: "IOCs Ingested", value: (stats.total_iocs_ingested ?? 0).toLocaleString(), color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Subscriptions table */}
      {subscriptions.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Rss className="h-3.5 w-3.5 text-indigo-400" />
              Feed Subscriptions ({subscriptions.length})
            </h3>
            <button
              onClick={load}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Feed</th>
                <th className="text-left px-4 py-2 font-medium">Status</th>
                <th className="text-right px-4 py-2 font-medium">IOCs</th>
                <th className="text-left px-4 py-2 font-medium">Interval</th>
                <th className="text-left px-4 py-2 font-medium">Last Refresh</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {subscriptions.map((sub, i) => {
                const id = sub.subscription_id ?? sub.id ?? String(i);
                return (
                  <tr key={id} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-1.5">
                        <StatusIcon status={sub.status ?? ""} />
                        <span className="font-medium text-sm">{sub.feed_name ?? "—"}</span>
                      </div>
                      {sub.feed_url && (
                        <div className="text-xs text-muted-foreground truncate max-w-[200px] mt-0.5">{sub.feed_url}</div>
                      )}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${pill(sub.status ?? "")}`}>
                        {sub.status ?? "unknown"}
                      </span>
                      {sub.error_message && (
                        <div className="text-xs text-red-400 mt-0.5 max-w-[160px] truncate">{sub.error_message}</div>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right font-mono text-xs text-sky-400">
                      {(sub.ioc_count ?? 0).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {sub.refresh_interval_minutes != null ? `${sub.refresh_interval_minutes}m` : "—"}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {sub.last_refresh ? new Date(sub.last_refresh).toLocaleString() : "—"}
                    </td>
                    <td className="px-4 py-2">
                      <button
                        onClick={() => triggerRefresh(id)}
                        disabled={refreshing === id}
                        className="rounded px-2 py-0.5 text-xs bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/40 disabled:opacity-50 transition-colors"
                      >
                        {refreshing === id ? "…" : "Refresh"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Recent ingestion logs */}
      {logs.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium text-muted-foreground">Recent Ingestion Log</h3>
          </div>
          <div className="divide-y divide-border/40 max-h-60 overflow-y-auto">
            {logs.slice(0, 20).map((log, i) => (
              <div key={log.log_id ?? log.id ?? i} className="flex items-center justify-between px-4 py-2 text-xs hover:bg-muted/10 transition-colors">
                <div>
                  <span className="font-medium text-foreground">{log.feed_name ?? "Unknown feed"}</span>
                  <span className="ml-2 text-muted-foreground">
                    {log.ingested_at ? new Date(log.ingested_at).toLocaleString() : ""}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sky-400">{(log.ioc_count ?? 0).toLocaleString()} IOCs</span>
                  {log.duration_ms != null && (
                    <span className="text-muted-foreground">{log.duration_ms}ms</span>
                  )}
                  <span className={`rounded px-1.5 py-0.5 font-medium ${pill(log.status ?? "")}`}>
                    {log.status ?? "—"}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
