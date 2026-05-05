/**
 * WatchlistPanel — IOC watchlist + threat-actor watch feed
 * API: GET /api/v1/ioc-enrichment/stats + /iocs + /threat-actors/watchlist
 * Used by ThreatIntelOpsHub "watchlist" tab.
 */

import { useEffect, useState } from "react";
import { Eye, AlertTriangle, RefreshCw, Zap } from "lucide-react";
import { iocEnrichmentApi, threatActorsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";

interface IOC {
  ioc_id?: string;
  id?: string;
  ioc_type?: string;
  value?: string;
  severity?: string;
  confidence?: number;
  enrichment_status?: string;
  last_seen?: string;
  source?: string;
}

interface IOCStats {
  total_iocs?: number;
  enriched?: number;
  pending?: number;
  by_type?: Record<string, number>;
  by_severity?: Record<string, number>;
}

interface WatchlistEntry {
  actor_id?: string;
  id?: string;
  name?: string;
  actor_type?: string;
  threat_level?: string;
  last_activity?: string;
  ioc_count?: number;
}

const SEV_PILL: Record<string, string> = {
  critical: "bg-red-700/40 text-red-300",
  high:     "bg-orange-700/40 text-orange-300",
  medium:   "bg-amber-700/40 text-amber-300",
  low:      "bg-green-700/40 text-green-300",
};

function pill(s: string) {
  return SEV_PILL[s?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

export function WatchlistPanel() {
  const [stats, setStats]       = useState<IOCStats | null>(null);
  const [iocs, setIocs]         = useState<IOC[]>([]);
  const [watchlist, setWatchlist] = useState<WatchlistEntry[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [enriching, setEnriching] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, iocsRes, watchRes] = await Promise.allSettled([
        iocEnrichmentApi.stats(),
        iocEnrichmentApi.list(),
        threatActorsApi.watchlist(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as IOCStats);
      if (iocsRes.status === "fulfilled") {
        const d = iocsRes.value.data;
        setIocs(Array.isArray(d) ? d : (d?.iocs ?? d?.items ?? []));
      }
      if (watchRes.status === "fulfilled") {
        const d = watchRes.value.data;
        setWatchlist(Array.isArray(d) ? d : (d?.watchlist ?? d?.actors ?? []));
      }
      if (statsRes.status === "rejected" && iocsRes.status === "rejected") {
        throw new Error("Failed to load watchlist data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const enrichIoc = async (iocId: string) => {
    setEnriching(iocId);
    try {
      await iocEnrichmentApi.enrich(iocId);
      await load();
    } catch {
      // silent — list refresh handles error state
    } finally {
      setEnriching(null);
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

  if (!stats && iocs.length === 0 && watchlist.length === 0) {
    return (
      <EmptyState
        icon={Eye}
        title="No watchlist entries"
        description="Add IOCs via POST /api/v1/ioc-enrichment/iocs or track actors via /api/v1/threat-actors/watchlist."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* IOC stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total IOCs",  value: stats.total_iocs ?? iocs.length, color: "text-foreground" },
            { label: "Enriched",    value: stats.enriched ?? 0,             color: "text-green-400" },
            { label: "Pending",     value: stats.pending ?? 0,              color: "text-amber-400" },
            { label: "Watchlisted", value: watchlist.length,                color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Severity breakdown */}
      {stats?.by_severity && Object.keys(stats.by_severity).length > 0 && (
        <div className="flex flex-wrap gap-2">
          {Object.entries(stats.by_severity).map(([sev, count]) => (
            <span key={sev} className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ${pill(sev)}`}>
              {sev} <span className="font-bold">{count}</span>
            </span>
          ))}
        </div>
      )}

      {/* IOC table */}
      {iocs.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Eye className="h-3.5 w-3.5 text-indigo-400" />
              IOC Watchlist ({iocs.length})
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
                <th className="text-left px-4 py-2 font-medium">Value</th>
                <th className="text-left px-4 py-2 font-medium">Type</th>
                <th className="text-left px-4 py-2 font-medium">Severity</th>
                <th className="text-left px-4 py-2 font-medium">Confidence</th>
                <th className="text-left px-4 py-2 font-medium">Status</th>
                <th className="text-left px-4 py-2 font-medium">Last Seen</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {iocs.slice(0, 50).map((ioc, i) => {
                const id = ioc.ioc_id ?? ioc.id ?? String(i);
                return (
                  <tr key={id} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2 font-mono text-xs truncate max-w-[200px]">{ioc.value ?? "—"}</td>
                    <td className="px-4 py-2 text-xs capitalize text-muted-foreground">{ioc.ioc_type ?? "—"}</td>
                    <td className="px-4 py-2">
                      {ioc.severity ? (
                        <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${pill(ioc.severity)}`}>
                          {ioc.severity}
                        </span>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-2 text-xs font-mono">
                      {ioc.confidence != null ? `${ioc.confidence}%` : "—"}
                    </td>
                    <td className="px-4 py-2 text-xs capitalize text-muted-foreground">
                      {ioc.enrichment_status ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
                      {ioc.last_seen ? new Date(ioc.last_seen).toLocaleDateString() : "—"}
                    </td>
                    <td className="px-4 py-2">
                      <button
                        onClick={() => enrichIoc(id)}
                        disabled={enriching === id}
                        title="Enrich IOC"
                        className="flex items-center gap-0.5 rounded px-2 py-0.5 text-xs bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/40 disabled:opacity-50 transition-colors"
                      >
                        <Zap className="h-3 w-3" />
                        {enriching === id ? "…" : "Enrich"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Actor watchlist */}
      {watchlist.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-orange-400" />
              Watched Actors ({watchlist.length})
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Actor</th>
                <th className="text-left px-4 py-2 font-medium">Type</th>
                <th className="text-left px-4 py-2 font-medium">Threat Level</th>
                <th className="text-right px-4 py-2 font-medium">IOCs</th>
                <th className="text-left px-4 py-2 font-medium">Last Activity</th>
              </tr>
            </thead>
            <tbody>
              {watchlist.map((a, i) => (
                <tr key={a.actor_id ?? a.id ?? i} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 font-medium text-sm">{a.name ?? "—"}</td>
                  <td className="px-4 py-2 text-xs capitalize text-muted-foreground">{a.actor_type ?? "—"}</td>
                  <td className="px-4 py-2">
                    {a.threat_level ? (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${pill(a.threat_level)}`}>
                        {a.threat_level}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2 text-right font-mono text-xs text-sky-400">{a.ioc_count ?? 0}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {a.last_activity ? new Date(a.last_activity).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
