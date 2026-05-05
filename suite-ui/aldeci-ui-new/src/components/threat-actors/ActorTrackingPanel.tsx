/**
 * ActorTrackingPanel — live actor tracking with activity + TTP summary
 * API: GET /api/v1/actor-tracking/summary + /actors + /active + /ttp-summary
 * Used by ThreatActorsHub "tracking" tab.
 */

import { useEffect, useState } from "react";
import { Crosshair, AlertTriangle, Activity, RefreshCw, Shield } from "lucide-react";
import { actorTrackingApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";

interface TrackingActor {
  actor_id?: string;
  id?: string;
  name: string;
  actor_type?: string;
  threat_level?: string;
  last_seen?: string;
  activity_count?: number;
  ttps?: string[];
}

interface TrackingSummary {
  total_tracked?: number;
  active_threats?: number;
  high_threat_count?: number;
  avg_activity_count?: number;
  last_updated?: string;
}

interface TTPEntry {
  technique_id?: string;
  technique_name?: string;
  actor_count?: number;
  tactic?: string;
}

const THREAT_PILL: Record<string, string> = {
  critical: "bg-red-700/40 text-red-300",
  high:     "bg-orange-700/40 text-orange-300",
  medium:   "bg-amber-700/40 text-amber-300",
  low:      "bg-green-700/40 text-green-300",
};

function pill(level: string) {
  return THREAT_PILL[level?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

export function ActorTrackingPanel() {
  const [summary, setSummary]   = useState<TrackingSummary | null>(null);
  const [actors, setActors]     = useState<TrackingActor[]>([]);
  const [active, setActive]     = useState<TrackingActor[]>([]);
  const [ttps, setTTPs]         = useState<TTPEntry[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sumRes, actorsRes, activeRes, ttpRes] = await Promise.allSettled([
        actorTrackingApi.summary(),
        actorTrackingApi.list(),
        actorTrackingApi.activeThreats(),
        actorTrackingApi.ttpSummary(),
      ]);
      if (sumRes.status === "fulfilled") setSummary(sumRes.value.data as TrackingSummary);
      if (actorsRes.status === "fulfilled") {
        const d = actorsRes.value.data;
        setActors(Array.isArray(d) ? d : (d?.actors ?? d?.items ?? []));
      }
      if (activeRes.status === "fulfilled") {
        const d = activeRes.value.data;
        setActive(Array.isArray(d) ? d : (d?.actors ?? d?.threats ?? []));
      }
      if (ttpRes.status === "fulfilled") {
        const d = ttpRes.value.data;
        setTTPs(Array.isArray(d) ? d : (d?.techniques ?? d?.ttps ?? []));
      }
      if (sumRes.status === "rejected" && actorsRes.status === "rejected") {
        throw new Error("Failed to load actor tracking data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4 animate-pulse">
        <div className="grid grid-cols-4 gap-3">
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

  if (!summary && actors.length === 0 && active.length === 0) {
    return (
      <EmptyState
        icon={Crosshair}
        title="No tracked actors"
        description="Track threat actors via POST /api/v1/actor-tracking/actors to begin activity monitoring."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Tracked",  value: summary.total_tracked ?? actors.length, color: "text-foreground" },
            { label: "Active Threats", value: summary.active_threats ?? active.length, color: "text-red-400" },
            { label: "High Threat",    value: summary.high_threat_count ?? 0, color: "text-orange-400" },
            { label: "Avg Activity",   value: summary.avg_activity_count?.toFixed(1) ?? "—", color: "text-sky-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Active threats banner */}
      {active.length > 0 && (
        <div className="rounded-lg border border-red-800/50 bg-red-900/10 p-3">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5 text-sm font-medium text-red-300">
              <Activity className="h-3.5 w-3.5" />
              Active Threats ({active.length})
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {active.slice(0, 10).map((a, i) => (
              <span
                key={a.actor_id ?? a.id ?? i}
                className="inline-flex items-center gap-1 rounded-full border border-red-700/40 bg-red-900/30 px-2.5 py-0.5 text-xs text-red-300"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                {a.name}
              </span>
            ))}
            {active.length > 10 && (
              <span className="text-xs text-muted-foreground self-center">+{active.length - 10} more</span>
            )}
          </div>
        </div>
      )}

      {/* Actor tracking table */}
      {actors.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5 text-indigo-400" />
              Tracked Actors ({actors.length})
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
                <th className="text-left px-4 py-2 font-medium">Actor</th>
                <th className="text-left px-4 py-2 font-medium">Type</th>
                <th className="text-left px-4 py-2 font-medium">Threat Level</th>
                <th className="text-left px-4 py-2 font-medium">Activity</th>
                <th className="text-left px-4 py-2 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {actors.slice(0, 50).map((a, i) => (
                <tr key={a.actor_id ?? a.id ?? i} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2.5 font-medium">{a.name}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground capitalize">{a.actor_type ?? "—"}</td>
                  <td className="px-4 py-2.5">
                    {a.threat_level ? (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${pill(a.threat_level)}`}>
                        {a.threat_level}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-xs font-mono text-sky-400">{a.activity_count ?? 0}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {a.last_seen ? new Date(a.last_seen).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* TTP summary */}
      {ttps.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-indigo-400" />
              Top TTPs Observed
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Technique ID</th>
                <th className="text-left px-4 py-2 font-medium">Name</th>
                <th className="text-left px-4 py-2 font-medium">Tactic</th>
                <th className="text-right px-4 py-2 font-medium">Actors</th>
              </tr>
            </thead>
            <tbody>
              {ttps.slice(0, 20).map((t, i) => (
                <tr key={t.technique_id ?? i} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs text-indigo-400">{t.technique_id ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">{t.technique_name ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground capitalize">{t.tactic ?? "—"}</td>
                  <td className="px-4 py-2 text-right text-xs font-semibold">{t.actor_count ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
