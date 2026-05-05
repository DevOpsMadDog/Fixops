/**
 * ThreatActorsPanel — wires GET /api/v1/threat-actors/actors + /stats
 * Used by ThreatActorsHub "actors" tab.
 */

import { useEffect, useState } from "react";
import { UserCog, AlertTriangle, Shield, Activity } from "lucide-react";
import { threatActorsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface Actor {
  actor_id?: string;
  id?: string;
  name: string;
  actor_type: string;
  origin_country: string;
  motivation: string;
  sophistication: string;
  threat_score?: number;
  active: boolean;
  aliases?: string[];
  mitre_group_id?: string;
}

interface ActorStats {
  total_actors?: number;
  active_actors?: number;
  by_type?: Record<string, number>;
  avg_threat_score?: number;
}

const SOPH_COLOR: Record<string, string> = {
  advanced: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-red-500/15 text-red-400 border-red-500/30",
  moderate: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-orange-500/15 text-orange-400 border-orange-500/30",
  basic:    "bg-green-500/15 text-green-400 border-green-500/30",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

export function ThreatActorsPanel() {
  const [actors, setActors] = useState<Actor[]>([]);
  const [stats, setStats] = useState<ActorStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      threatActorsApi.list().catch(() => ({ data: [] })),
      threatActorsApi.stats().catch(() => ({ data: {} })),
    ])
      .then(([actorsRes, statsRes]) => {
        if (cancelled) return;
        const raw = actorsRes.data;
        setActors(Array.isArray(raw) ? raw : (raw?.actors ?? raw?.items ?? []));
        setStats(statsRes.data ?? {});
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load threat actors");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="space-y-2 animate-pulse">
        <div className="grid grid-cols-3 gap-3">
          {[...Array(3)].map((_, i) => <div key={i} className="h-20 rounded-lg bg-muted/50" />)}
        </div>
        {[...Array(5)].map((_, i) => <div key={i} className="h-12 rounded-lg bg-muted/40" />)}
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

  if (actors.length === 0) {
    return (
      <EmptyState
        icon={UserCog}
        title="No threat actors tracked"
        description="Import MITRE ATT&CK groups or add actors manually to begin tracking."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <UserCog className="h-3.5 w-3.5" /> Total Actors
          </div>
          <p className="text-2xl font-bold">{stats.total_actors ?? actors.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Activity className="h-3.5 w-3.5 text-green-400" /> Active
          </div>
          <p className="text-2xl font-bold text-green-400">
            {stats.active_actors ?? actors.filter(a => a.active).length}
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Shield className="h-3.5 w-3.5 text-amber-400" /> Avg Threat Score
          </div>
          <p className="text-2xl font-bold text-amber-400">
            {stats.avg_threat_score !== undefined
              ? stats.avg_threat_score.toFixed(1)
              : "—"}
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Actor</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Country</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Motivation</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Sophistication</th>
              <th className="text-right px-4 py-2 font-medium text-muted-foreground">Score</th>
            </tr>
          </thead>
          <tbody>
            {actors.slice(0, 50).map((a, i) => (
              <tr
                key={a.actor_id ?? a.id ?? i}
                className="border-b border-border/50 hover:bg-muted/20 transition-colors"
              >
                <td className="px-4 py-2.5 font-medium">
                  {a.name}
                  {a.active && (
                    <span className="ml-1.5 inline-block h-1.5 w-1.5 rounded-full bg-green-400" />
                  )}
                </td>
                <td className="px-4 py-2.5 text-muted-foreground capitalize">{a.actor_type}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{a.origin_country || "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground capitalize">{a.motivation || "—"}</td>
                <td className="px-4 py-2.5">
                  <Badge className={`text-xs ${SOPH_COLOR[a.sophistication] ?? "bg-muted/30"}`}>
                    {a.sophistication}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 text-right font-mono text-amber-400">
                  {a.threat_score !== undefined ? a.threat_score.toFixed(1) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
