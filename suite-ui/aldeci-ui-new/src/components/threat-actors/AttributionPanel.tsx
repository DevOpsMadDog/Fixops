/**
 * AttributionPanel — wires GET /api/v1/threat-attribution/attributions + /stats
 * Used by ThreatActorsHub "attribution" tab.
 */

import { useEffect, useState } from "react";
import { Fingerprint, AlertTriangle, CheckCircle2, Clock } from "lucide-react";
import { threatAttributionApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface Attribution {
  attribution_id?: string;
  id?: string;
  incident_id: string;
  actor_id?: string;
  confidence: string;
  status: string;
  analyst?: string;
  attribution_date?: string;
  notes?: string;
}

interface AttributionStats {
  total_attributions?: number;
  confirmed?: number;
  investigating?: number;
  by_confidence?: Record<string, number>;
}

const CONF_COLOR: Record<string, string> = {
  confirmed: "bg-green-500/15 text-green-400 border-green-500/30",
  likely:    "bg-blue-500/15 text-blue-400 border-blue-500/30",
  possible:  "bg-amber-500/15 text-amber-400 border-amber-500/30",
  unlikely:  "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

const STATUS_COLOR: Record<string, string> = {
  attributed:    "bg-green-500/15 text-green-400 border-green-500/30",
  investigating: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  disputed:      "bg-orange-500/15 text-orange-400 border-orange-500/30",
  closed:        "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

export function AttributionPanel() {
  const [attributions, setAttributions] = useState<Attribution[]>([]);
  const [stats, setStats] = useState<AttributionStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      threatAttributionApi.listAttributions().catch(() => ({ data: [] })),
      threatAttributionApi.stats().catch(() => ({ data: {} })),
    ])
      .then(([attrRes, statsRes]) => {
        if (cancelled) return;
        const raw = attrRes.data;
        setAttributions(Array.isArray(raw) ? raw : (raw?.attributions ?? raw?.items ?? []));
        setStats(statsRes.data ?? {});
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load attributions");
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
        {[...Array(4)].map((_, i) => <div key={i} className="h-12 rounded-lg bg-muted/40" />)}
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

  if (attributions.length === 0) {
    return (
      <EmptyState
        icon={Fingerprint}
        title="No attributions recorded"
        description="Link incidents to threat actor profiles to build attribution chains."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Fingerprint className="h-3.5 w-3.5" /> Total
          </div>
          <p className="text-2xl font-bold">{stats.total_attributions ?? attributions.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <CheckCircle2 className="h-3.5 w-3.5 text-green-400" /> Confirmed
          </div>
          <p className="text-2xl font-bold text-green-400">
            {stats.confirmed ??
              attributions.filter(a => a.confidence === "confirmed" || a.status === "attributed").length}
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Clock className="h-3.5 w-3.5 text-blue-400" /> Investigating
          </div>
          <p className="text-2xl font-bold text-blue-400">
            {stats.investigating ??
              attributions.filter(a => a.status === "investigating").length}
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Incident</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Confidence</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Analyst</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Date</th>
            </tr>
          </thead>
          <tbody>
            {attributions.slice(0, 50).map((a, i) => (
              <tr
                key={a.attribution_id ?? a.id ?? i}
                className="border-b border-border/50 hover:bg-muted/20 transition-colors"
              >
                <td className="px-4 py-2.5 font-mono text-xs">{a.incident_id}</td>
                <td className="px-4 py-2.5">
                  <Badge className={`text-xs ${STATUS_COLOR[a.status] ?? "bg-muted/30"}`}>
                    {a.status}
                  </Badge>
                </td>
                <td className="px-4 py-2.5">
                  <Badge className={`text-xs ${CONF_COLOR[a.confidence] ?? "bg-muted/30"}`}>
                    {a.confidence}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">{a.analyst || "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground text-xs">
                  {a.attribution_date
                    ? new Date(a.attribution_date).toLocaleDateString()
                    : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
