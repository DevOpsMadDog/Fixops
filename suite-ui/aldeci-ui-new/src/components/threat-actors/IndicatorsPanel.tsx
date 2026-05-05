/**
 * IndicatorsPanel — wires GET /api/v1/threat-indicators/indicators + /summary
 * Used by ThreatActorsHub "indicators" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Activity, ShieldAlert, Tag } from "lucide-react";
import { threatIndicatorsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface Indicator {
  indicator_id?: string;
  id?: string;
  indicator_value?: string;
  value?: string;
  indicator_type?: string;
  type?: string;
  severity: string;
  confidence?: number;
  source?: string;
  tlp?: string;
  sighting_count?: number;
  tags?: string[];
  expiry_at?: string | null;
}

interface IndicatorSummary {
  total_active?: number;
  total?: number;
  by_type?: Record<string, number>;
  by_severity?: Record<string, number>;
  high_confidence_count?: number;
}

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-amber-500/15 text-amber-400 border-amber-500/30",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

const TLP_COLOR: Record<string, string> = {
  red:    "bg-red-500/20 text-red-300",
  amber:  "bg-amber-500/20 text-amber-300",
  green:  "bg-green-500/20 text-green-300",
  white:  "bg-slate-500/20 text-slate-300",
  clear:  "bg-slate-500/20 text-slate-300",
};

export function IndicatorsPanel() {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [summary, setSummary] = useState<IndicatorSummary>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      threatIndicatorsApi.list().catch(() => ({ data: [] })),
      threatIndicatorsApi.summary().catch(() => ({ data: {} })),
    ])
      .then(([indRes, sumRes]) => {
        if (cancelled) return;
        const raw = indRes.data;
        setIndicators(Array.isArray(raw) ? raw : (raw?.indicators ?? raw?.items ?? []));
        setSummary(sumRes.data ?? {});
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load indicators");
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

  if (indicators.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No active indicators"
        description="Add IOCs, TTPs, or infrastructure markers to start tracking threat indicators."
      />
    );
  }

  const totalActive = summary.total_active ?? summary.total ?? indicators.length;
  const criticalCount = summary.by_severity?.critical ??
    indicators.filter(i => i.severity === "critical").length;
  const highCount = summary.by_severity?.high ??
    indicators.filter(i => i.severity === "high").length;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Activity className="h-3.5 w-3.5" /> Active Indicators
          </div>
          <p className="text-2xl font-bold">{totalActive}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <AlertTriangle className="h-3.5 w-3.5 text-red-400" /> Critical
          </div>
          <p className="text-2xl font-bold text-red-400">{criticalCount}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Tag className="h-3.5 w-3.5 text-orange-400" /> High
          </div>
          <p className="text-2xl font-bold text-orange-400">{highCount}</p>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Value</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Severity</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">TLP</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Source</th>
              <th className="text-right px-4 py-2 font-medium text-muted-foreground">Sightings</th>
            </tr>
          </thead>
          <tbody>
            {indicators.slice(0, 50).map((ind, i) => {
              const val = ind.indicator_value ?? ind.value ?? "—";
              const type = ind.indicator_type ?? ind.type ?? "—";
              const tlp = (ind.tlp ?? "amber").toLowerCase();
              return (
                <tr
                  key={ind.indicator_id ?? ind.id ?? i}
                  className="border-b border-border/50 hover:bg-muted/20 transition-colors"
                >
                  <td className="px-4 py-2.5 font-mono text-xs max-w-[200px] truncate">{val}</td>
                  <td className="px-4 py-2.5 text-muted-foreground capitalize">{type}</td>
                  <td className="px-4 py-2.5">
                    <Badge className={`text-xs ${SEV_COLOR[ind.severity] ?? "bg-muted/30"}`}>
                      {ind.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`rounded px-1.5 py-0.5 text-xs font-medium uppercase ${TLP_COLOR[tlp] ?? "bg-muted/20"}`}>
                      {tlp}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground text-xs">{ind.source || "—"}</td>
                  <td className="px-4 py-2.5 text-right text-muted-foreground">
                    {ind.sighting_count ?? 0}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
