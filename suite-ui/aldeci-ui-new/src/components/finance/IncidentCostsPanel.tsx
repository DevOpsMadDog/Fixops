/**
 * IncidentCostsPanel — wires GET /api/v1/incident-costs/analytics + /summaries
 * Shows per-incident cost analytics and finalized incident ledger.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, DollarSign, Flame, BarChart2 } from "lucide-react";
import { incidentCostsApi } from "@/lib/api";

interface CostAnalytics {
  total_incidents: number;
  total_cost: number;
  avg_cost_per_incident: number;
  by_category: Record<string, number>;
  by_type: Record<string, number>;
}

interface IncidentSummary {
  incident_id: string;
  incident_name?: string;
  incident_type?: string;
  severity?: string;
  total_cost?: number;
  finalized_at?: string;
}

function fmt$(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(1)}K`;
  return `$${n.toFixed(0)}`;
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-emerald-400",
};

export function IncidentCostsPanel() {
  const [analytics, setAnalytics] = useState<CostAnalytics | null>(null);
  const [summaries, setSummaries] = useState<IncidentSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([incidentCostsApi.analytics(), incidentCostsApi.summaries()])
      .then(([analyticsRes, summaryRes]) => {
        if (cancelled) return;
        setAnalytics(analyticsRes.data as CostAnalytics);
        const d = summaryRes.data;
        const rows: IncidentSummary[] =
          Array.isArray(d?.summaries) ? d.summaries :
          Array.isArray(d) ? d : [];
        setSummaries(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load incident cost data");
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />
          ))}
        </div>
        <div className="h-48 rounded-xl border border-border/40 bg-muted/30" />
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

  const totalIncidents = analytics?.total_incidents ?? 0;

  if (totalIncidents === 0 && summaries.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <DollarSign className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No incident cost records yet</p>
        <p className="text-xs opacity-70">
          Record a cost via POST /api/v1/incident-costs/costs.
        </p>
      </div>
    );
  }

  const byCategory = analytics?.by_category ?? {};
  const categoryEntries = Object.entries(byCategory).sort(([, a], [, b]) => b - a);

  return (
    <div className="flex flex-col gap-6">
      {analytics && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
          <StatCard label="Total Incidents" value={String(totalIncidents)} icon={Flame} accent="text-red-400" />
          <StatCard label="Total Cost" value={fmt$(analytics.total_cost)} icon={DollarSign} accent="text-indigo-400" />
          <StatCard label="Avg Cost / Incident" value={fmt$(analytics.avg_cost_per_incident)} icon={BarChart2} accent="text-sky-400" />
        </div>
      )}

      {categoryEntries.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Cost by Category
          </p>
          <div className="flex flex-col gap-2">
            {categoryEntries.map(([cat, cost]) => {
              const maxCost = categoryEntries[0]?.[1] ?? 1;
              const pct = Math.round(((cost as number) / maxCost) * 100);
              return (
                <div key={cat} className="flex items-center gap-3">
                  <span className="w-36 shrink-0 capitalize text-xs text-foreground truncate">{cat.replace(/_/g, " ")}</span>
                  <div className="flex-1 h-5 rounded bg-muted/30 overflow-hidden">
                    <div
                      className="h-full rounded bg-indigo-500/70 transition-all duration-500"
                      style={{ width: `${Math.max(pct, 2)}%` }}
                    />
                  </div>
                  <span className="w-20 shrink-0 text-right text-xs font-mono text-muted-foreground">
                    {fmt$(cost as number)}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {summaries.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <p className="px-4 pt-4 pb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Recent Incidents
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 text-xs text-muted-foreground uppercase tracking-wider">
                  <th className="px-4 py-2 text-left font-medium">Incident</th>
                  <th className="px-4 py-2 text-left font-medium">Type</th>
                  <th className="px-4 py-2 text-left font-medium">Severity</th>
                  <th className="px-4 py-2 text-right font-medium">Total Cost</th>
                </tr>
              </thead>
              <tbody>
                {summaries.slice(0, 20).map(s => (
                  <tr key={s.incident_id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 font-medium text-foreground truncate max-w-[200px]">
                      {s.incident_name ?? s.incident_id}
                    </td>
                    <td className="px-4 py-2.5 capitalize text-muted-foreground">{s.incident_type ?? "—"}</td>
                    <td className={`px-4 py-2.5 font-semibold capitalize ${SEV_COLOR[s.severity?.toLowerCase() ?? ""] ?? "text-muted-foreground"}`}>
                      {s.severity ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-foreground">
                      {s.total_cost != null ? fmt$(s.total_cost) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
