/**
 * BUHeatmapPanel — wires GET /api/v1/fair/business-units + /api/v1/fair/stats
 * Renders per-BU FAIR ALE heatmap with stat summary.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, DollarSign, TrendingUp, Building2 } from "lucide-react";
import { fairApi } from "@/lib/api";

interface BusinessUnit {
  bu_id: string;
  name: string;
  total_ale?: number;
  risk_level?: string;
  finding_count?: number;
}

interface FAIRStats {
  business_unit_count: number;
  cumulative_ale_reduced_90d: number;
  cumulative_fix_cost_90d: number;
  roi_pct_90d: number;
}

function fmt$(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

const RISK_COLOR: Record<string, string> = {
  critical: "bg-red-600/80 border-red-500",
  high: "bg-orange-500/80 border-orange-400",
  medium: "bg-amber-400/80 border-amber-300",
  low: "bg-emerald-500/80 border-emerald-400",
};

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

export function BUHeatmapPanel() {
  const [bus, setBus] = useState<BusinessUnit[]>([]);
  const [stats, setStats] = useState<FAIRStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([fairApi.businessUnits(), fairApi.stats()])
      .then(([buRes, statsRes]) => {
        if (cancelled) return;
        const buData = buRes.data;
        const units: BusinessUnit[] =
          Array.isArray(buData?.business_units) ? buData.business_units :
          Array.isArray(buData) ? buData : [];
        setBus(units);
        setStats(statsRes.data as FAIRStats);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load FAIR data");
        }
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
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

  if (!bus.length) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Building2 className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No business units found</p>
        <p className="text-xs opacity-70">
          Business units are seeded on first FAIR risk compute. POST to
          /api/v1/fair/per-bu-risk to initialise.
        </p>
      </div>
    );
  }

  const maxAle = Math.max(...bus.map(b => b.total_ale ?? 0), 1);

  return (
    <div className="flex flex-col gap-6">
      {stats && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Business Units" value={String(stats.business_unit_count)} icon={Building2} accent="text-indigo-400" />
          <StatCard label="ALE Reduced (90d)" value={fmt$(stats.cumulative_ale_reduced_90d)} icon={TrendingUp} accent="text-emerald-400" />
          <StatCard label="Fix Cost (90d)" value={fmt$(stats.cumulative_fix_cost_90d)} icon={DollarSign} accent="text-sky-400" />
          <StatCard label="ROI (90d)" value={`${stats.roi_pct_90d.toFixed(1)}%`} icon={TrendingUp} accent="text-amber-400" />
        </div>
      )}

      <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
        <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          ALE Exposure by Business Unit
        </p>
        <div className="flex flex-col gap-3">
          {bus.map(bu => {
            const ale = bu.total_ale ?? 0;
            const pct = Math.round((ale / maxAle) * 100);
            const level = bu.risk_level?.toLowerCase() ?? "low";
            const barClass = RISK_COLOR[level] ?? "bg-slate-500/70 border-slate-400";
            return (
              <div key={bu.bu_id} className="flex items-center gap-3">
                <span className="w-32 shrink-0 truncate text-xs font-medium text-foreground">
                  {bu.name ?? bu.bu_id}
                </span>
                <div className="flex-1 h-6 rounded bg-muted/30 overflow-hidden">
                  <div
                    className={`h-full rounded border ${barClass} transition-all duration-500`}
                    style={{ width: `${Math.max(pct, 2)}%` }}
                  />
                </div>
                <span className="w-20 shrink-0 text-right text-xs text-muted-foreground">
                  {fmt$(ale)}
                </span>
                {bu.risk_level && (
                  <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase text-white ${RISK_COLOR[level]?.split(" ")[0] ?? "bg-slate-500"}`}>
                    {bu.risk_level}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
