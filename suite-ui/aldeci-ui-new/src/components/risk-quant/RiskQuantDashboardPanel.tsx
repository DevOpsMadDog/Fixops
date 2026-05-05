/**
 * RiskQuantDashboardPanel — wires /api/v1/risk-quantifier/portfolio + heatmap + roi
 * Used by RiskQuantHub "dashboard" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BarChart3, DollarSign, TrendingUp } from "lucide-react";
import { riskQuantApi } from "@/lib/api";

interface Portfolio {
  total_ale: number;
  scenario_count: number;
  tier_breakdown?: Record<string, number>;
  top_risks?: Array<{ name?: string; ale_p50?: number; risk_tier?: string }>;
}

interface ROIData {
  total_investment: number;
  total_risk_reduction: number;
  net_benefit: number;
  roi_percentage: number;
  payback_period_months?: number;
}

interface HeatmapData {
  matrix?: Array<Array<{ count: number; cumulative_ale: number }>>;
  probability_bands?: string[];
  loss_bands?: string[];
}

const TIER_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-green-400",
};

function fmt(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

export function RiskQuantDashboardPanel() {
  const [portfolio, setPortfolio] = useState<Portfolio | null>(null);
  const [roi, setRoi] = useState<ROIData | null>(null);
  const [heatmap, setHeatmap] = useState<HeatmapData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      riskQuantApi.portfolio(),
      riskQuantApi.roi(),
      riskQuantApi.heatmap(),
    ])
      .then(([portRes, roiRes, hmRes]) => {
        if (cancelled) return;
        setPortfolio(portRes.data as Portfolio);
        setRoi(roiRes.data as ROIData);
        setHeatmap(hmRes.data as HeatmapData);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load dashboard data");
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
        <div className="h-56 rounded-xl border border-border/40 bg-muted/30" />
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

  if (!portfolio) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <BarChart3 className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No portfolio data yet</p>
        <p className="text-xs opacity-70">Add risk scenarios to see Monte Carlo quantification results.</p>
      </div>
    );
  }

  const tierBreakdown = portfolio.tier_breakdown ?? {};
  const topRisks = portfolio.top_risks ?? [];

  return (
    <div className="flex flex-col gap-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
            <DollarSign className="h-4 w-4 text-red-400" />Total ALE
          </div>
          <p className="text-2xl font-bold text-foreground">{fmt(portfolio.total_ale ?? 0)}</p>
        </div>
        <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
            <BarChart3 className="h-4 w-4 text-indigo-400" />Scenarios
          </div>
          <p className="text-2xl font-bold text-foreground">{portfolio.scenario_count ?? 0}</p>
        </div>
        <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
            <TrendingUp className="h-4 w-4 text-green-400" />ROI
          </div>
          <p className="text-2xl font-bold text-foreground">
            {roi ? `${roi.roi_percentage?.toFixed(0)}%` : "—"}
          </p>
        </div>
        <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
            <DollarSign className="h-4 w-4 text-sky-400" />Net Benefit
          </div>
          <p className="text-2xl font-bold text-foreground">
            {roi ? fmt(roi.net_benefit ?? 0) : "—"}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Tier breakdown */}
        {Object.keys(tierBreakdown).length > 0 && (
          <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Risk Tier Breakdown</p>
            <div className="flex flex-col gap-2">
              {Object.entries(tierBreakdown).map(([tier, count]) => (
                <div key={tier} className="flex items-center justify-between text-sm">
                  <span className={`font-semibold capitalize ${TIER_COLOR[tier] ?? "text-foreground"}`}>{tier}</span>
                  <div className="flex items-center gap-3">
                    <div className="w-32 h-2 rounded-full bg-muted/40 overflow-hidden">
                      <div
                        className={`h-2 rounded-full transition-all duration-500 ${tier === "critical" ? "bg-red-500" : tier === "high" ? "bg-orange-500" : tier === "medium" ? "bg-amber-400" : "bg-green-500"}`}
                        style={{ width: `${Math.min(100, (count / Math.max(...Object.values(tierBreakdown), 1)) * 100)}%` }}
                      />
                    </div>
                    <span className="text-muted-foreground w-6 text-right">{count}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Top risks */}
        {topRisks.length > 0 && (
          <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
            <div className="border-b border-border/60 px-4 py-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Top Risks by ALE</p>
            </div>
            <div className="divide-y divide-border/40">
              {topRisks.slice(0, 6).map((r, i) => (
                <div key={i} className="flex items-center justify-between px-4 py-2.5 text-sm hover:bg-muted/20 transition-colors">
                  <span className="text-foreground font-medium truncate">{r.name ?? `Scenario ${i + 1}`}</span>
                  <div className="flex items-center gap-3 shrink-0 ml-2">
                    {r.risk_tier && (
                      <span className={`text-xs font-semibold capitalize ${TIER_COLOR[r.risk_tier] ?? "text-foreground"}`}>
                        {r.risk_tier}
                      </span>
                    )}
                    <span className="text-xs font-bold text-red-400">{fmt(r.ale_p50 ?? 0)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Heatmap */}
      {heatmap?.matrix && heatmap.probability_bands && heatmap.loss_bands && (
        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Probability × Impact Heatmap
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs border-collapse">
              <thead>
                <tr>
                  <th className="text-left text-muted-foreground font-medium py-1 pr-2">Prob \ Loss</th>
                  {heatmap.loss_bands.map((band) => (
                    <th key={band} className="text-center text-muted-foreground font-medium py-1 px-1">{band}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {heatmap.matrix.map((row, ri) => (
                  <tr key={ri}>
                    <td className="text-muted-foreground font-medium py-1 pr-2 whitespace-nowrap">
                      {heatmap.probability_bands![ri]}
                    </td>
                    {row.map((cell, ci) => {
                      const intensity = cell.count > 0 ? Math.min(1, cell.count / 5) : 0;
                      return (
                        <td key={ci} className="py-1 px-1 text-center">
                          <div
                            className="rounded w-full flex items-center justify-center text-xs font-bold transition-colors"
                            style={{
                              minWidth: 32,
                              height: 28,
                              backgroundColor: cell.count > 0
                                ? `rgba(239,68,68,${0.15 + intensity * 0.65})`
                                : "transparent",
                              color: cell.count > 0 ? (intensity > 0.5 ? "#fff" : "#ef4444") : "#6b7280",
                            }}
                            title={cell.count > 0 ? `${cell.count} scenarios · ${fmt(cell.cumulative_ale)} ALE` : "No scenarios"}
                          >
                            {cell.count > 0 ? cell.count : "·"}
                          </div>
                        </td>
                      );
                    })}
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
