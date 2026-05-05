/**
 * PostureTrendsPanel — wires GET /api/v1/posture-trends/velocity-summary
 * and GET /api/v1/posture-trends/trends → per-metric trend list + targets.
 * Used by PostureMetricsHub "trends" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, TrendingUp, TrendingDown, Minus, Target, Activity } from "lucide-react";
import api from "@/lib/api";

interface VelocitySummary {
  avg_velocity_by_category?: Record<string, number>;
  fastest_improving?: Array<{ metric_name: string; velocity: number }>;
  fastest_declining?: Array<{ metric_name: string; velocity: number }>;
  total_metrics?: number;
  improving?: number;
  declining?: number;
  stable?: number;
}

interface TrendEntry {
  metric_name?: string;
  metric_category?: string;
  trend_label?: string;
  velocity?: number;
  prediction_30d?: number;
  last_value?: number;
  data_points?: number;
}

interface TrendTarget {
  metric_name?: string;
  target_value?: number;
  current_value?: number;
  gap?: number;
  on_track?: boolean;
  eta_days?: number;
}

function trendIcon(label?: string) {
  if (label === "improving") return <TrendingUp className="h-4 w-4 text-emerald-400" />;
  if (label === "declining") return <TrendingDown className="h-4 w-4 text-red-400" />;
  return <Minus className="h-4 w-4 text-muted-foreground" />;
}

function trendColor(label?: string) {
  if (label === "improving") return "text-emerald-400";
  if (label === "declining") return "text-red-400";
  return "text-muted-foreground";
}

function StatCard({
  label, value, icon: Icon, accent,
}: {
  label: string; value: string | number;
  icon: React.ComponentType<{ className?: string }>; accent: string;
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

export function PostureTrendsPanel() {
  const [summary, setSummary] = useState<VelocitySummary | null>(null);
  const [trends, setTrends] = useState<TrendEntry[]>([]);
  const [targets, setTargets] = useState<TrendTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<VelocitySummary>("/api/v1/posture-trends/velocity-summary").catch(() => null),
      api.get<TrendEntry[]>("/api/v1/posture-trends/trends").catch(() => null),
      api.get<TrendTarget[]>("/api/v1/posture-trends/targets").catch(() => null),
    ])
      .then(([summaryRes, trendsRes, targetsRes]) => {
        if (cancelled) return;
        if (summaryRes?.data) setSummary(summaryRes.data as VelocitySummary);
        const rawTrends = trendsRes?.data;
        setTrends(Array.isArray(rawTrends) ? (rawTrends as TrendEntry[]) : []);
        const rawTargets = targetsRes?.data;
        setTargets(Array.isArray(rawTargets) ? (rawTargets as TrendTarget[]) : []);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load trend data");
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />)}
        </div>
        <div className="h-64 rounded-xl border border-border/40 bg-muted/30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />{error}
      </div>
    );
  }

  const hasData = summary || trends.length > 0 || targets.length > 0;
  if (!hasData) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <TrendingUp className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No trend data yet</p>
        <p className="text-xs opacity-70">
          Record datapoints via POST /api/v1/posture-trends/datapoints to populate this view.
        </p>
      </div>
    );
  }

  const categoryVelocities = Object.entries(summary?.avg_velocity_by_category ?? {});

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Metrics" value={summary?.total_metrics ?? trends.length} icon={Activity} accent="text-indigo-400" />
        <StatCard label="Improving" value={summary?.improving ?? trends.filter(t => t.trend_label === "improving").length} icon={TrendingUp} accent="text-emerald-400" />
        <StatCard label="Declining" value={summary?.declining ?? trends.filter(t => t.trend_label === "declining").length} icon={TrendingDown} accent="text-red-400" />
        <StatCard label="Stable" value={summary?.stable ?? trends.filter(t => t.trend_label === "stable").length} icon={Minus} accent="text-muted-foreground" />
      </div>

      {categoryVelocities.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Avg Velocity by Category</p>
          </div>
          <div className="grid grid-cols-2 gap-0 divide-border/30 sm:grid-cols-4">
            {categoryVelocities.map(([cat, vel]) => (
              <div key={cat} className="flex flex-col gap-1 p-4 border-r border-b border-border/30 last:border-r-0">
                <p className="text-xs text-muted-foreground capitalize">{cat}</p>
                <p className={`text-lg font-bold ${vel > 0 ? "text-emerald-400" : vel < 0 ? "text-red-400" : "text-muted-foreground"}`}>
                  {vel > 0 ? "+" : ""}{vel.toFixed(1)}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      {trends.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Metric Trends ({trends.length})</p>
          </div>
          <div className="divide-y divide-border/30">
            {trends.slice(0, 20).map((t, i) => (
              <div key={t.metric_name ?? i} className="flex items-center gap-4 px-4 py-3 hover:bg-muted/20 transition-colors">
                {trendIcon(t.trend_label)}
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{t.metric_name ?? "Unknown"}</p>
                  {t.metric_category && <p className="text-xs text-muted-foreground capitalize">{t.metric_category}</p>}
                </div>
                <span className={`text-xs font-medium capitalize ${trendColor(t.trend_label)}`}>{t.trend_label ?? "—"}</span>
                {typeof t.velocity === "number" && (
                  <span className={`text-xs hidden sm:block ${t.velocity > 0 ? "text-emerald-400" : t.velocity < 0 ? "text-red-400" : "text-muted-foreground"}`}>
                    {t.velocity > 0 ? "+" : ""}{t.velocity.toFixed(2)}/d
                  </span>
                )}
                {typeof t.last_value === "number" && (
                  <span className="text-xs text-muted-foreground w-10 text-right">{t.last_value.toFixed(1)}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {targets.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Posture Targets</p>
          </div>
          <div className="divide-y divide-border/30">
            {targets.slice(0, 10).map((tgt, i) => {
              const progress = tgt.target_value && tgt.current_value != null
                ? Math.min(100, (tgt.current_value / tgt.target_value) * 100)
                : 0;
              return (
                <div key={tgt.metric_name ?? i} className="flex items-center gap-4 px-4 py-3 hover:bg-muted/20 transition-colors">
                  <Target className={`h-4 w-4 shrink-0 ${tgt.on_track ? "text-emerald-400" : "text-amber-400"}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{tgt.metric_name ?? "Unknown"}</p>
                    <div className="flex items-center gap-2 mt-1">
                      <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${tgt.on_track ? "bg-emerald-500" : "bg-amber-400"}`}
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                      <span className="text-xs text-muted-foreground">{tgt.current_value?.toFixed(1)} / {tgt.target_value?.toFixed(1)}</span>
                    </div>
                  </div>
                  {typeof tgt.eta_days === "number" && (
                    <span className="text-xs text-muted-foreground hidden sm:block">{tgt.eta_days}d ETA</span>
                  )}
                  <span className={`text-xs font-medium ${tgt.on_track ? "text-emerald-400" : "text-amber-400"}`}>
                    {tgt.on_track ? "On track" : "At risk"}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
