/**
 * MetricsPanel — AwarenessHub "metrics" tab
 *
 * Wired to real backend:
 *   GET /api/v1/awareness-metrics/stats          → KPI bar
 *   GET /api/v1/awareness-metrics/metrics/latest → latest metric snapshot
 *   GET /api/v1/awareness-metrics/metrics/trend  → trend list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { BarChart3, TrendingUp, TrendingDown, Activity, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";

interface AwarenessStats {
  total_metrics?: number;
  avg_phishing_click_rate?: number;
  avg_training_completion?: number;
  improvement_rate?: number;
}

interface MetricEntry {
  metric_id?: string;
  org_id?: string;
  period?: string;
  phishing_click_rate?: number;
  training_completion_rate?: number;
  repeat_clicker_rate?: number;
  reported_phishing_rate?: number;
  recorded_at?: string;
}

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["metrics", "trend", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

function pct(v: number | undefined) {
  return v != null ? `${(v * 100).toFixed(1)}%` : "—";
}

export default function MetricsPanel() {
  const [stats, setStats] = useState<AwarenessStats | null>(null);
  const [latest, setLatest] = useState<MetricEntry | null>(null);
  const [trend, setTrend] = useState<MetricEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawLatest, rawTrend] = await Promise.all([
        apiFetch<AwarenessStats>("/api/v1/awareness-metrics/stats"),
        apiFetch<MetricEntry>("/api/v1/awareness-metrics/metrics/latest"),
        apiFetch<unknown>("/api/v1/awareness-metrics/metrics/trend"),
      ]);
      setStats(rawStats);
      setLatest(rawLatest);
      setTrend(extractArray<MetricEntry>(rawTrend));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load metrics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Snapshots", value: stats?.total_metrics ?? 0, icon: Activity, color: "text-indigo-400" },
    {
      label: "Avg Click Rate",
      value: stats?.avg_phishing_click_rate != null ? `${(stats.avg_phishing_click_rate * 100).toFixed(1)}%` : "—",
      icon: TrendingDown,
      color: "text-red-400",
    },
    {
      label: "Avg Completion",
      value: stats?.avg_training_completion != null ? `${(stats.avg_training_completion * 100).toFixed(1)}%` : "—",
      icon: TrendingUp,
      color: "text-emerald-400",
    },
    {
      label: "Improvement Rate",
      value: stats?.improvement_rate != null ? `${(stats.improvement_rate * 100).toFixed(1)}%` : "—",
      icon: BarChart3,
      color: "text-sky-400",
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Awareness Metrics</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      {latest && (
        <div className="rounded-lg border border-border bg-muted/20 px-4 py-3">
          <p className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wide">Latest Snapshot</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-muted-foreground">Phishing Click Rate</p>
              <p className="font-semibold text-red-400">{pct(latest.phishing_click_rate)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Training Completion</p>
              <p className="font-semibold text-emerald-400">{pct(latest.training_completion_rate)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Repeat Clickers</p>
              <p className="font-semibold text-orange-400">{pct(latest.repeat_clicker_rate)}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Reported Phishing</p>
              <p className="font-semibold text-sky-400">{pct(latest.reported_phishing_rate)}</p>
            </div>
          </div>
        </div>
      )}

      {trend.length === 0 ? (
        <EmptyState icon={BarChart3} title="No trend data" description="Awareness metrics will appear after recording periodic snapshots." />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Period", "Click Rate", "Completion", "Repeat Clickers", "Reported", "Recorded"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {trend.slice(0, 200).map((m, i) => (
                <tr key={m.metric_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-medium">{m.period ?? "—"}</td>
                  <td className="px-3 py-2 text-red-400 tabular-nums">{pct(m.phishing_click_rate)}</td>
                  <td className="px-3 py-2 text-emerald-400 tabular-nums">{pct(m.training_completion_rate)}</td>
                  <td className="px-3 py-2 text-orange-400 tabular-nums">{pct(m.repeat_clicker_rate)}</td>
                  <td className="px-3 py-2 text-sky-400 tabular-nums">{pct(m.reported_phishing_rate)}</td>
                  <td className="px-3 py-2 text-muted-foreground">{m.recorded_at ? new Date(m.recorded_at).toLocaleDateString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
