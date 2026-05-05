/**
 * PostureScorePanel — posture tab for StrategicPostureHub
 * Fetches /api/v1/posture-score/stats, /components, /history
 * Real data only — no mocks.
 */

import { useCallback, useEffect, useState } from "react";
import {
  Shield,
  TrendingUp,
  TrendingDown,
  Minus,
  RefreshCw,
  AlertCircle,
} from "lucide-react";
import { postureScoreApi, type PostureStats, type PostureComponent } from "@/lib/api";

const GRADE_COLOR: Record<string, string> = {
  A: "text-green-400",
  B: "text-lime-400",
  C: "text-amber-400",
  D: "text-orange-500",
  F: "text-red-500",
};

function ScoreMeter({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color =
    pct >= 80 ? "bg-green-500" : pct >= 60 ? "bg-amber-400" : "bg-red-500";
  return (
    <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-700 ${color}`}
        style={{ width: `${pct}%` }}
      />
    </div>
  );
}

function TrendIcon({ trend }: { trend?: number | null }) {
  if (trend == null) return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
  if (trend > 0) return <TrendingUp className="h-3.5 w-3.5 text-green-500" />;
  if (trend < 0) return <TrendingDown className="h-3.5 w-3.5 text-red-500" />;
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
}

export function PostureScorePanel() {
  const [stats, setStats] = useState<PostureStats | null>(null);
  const [components, setComponents] = useState<PostureComponent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      postureScoreApi.stats(),
      postureScoreApi.components(),
    ])
      .then(([statsRes, compRes]) => {
        setStats(statsRes.data ?? null);
        setComponents(Array.isArray(compRes.data) ? compRes.data : []);
      })
      .catch((err: { response?: { data?: { detail?: string } }; message?: string }) => {
        setError(err?.response?.data?.detail ?? err?.message ?? "Failed to load posture data");
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="flex flex-col gap-6">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Security posture score across all domains — source: /api/v1/posture-score
        </p>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
          aria-label="Refresh posture score"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error && !loading && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {loading && (
        <div className="space-y-3">
          <div className="h-28 animate-pulse rounded-xl bg-muted/40" />
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-20 animate-pulse rounded-xl bg-muted/40" />
            ))}
          </div>
          <div className="h-48 animate-pulse rounded-xl bg-muted/40" />
        </div>
      )}

      {!loading && !error && !stats && (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-16 text-center">
          <Shield className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">No posture score yet</p>
          <p className="text-xs text-muted-foreground/60">
            POST /api/v1/posture-score/compute to generate the first score.
          </p>
        </div>
      )}

      {!loading && stats && (
        <>
          {/* Hero score card */}
          <div className="rounded-xl border border-border/60 bg-card p-6 flex flex-col sm:flex-row items-center gap-6">
            <div className="flex flex-col items-center gap-1 shrink-0">
              <div className="text-6xl font-bold tabular-nums text-foreground">
                {Math.round(stats.current_score ?? 0)}
              </div>
              <div className={`text-2xl font-semibold ${GRADE_COLOR[stats.grade ?? ""] ?? "text-muted-foreground"}`}>
                Grade {stats.grade ?? "—"}
              </div>
              <div className="text-xs text-muted-foreground">out of 100</div>
            </div>
            <div className="flex-1 flex flex-col gap-3 w-full">
              <ScoreMeter score={stats.current_score ?? 0} />
              <div className="grid grid-cols-2 gap-4 text-xs sm:grid-cols-3">
                <div>
                  <p className="text-muted-foreground">30-day trend</p>
                  <div className="flex items-center gap-1 mt-0.5">
                    <TrendIcon trend={stats.trend_30d} />
                    <span className={`font-semibold ${(stats.trend_30d ?? 0) >= 0 ? "text-green-400" : "text-red-400"}`}>
                      {stats.trend_30d != null
                        ? `${stats.trend_30d > 0 ? "+" : ""}${stats.trend_30d.toFixed(1)}`
                        : "—"}
                    </span>
                  </div>
                </div>
                <div>
                  <p className="text-muted-foreground">Days at risk</p>
                  <p className="font-semibold text-foreground mt-0.5">
                    {stats.days_at_risk ?? "—"}
                  </p>
                </div>
                <div>
                  <p className="text-muted-foreground">Last computed</p>
                  <p className="font-semibold text-foreground mt-0.5 truncate">
                    {stats.computed_at
                      ? new Date(stats.computed_at).toLocaleDateString()
                      : "—"}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Component breakdown */}
          {components.length > 0 && (
            <div className="flex flex-col gap-2">
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Domain Breakdown
              </p>
              <div className="overflow-x-auto rounded-xl border border-border/60">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/60 bg-muted/30 text-left text-muted-foreground">
                      <th className="px-3 py-2.5 font-medium">Component</th>
                      <th className="px-3 py-2.5 font-medium">Score</th>
                      <th className="px-3 py-2.5 font-medium w-40">Progress</th>
                      <th className="px-3 py-2.5 font-medium">Weight</th>
                      <th className="px-3 py-2.5 font-medium">Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40">
                    {components.map((c) => (
                      <tr key={c.name} className="bg-card hover:bg-muted/20 transition-colors">
                        <td className="px-3 py-2 font-medium text-foreground capitalize">
                          {c.name.replace(/_/g, " ")}
                        </td>
                        <td className="px-3 py-2 tabular-nums text-foreground">
                          {c.score ?? 0}
                        </td>
                        <td className="px-3 py-2 w-40">
                          <ScoreMeter score={c.score ?? 0} />
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">
                          {c.weight != null ? `${(c.weight * 100).toFixed(0)}%` : "—"}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">{c.source || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
