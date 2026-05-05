import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { assetRiskApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface AssetScore {
  asset_id: string;
  asset_name?: string;
  asset_type?: string;
  criticality?: string;
  composite_score?: number;
  risk_level?: string;
  calculated_at?: string;
}

interface RiskStats {
  total_assets?: number;
  total_scores?: number;
  by_risk_level?: Record<string, number>;
  avg_composite_score?: number;
}

const LEVEL_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/15 text-green-400 border-green-500/30",
};

function ScoreBar({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const color =
    pct >= 75 ? "bg-red-500" : pct >= 50 ? "bg-orange-500" : pct >= 25 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/40">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums w-8 text-right">{pct.toFixed(0)}</span>
    </div>
  );
}

export function AssetRiskPanel() {
  const [scores, setScores] = useState<AssetScore[]>([]);
  const [stats, setStats] = useState<RiskStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      assetRiskApi.listScores().catch(() => ({ data: [] })),
      assetRiskApi.stats().catch(() => ({ data: {} })),
    ])
      .then(([scoresRes, statsRes]) => {
        if (cancelled) return;
        const raw = scoresRes.data;
        setScores(Array.isArray(raw) ? raw : (raw?.scores ?? raw?.items ?? []));
        setStats(statsRes.data ?? {});
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message ?? "Failed to load risk data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="space-y-2 animate-pulse">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-12 rounded-lg bg-muted/50" />
        ))}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={ShieldAlert} title="Error loading risk data" description={error} />;
  }

  if (scores.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No risk scores"
        description="Register assets and calculate risk scores to populate this view."
      />
    );
  }

  const byLevel = stats.by_risk_level ?? {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {(["critical", "high", "medium", "low"] as const).map((level) => (
          <div key={level} className="rounded-lg border border-border bg-card p-3">
            <p className="text-xs text-muted-foreground capitalize">{level}</p>
            <p className={`text-2xl font-bold ${LEVEL_COLOR[level].split(" ")[1]}`}>
              {byLevel[level] ?? 0}
            </p>
          </div>
        ))}
      </div>

      {stats.avg_composite_score !== undefined && (
        <div className="rounded-lg border border-border bg-card p-3 flex items-center gap-4">
          <div>
            <p className="text-xs text-muted-foreground">Avg Composite Score</p>
            <p className="text-xl font-bold">{stats.avg_composite_score.toFixed(1)}</p>
          </div>
          <div className="flex-1">
            <ScoreBar score={stats.avg_composite_score} />
          </div>
        </div>
      )}

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="px-4 py-2 bg-muted/30 border-b border-border text-xs font-medium text-muted-foreground">
          Asset Risk Scores (top {Math.min(scores.length, 30)})
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/10">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Asset</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Criticality</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Risk Level</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground w-40">Score</th>
            </tr>
          </thead>
          <tbody>
            {scores.slice(0, 30).map((s, i) => (
              <tr
                key={s.asset_id ?? i}
                className="border-b border-border/50 hover:bg-muted/20 transition-colors"
              >
                <td className="px-4 py-2.5 font-medium">{s.asset_name ?? s.asset_id}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{s.asset_type ?? "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground capitalize">{s.criticality ?? "—"}</td>
                <td className="px-4 py-2.5">
                  {s.risk_level ? (
                    <Badge className={`text-xs ${LEVEL_COLOR[s.risk_level] ?? "bg-muted/30"}`}>
                      {s.risk_level}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-4 py-2.5 w-40">
                  {s.composite_score !== undefined ? (
                    <ScoreBar score={s.composite_score} />
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
