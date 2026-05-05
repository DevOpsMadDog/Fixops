/**
 * DependencyRiskPanel — dep-risk tab for UpgradePathsHub.
 * Wired to GET /api/v1/risk/overview and /api/v1/risk/scores.
 */

import { useEffect, useState } from "react";
import { AlertOctagon, RefreshCw } from "lucide-react";

import { riskOverviewApi, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

interface RiskOverview {
  overall_score?: number;
  risk_level?: string;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  total_components?: number;
  ecosystems?: Record<string, number>;
  [key: string]: unknown;
}

interface RiskScore {
  component?: string;
  purl?: string;
  score?: number;
  risk_level?: string;
  ecosystem?: string;
  cve_count?: number;
  [key: string]: unknown;
}

const RISK_COLOR: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/20",
  high: "text-orange-400 bg-orange-400/10 border-orange-400/20",
  medium: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  low: "text-green-500 bg-green-500/10 border-green-500/20",
};

export function DependencyRiskPanel() {
  const orgId = getStoredOrgId();

  const [overview, setOverview] = useState<RiskOverview | null>(null);
  const [scores, setScores] = useState<RiskScore[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.all([
      riskOverviewApi.overview(),
      riskOverviewApi.scores({ org_id: orgId }),
    ])
      .then(([overviewRes, scoresRes]) => {
        setOverview(overviewRes.data as RiskOverview);
        const raw = scoresRes.data;
        setScores(
          Array.isArray(raw)
            ? (raw as RiskScore[])
            : ((raw as { items?: RiskScore[]; scores?: RiskScore[] })?.items ??
              (raw as { items?: RiskScore[]; scores?: RiskScore[] })?.scores ??
              [])
        );
      })
      .catch((e) =>
        setError(e?.response?.data?.detail ?? e?.message ?? "Failed to load risk data")
      )
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, [orgId]);

  if (loading) return <PageSkeleton />;

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
        {error}
      </div>
    );
  }

  if (!overview && scores.length === 0) {
    return (
      <EmptyState
        icon={AlertOctagon}
        title="No dependency risk data"
        description="Dependency risk scores appear after SCA scans are ingested through the Brain Pipeline."
      />
    );
  }

  const riskLevel = (overview?.risk_level ?? "unknown").toLowerCase();

  return (
    <div className="space-y-6">
      {/* Overall score */}
      {overview && (
        <div className="flex flex-col sm:flex-row gap-4">
          <div
            className={`flex-1 rounded-xl border px-6 py-5 space-y-1 ${RISK_COLOR[riskLevel] ?? "border-border bg-card"}`}
          >
            <p className="text-xs text-muted-foreground">Overall Risk Score</p>
            <p className="text-4xl font-bold">
              {overview.overall_score != null ? Math.round(Number(overview.overall_score)) : "—"}
            </p>
            <p className="text-xs font-medium capitalize">{riskLevel} risk</p>
          </div>

          <div className="flex-1 grid grid-cols-2 gap-3">
            {(
              [
                { label: "Critical", count: overview.critical_count, level: "critical" },
                { label: "High", count: overview.high_count, level: "high" },
                { label: "Medium", count: overview.medium_count, level: "medium" },
                { label: "Low", count: overview.low_count, level: "low" },
              ] as const
            ).map(({ label, count, level }) =>
              count != null ? (
                <div
                  key={level}
                  className={`rounded-lg border px-4 py-3 space-y-0.5 ${RISK_COLOR[level]}`}
                >
                  <p className="text-xs">{label}</p>
                  <p className="text-xl font-semibold">{count}</p>
                </div>
              ) : null
            )}
          </div>
        </div>
      )}

      {/* Ecosystem breakdown */}
      {overview?.ecosystems && Object.keys(overview.ecosystems).length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
            Risk by Ecosystem
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {Object.entries(overview.ecosystems).map(([eco, score]) => (
              <div key={eco} className="rounded-lg bg-muted/40 px-3 py-2 space-y-0.5">
                <p className="text-xs text-muted-foreground capitalize">{eco}</p>
                <p className="text-lg font-semibold">{String(score)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Per-component scores table */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <AlertOctagon className="h-4 w-4 text-muted-foreground" />
          Component Risk Scores
          {scores.length > 0 && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs">{scores.length}</span>
          )}
        </h3>
        <button
          onClick={load}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
        >
          <RefreshCw className="h-3 w-3" />
          Refresh
        </button>
      </div>

      {scores.length === 0 ? (
        <EmptyState
          icon={AlertOctagon}
          title="No component scores yet"
          description="Scores appear after SCA scans are processed."
        />
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground">
                <th className="px-4 py-2.5">Component</th>
                <th className="px-4 py-2.5">Ecosystem</th>
                <th className="px-4 py-2.5">CVEs</th>
                <th className="px-4 py-2.5">Score</th>
                <th className="px-4 py-2.5">Risk</th>
              </tr>
            </thead>
            <tbody>
              {scores.slice(0, 50).map((s, i) => {
                const level = (s.risk_level ?? "medium").toLowerCase();
                return (
                  <tr key={s.purl ?? s.component ?? i} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="px-4 py-2.5 font-mono text-xs">
                      {s.component ?? s.purl ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 capitalize">{s.ecosystem ?? "—"}</td>
                    <td className="px-4 py-2.5">{s.cve_count ?? "—"}</td>
                    <td className="px-4 py-2.5 font-semibold">
                      {s.score != null ? Math.round(Number(s.score)) : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`rounded-full border px-2 py-0.5 text-xs font-medium capitalize ${RISK_COLOR[level] ?? "text-muted-foreground bg-muted/40 border-border"}`}
                      >
                        {level}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {scores.length > 50 && (
            <p className="px-4 py-2 text-xs text-muted-foreground border-t border-border">
              Showing 50 of {scores.length} components
            </p>
          )}
        </div>
      )}
    </div>
  );
}
