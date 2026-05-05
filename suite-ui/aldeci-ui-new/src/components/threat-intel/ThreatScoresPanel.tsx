/**
 * ThreatScoresPanel — ExternalThreatIntelHub "scores" tab
 *
 * Wired to real backend:
 *   GET /api/v1/threat-scores/stats        → KPI bar
 *   GET /api/v1/threat-scores/scores       → scored assets table
 *   GET /api/v1/threat-scores/top-threats  → top threats list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { BarChart3, TrendingUp, Activity, RefreshCw, ShieldAlert } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ThreatStats {
  total_assets_scored?: number;
  avg_threat_score?: number;
  high_risk_assets?: number;
  signals_processed?: number;
  org_id?: string;
}

interface AssetScore {
  asset_id: string;
  threat_score?: number;
  risk_level?: string;
  signal_count?: number;
  top_signal?: string;
  last_calculated?: string;
}

interface TopThreat {
  threat_id?: string;
  asset_id?: string;
  threat_name?: string;
  threat_score?: number;
  risk_level?: string;
  category?: string;
  created_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SCORE_COLOR = (score: number) => {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
};

const SCORE_BAR_COLOR = (score: number) => {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-amber-500";
  return "bg-emerald-500";
};

const RISK_BADGE: Record<string, string> = {
  critical: "border-red-500 text-red-400",
  high: "border-orange-500 text-orange-400",
  medium: "border-amber-500 text-amber-400",
  low: "border-emerald-500 text-emerald-400",
};

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["items", "scores", "threats", "top_threats", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ThreatScoresPanel() {
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [scores, setScores] = useState<AssetScore[]>([]);
  const [topThreats, setTopThreats] = useState<TopThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subTab, setSubTab] = useState<"scores" | "top-threats">("scores");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawScores, rawTop] = await Promise.all([
        apiFetch<ThreatStats>("/api/v1/threat-scores/stats"),
        apiFetch<unknown>("/api/v1/threat-scores/scores"),
        apiFetch<unknown>("/api/v1/threat-scores/top-threats"),
      ]);
      setStats(rawStats);
      setScores(extractArray<AssetScore>(rawScores));
      setTopThreats(extractArray<TopThreat>(rawTop));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load threat score data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const avg = stats?.avg_threat_score ?? 0;
  const kpis = [
    { label: "Assets Scored", value: stats?.total_assets_scored ?? 0, icon: BarChart3, color: "text-slate-300" },
    { label: "Avg Threat Score", value: avg.toFixed(1), icon: TrendingUp, color: SCORE_COLOR(avg) },
    { label: "High Risk Assets", value: stats?.high_risk_assets ?? 0, icon: ShieldAlert, color: "text-red-400" },
    { label: "Signals Processed", value: stats?.signals_processed ?? 0, icon: Activity, color: "text-indigo-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Composite Threat Scoring</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </span>
          </div>
        ))}
      </div>

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["scores", "top-threats"] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              subTab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "scores" ? `Asset Scores (${scores.length})` : `Top Threats (${topThreats.length})`}
          </button>
        ))}
      </div>

      {/* Asset scores table */}
      {subTab === "scores" && (
        scores.length === 0 ? (
          <EmptyState
            icon={BarChart3}
            title="No assets scored"
            description="Threat scores will populate once signal ingestion is active and assets are enrolled."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Asset", "Threat Score", "Risk Level", "Signals", "Top Signal", "Last Calculated"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {scores.slice(0, 200).map((s, i) => {
                  const score = s.threat_score ?? 0;
                  return (
                    <tr key={s.asset_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                      <td className="px-3 py-2 font-mono text-xs text-indigo-300 max-w-[12rem] truncate">{s.asset_id}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 rounded-full bg-muted/60 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${SCORE_BAR_COLOR(score)}`}
                              style={{ width: `${Math.min(score, 100)}%` }}
                            />
                          </div>
                          <span className={`font-bold tabular-nums ${SCORE_COLOR(score)}`}>{score.toFixed(1)}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <Badge
                          variant="outline"
                          className={`text-[10px] capitalize ${RISK_BADGE[s.risk_level?.toLowerCase() ?? ""] ?? ""}`}
                        >
                          {s.risk_level ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground tabular-nums">{s.signal_count ?? "—"}</td>
                      <td className="px-3 py-2 text-muted-foreground max-w-xs truncate">{s.top_signal ?? "—"}</td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {s.last_calculated ? new Date(s.last_calculated).toLocaleString() : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Top threats table */}
      {subTab === "top-threats" && (
        topThreats.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No top threats identified"
            description="High-composite-score threats will appear here once scoring signals are ingested."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Threat / Asset", "Score", "Risk Level", "Category", "Detected"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {topThreats.slice(0, 100).map((t, i) => {
                  const score = t.threat_score ?? 0;
                  return (
                    <tr key={t.threat_id ?? t.asset_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                      <td className="px-3 py-2 font-medium max-w-xs truncate">
                        {t.threat_name ?? t.asset_id ?? "—"}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`font-bold tabular-nums ${SCORE_COLOR(score)}`}>{score.toFixed(1)}</span>
                      </td>
                      <td className="px-3 py-2">
                        <Badge
                          variant="outline"
                          className={`text-[10px] capitalize ${RISK_BADGE[t.risk_level?.toLowerCase() ?? ""] ?? ""}`}
                        >
                          {t.risk_level ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-muted-foreground capitalize">{t.category ?? "—"}</td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {t.created_at ? new Date(t.created_at).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )
      )}
    </motion.div>
  );
}
