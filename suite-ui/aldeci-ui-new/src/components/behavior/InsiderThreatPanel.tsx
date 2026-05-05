/**
 * InsiderThreatPanel — BehaviorAnalyticsHub "insider" tab
 *
 * Wired to real backend:
 *   GET /api/v1/insider-threat/stats         → KPI bar
 *   GET /api/v1/insider-threat/distribution  → risk distribution counts
 *   GET /api/v1/insider-threat/high-risk     → high-risk user table
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { UserX, RefreshCw, ShieldOff, Eye, AlertOctagon } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface DetectionStats {
  total_activities?: number;
  total_alerts?: number;
  reviewed_alerts?: number;
  unreviewed_alerts?: number;
  risk_distribution?: {
    low?: number;
    medium?: number;
    high?: number;
    critical?: number;
  };
  top_indicators?: string[];
}

interface RiskDistribution {
  low?: number;
  medium?: number;
  high?: number;
  critical?: number;
}

interface ThreatIndicator {
  type?: string;
  description?: string;
  score?: number;
  detected_at?: string;
}

interface UserRiskProfile {
  user_email?: string;
  risk_score?: number;
  alert_level?: string;
  total_activities?: number;
  active_indicators?: ThreatIndicator[];
  last_activity?: string;
  acknowledged?: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const ALERT_LEVEL_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

const RISK_COLOR = (score: number) => {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
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

function extractProfiles(data: unknown): UserRiskProfile[] {
  if (Array.isArray(data)) return data as UserRiskProfile[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["profiles", "users", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as UserRiskProfile[];
    }
  }
  return [];
}

// ── Distribution bar ──────────────────────────────────────────────────────────

function DistBar({ dist }: { dist: RiskDistribution }) {
  const total = (dist.low ?? 0) + (dist.medium ?? 0) + (dist.high ?? 0) + (dist.critical ?? 0);
  if (total === 0) return null;
  const pct = (n: number) => `${Math.round((n / total) * 100)}%`;
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">Risk Distribution ({total} users)</p>
      <div className="flex rounded-full overflow-hidden h-3 bg-muted/40">
        {dist.critical != null && dist.critical > 0 && (
          <div style={{ width: pct(dist.critical) }} className="bg-red-600" title={`Critical: ${dist.critical}`} />
        )}
        {dist.high != null && dist.high > 0 && (
          <div style={{ width: pct(dist.high) }} className="bg-orange-500" title={`High: ${dist.high}`} />
        )}
        {dist.medium != null && dist.medium > 0 && (
          <div style={{ width: pct(dist.medium) }} className="bg-amber-400" title={`Medium: ${dist.medium}`} />
        )}
        {dist.low != null && dist.low > 0 && (
          <div style={{ width: pct(dist.low) }} className="bg-blue-500" title={`Low: ${dist.low}`} />
        )}
      </div>
      <div className="flex gap-3 text-[10px] text-muted-foreground">
        {[
          { label: "Critical", val: dist.critical, cls: "text-red-400" },
          { label: "High", val: dist.high, cls: "text-orange-400" },
          { label: "Medium", val: dist.medium, cls: "text-amber-400" },
          { label: "Low", val: dist.low, cls: "text-blue-400" },
        ].map(({ label, val, cls }) => (
          <span key={label} className={cls}>{label}: {val ?? 0}</span>
        ))}
      </div>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function InsiderThreatPanel() {
  const [detectionStats, setDetectionStats] = useState<DetectionStats | null>(null);
  const [distribution, setDistribution] = useState<RiskDistribution | null>(null);
  const [highRisk, setHighRisk] = useState<UserRiskProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawDist, rawHigh] = await Promise.all([
        apiFetch<DetectionStats>("/api/v1/insider-threat/stats"),
        apiFetch<RiskDistribution>("/api/v1/insider-threat/distribution"),
        apiFetch<unknown>("/api/v1/insider-threat/high-risk"),
      ]);
      setDetectionStats(rawStats);
      // distribution may be wrapped in a "distribution" key
      const distObj = (rawDist as Record<string, unknown>)?.distribution ?? rawDist;
      setDistribution(distObj as RiskDistribution);
      setHighRisk(extractProfiles(rawHigh));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load insider threat data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Activities", value: detectionStats?.total_activities ?? 0, icon: Eye, color: "text-slate-300" },
    { label: "Total Alerts", value: detectionStats?.total_alerts ?? 0, icon: AlertOctagon, color: "text-orange-400" },
    { label: "Unreviewed", value: detectionStats?.unreviewed_alerts ?? 0, icon: ShieldOff, color: "text-red-400" },
    { label: "High-Risk Users", value: highRisk.length, icon: UserX, color: "text-red-500" },
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
          <UserX className="h-5 w-5 text-red-400" />
          <span className="font-semibold text-sm">Insider Threat Monitor</span>
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
              {value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>

      {/* Distribution bar */}
      {distribution && <DistBar dist={distribution} />}

      {/* Top indicators */}
      {detectionStats?.top_indicators && detectionStats.top_indicators.length > 0 && (
        <div className="flex flex-wrap gap-2">
          <span className="text-xs text-muted-foreground self-center">Top indicators:</span>
          {detectionStats.top_indicators.slice(0, 6).map(ind => (
            <Badge key={ind} variant="outline" className="text-[10px] border-amber-600 text-amber-400">{ind}</Badge>
          ))}
        </div>
      )}

      {/* High-risk user table */}
      <div>
        <p className="text-xs font-medium text-muted-foreground mb-2">High-Risk Users (threshold &ge;60)</p>
        {highRisk.length === 0 ? (
          <EmptyState
            icon={UserX}
            title="No high-risk users"
            description="Users with a risk score above 60 will appear here."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["User", "Risk Score", "Alert Level", "Activities", "Active Indicators", "Last Activity", "Reviewed"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {highRisk.slice(0, 200).map((u, i) => (
                  <tr key={u.user_email ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{u.user_email ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`font-bold tabular-nums ${RISK_COLOR(u.risk_score ?? 0)}`}>
                        {u.risk_score ?? 0}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${ALERT_LEVEL_CLASS[u.alert_level?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {u.alert_level ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-muted-foreground">
                      {u.total_activities ?? 0}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {(u.active_indicators?.length ?? 0) > 0
                        ? (u.active_indicators ?? []).slice(0, 2).map(ind => ind.type ?? "").join(", ")
                        : "—"}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {u.last_activity ? new Date(u.last_activity).toLocaleString() : "—"}
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className={`text-[10px] ${u.acknowledged ? "border-emerald-600 text-emerald-400" : "border-amber-600 text-amber-400"}`}>
                        {u.acknowledged ? "Yes" : "No"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </motion.div>
  );
}
