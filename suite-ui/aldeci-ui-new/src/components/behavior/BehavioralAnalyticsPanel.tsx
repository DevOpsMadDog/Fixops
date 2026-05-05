/**
 * BehavioralAnalyticsPanel — BehaviorAnalyticsHub "behavioral" tab
 *
 * Wired to real backend:
 *   GET /api/v1/behavioral-analytics/stats      → KPI bar
 *   GET /api/v1/behavioral-analytics/anomalies  → anomaly table (filterable by severity/status)
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, AlertCircle, TrendingUp, BarChart2 } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface BehavioralStats {
  total_baselines?: number;
  total_anomalies?: number;
  open_anomalies?: number;
  high_severity_anomalies?: number;
  users_profiled?: number;
  org_id?: string;
}

interface BehavioralAnomaly {
  anomaly_id?: string;
  id?: string;
  user_id?: string;
  behavior_type?: string;
  severity?: string;
  status?: string;
  deviation_score?: number;
  observed_value?: number;
  baseline_value?: number;
  description?: string;
  detected_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

const STATUS_CLASS: Record<string, string> = {
  open: "border-red-600 text-red-400",
  investigating: "border-amber-600 text-amber-400",
  resolved: "border-emerald-600 text-emerald-400",
  false_positive: "border-slate-500 text-slate-400",
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

function extractAnomalies(data: unknown): BehavioralAnomaly[] {
  if (Array.isArray(data)) return data as BehavioralAnomaly[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["anomalies", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as BehavioralAnomaly[];
    }
  }
  return [];
}

const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"];

// ── Component ─────────────────────────────────────────────────────────────────

export default function BehavioralAnalyticsPanel() {
  const [stats, setStats] = useState<BehavioralStats | null>(null);
  const [anomalies, setAnomalies] = useState<BehavioralAnomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<string>("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawAnomalies] = await Promise.all([
        apiFetch<BehavioralStats>("/api/v1/behavioral-analytics/stats"),
        apiFetch<unknown>("/api/v1/behavioral-analytics/anomalies"),
      ]);
      setStats(rawStats);
      setAnomalies(extractAnomalies(rawAnomalies));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load behavioral analytics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const filtered = sevFilter === "all"
    ? anomalies
    : anomalies.filter(a => a.severity?.toLowerCase() === sevFilter);

  const kpis = [
    { label: "Baselines", value: stats?.total_baselines ?? 0, icon: BarChart2, color: "text-slate-300" },
    { label: "Total Anomalies", value: stats?.total_anomalies ?? 0, icon: TrendingUp, color: "text-amber-400" },
    { label: "Open", value: stats?.open_anomalies ?? 0, icon: AlertCircle, color: "text-red-400" },
    { label: "Users Profiled", value: stats?.users_profiled ?? 0, icon: Activity, color: "text-indigo-400" },
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
          <Activity className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Behavioral Analytics</span>
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

      {/* Severity filter */}
      <div className="flex items-center gap-2 flex-wrap">
        {SEVERITY_FILTERS.map(f => (
          <button
            key={f}
            onClick={() => setSevFilter(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              sevFilter === f
                ? "bg-indigo-600 text-white"
                : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {f}
          </button>
        ))}
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} anomal{filtered.length !== 1 ? "ies" : "y"}
        </span>
      </div>

      {/* Anomaly table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No anomalies"
          description="Behavioral anomalies will appear here once baselines are established and deviations detected."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Behavior Type", "User", "Severity", "Status", "Deviation Score", "Detected"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 200).map((a, i) => {
                const id = a.anomaly_id ?? a.id ?? String(i);
                return (
                  <tr key={id} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{a.behavior_type ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{a.user_id ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[a.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {a.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className={`text-[10px] ${STATUS_CLASS[a.status ?? ""] ?? ""}`}>
                        {a.status ?? "—"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-amber-400">
                      {a.deviation_score != null ? a.deviation_score.toFixed(2) : "—"}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {a.detected_at ? new Date(a.detected_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
