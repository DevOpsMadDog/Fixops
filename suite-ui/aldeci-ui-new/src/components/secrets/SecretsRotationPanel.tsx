/**
 * SecretsRotationPanel — Rotation lifecycle tracker
 * API: GET /api/v1/secrets-rotation/ + GET /api/v1/secrets-rotation/metrics + GET /api/v1/secrets-rotation/overdue
 */

import { useEffect, useState } from "react";
import { RotateCw, RefreshCw, AlertTriangle, Clock, CheckCircle } from "lucide-react";
import { secretsRotationApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface RotationRecord {
  rotation_id: string;
  secret_type: string;
  state: string;
  severity: string;
  exposed_location: string;
  detection_source?: string;
  assignee?: string;
  sla_deadline?: string;
  created_at?: string;
  rotated_by?: string;
}

interface RotationMetrics {
  total: number;
  by_state?: Record<string, number>;
  by_type?: Record<string, number>;
  overdue_count?: number;
  avg_time_hours?: number;
}

const STATE_COLORS: Record<string, string> = {
  pending: "bg-amber-800 text-amber-200",
  in_progress: "bg-blue-800 text-blue-200",
  rotated: "bg-green-800 text-green-200",
  verified: "bg-emerald-800 text-emerald-200",
  failed: "bg-red-800 text-red-200",
  deferred: "bg-slate-700 text-slate-300",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-slate-400",
};

function stateClass(s: string) {
  return STATE_COLORS[s?.toLowerCase()] ?? STATE_COLORS.pending;
}
function sevColor(s: string) {
  return SEVERITY_COLORS[s?.toLowerCase()] ?? SEVERITY_COLORS.low;
}

function slaStatus(deadline?: string): { label: string; color: string } | null {
  if (!deadline) return null;
  const diff = new Date(deadline).getTime() - Date.now();
  const hours = diff / 3_600_000;
  if (hours < 0) return { label: "Overdue", color: "text-red-400" };
  if (hours < 24) return { label: `${Math.round(hours)}h left`, color: "text-amber-400" };
  const days = Math.round(hours / 24);
  return { label: `${days}d left`, color: "text-green-400" };
}

export function SecretsRotationPanel() {
  const [records, setRecords] = useState<RotationRecord[]>([]);
  const [metrics, setMetrics] = useState<RotationMetrics | null>(null);
  const [overdue, setOverdue] = useState<RotationRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [recRes, metRes, overRes] = await Promise.allSettled([
        secretsRotationApi.list(),
        secretsRotationApi.metrics(),
        secretsRotationApi.overdue(),
      ]);

      if (recRes.status === "fulfilled") {
        const d = recRes.value.data;
        setRecords(Array.isArray(d) ? (d as RotationRecord[]) : []);
      }
      if (metRes.status === "fulfilled") {
        setMetrics(metRes.value.data as RotationMetrics);
      }
      if (overRes.status === "fulfilled") {
        const d = overRes.value.data;
        setOverdue(Array.isArray(d) ? (d as RotationRecord[]) : []);
      }

      if (recRes.status === "rejected" && metRes.status === "rejected") {
        throw new Error((recRes.reason as Error).message ?? "Failed to load rotation data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-12 rounded bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  if (records.length === 0 && !metrics) {
    return (
      <EmptyState
        icon={RotateCw}
        title="No rotation records"
        description="No exposed secrets have been registered for rotation tracking yet."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Metrics row */}
      {metrics && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Records", value: metrics.total, color: "text-foreground" },
            { label: "Overdue", value: metrics.overdue_count ?? overdue.length, color: "text-red-400" },
            {
              label: "Avg Resolution",
              value: metrics.avg_time_hours != null ? `${metrics.avg_time_hours.toFixed(1)}h` : "—",
              color: "text-indigo-400",
            },
            {
              label: "Verified",
              value: metrics.by_state?.verified ?? 0,
              color: "text-green-400",
            },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* State breakdown */}
      {metrics?.by_state && Object.keys(metrics.by_state).length > 0 && (
        <div className="rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium mb-3 flex items-center gap-1.5">
            <CheckCircle className="h-3.5 w-3.5 text-green-400" />
            By State
          </h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(metrics.by_state).map(([state, count]) => (
              <div
                key={state}
                className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${stateClass(state)}`}
              >
                <span>{state}</span>
                <span className="opacity-75">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Overdue alert */}
      {overdue.length > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-red-700 bg-red-900/20 px-3 py-2 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          {overdue.length} rotation{overdue.length !== 1 ? "s" : ""} past SLA deadline — escalate immediately.
        </div>
      )}

      {/* Rotation records table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <RotateCw className="h-3.5 w-3.5 text-indigo-400" />
            Rotation Records ({records.length})
          </h3>
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
        </div>
        {records.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">No rotation records found.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">ID</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Type</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Location</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Severity</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">State</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Assignee</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">SLA</th>
              </tr>
            </thead>
            <tbody>
              {records.slice(0, 50).map((r) => {
                const sla = slaStatus(r.sla_deadline);
                return (
                  <tr key={r.rotation_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2 font-mono text-xs text-muted-foreground">
                      {r.rotation_id.slice(0, 8)}…
                    </td>
                    <td className="px-4 py-2 text-xs font-mono">{r.secret_type}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[160px]" title={r.exposed_location}>
                      {r.exposed_location}
                    </td>
                    <td className={`px-4 py-2 text-xs font-medium ${sevColor(r.severity)}`}>
                      {r.severity ?? "—"}
                    </td>
                    <td className="px-4 py-2">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${stateClass(r.state)}`}>
                        {r.state}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{r.assignee ?? "—"}</td>
                    <td className="px-4 py-2 text-xs">
                      {sla ? (
                        <span className={`flex items-center gap-1 ${sla.color}`}>
                          <Clock className="h-3 w-3" />
                          {sla.label}
                        </span>
                      ) : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
