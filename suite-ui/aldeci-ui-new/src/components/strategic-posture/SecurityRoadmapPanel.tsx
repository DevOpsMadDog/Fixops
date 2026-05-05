/**
 * SecurityRoadmapPanel — roadmap tab for StrategicPostureHub
 * Fetches /api/v1/security-roadmap/initiatives + /gaps + /stats
 * Real data only — no mocks.
 */

import { useCallback, useEffect, useState } from "react";
import {
  Map,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Clock,
  AlertTriangle,
  XCircle,
} from "lucide-react";
import { securityRoadmapApi, type RoadmapInitiative, type RoadmapGap, type RoadmapStats } from "@/lib/api";

const STATUS_BADGE: Record<string, string> = {
  completed:   "text-green-400 bg-green-500/10",
  in_progress: "text-blue-400 bg-blue-500/10",
  planned:     "text-amber-400 bg-amber-500/10",
  cancelled:   "text-slate-400 bg-slate-500/10",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  completed:   CheckCircle2,
  in_progress: Clock,
  planned:     AlertTriangle,
  cancelled:   XCircle,
};

const PRIORITY_COLOR: Record<string, string> = {
  critical: "text-red-500",
  high:     "text-orange-500",
  medium:   "text-amber-400",
  low:      "text-blue-400",
};

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400",
  high:     "bg-orange-500/10 text-orange-400",
  medium:   "bg-amber-500/10 text-amber-400",
  low:      "bg-blue-500/10 text-blue-400",
};

export function SecurityRoadmapPanel() {
  const [initiatives, setInitiatives] = useState<RoadmapInitiative[]>([]);
  const [gaps, setGaps] = useState<RoadmapGap[]>([]);
  const [stats, setStats] = useState<RoadmapStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      securityRoadmapApi.initiatives({ org_id: "default", status: statusFilter || undefined }),
      securityRoadmapApi.gaps({ org_id: "default" }),
      securityRoadmapApi.stats("default"),
    ])
      .then(([initRes, gapsRes, statsRes]) => {
        setInitiatives(Array.isArray(initRes.data) ? initRes.data : []);
        setGaps(Array.isArray(gapsRes.data) ? gapsRes.data : []);
        setStats(statsRes.data ?? null);
      })
      .catch((err: { response?: { data?: { detail?: string } }; message?: string }) => {
        setError(err?.response?.data?.detail ?? err?.message ?? "Failed to load roadmap");
      })
      .finally(() => setLoading(false));
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="flex flex-col gap-6">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-md border border-border bg-card px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          aria-label="Filter initiatives by status"
        >
          <option value="">All statuses</option>
          <option value="planned">Planned</option>
          <option value="in_progress">In Progress</option>
          <option value="completed">Completed</option>
          <option value="cancelled">Cancelled</option>
        </select>
        <button
          onClick={load}
          disabled={loading}
          className="ml-auto flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
          aria-label="Refresh roadmap"
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
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-16 animate-pulse rounded-xl bg-muted/40" />
          ))}
        </div>
      )}

      {/* Stats row */}
      {!loading && stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Total initiatives", value: stats.total_initiatives ?? 0 },
            { label: "In progress",       value: stats.in_progress ?? 0 },
            { label: "Completed",         value: stats.completed ?? 0 },
            { label: "Open gaps",         value: stats.open_gaps ?? 0 },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-xl border border-border/60 bg-card px-4 py-3 text-center">
              <p className="text-2xl font-bold tabular-nums text-foreground">{value}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Initiatives */}
      {!loading && !error && initiatives.length === 0 && (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-16 text-center">
          <Map className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">No initiatives yet</p>
          <p className="text-xs text-muted-foreground/60">
            Create one via POST /api/v1/security-roadmap/initiatives
          </p>
        </div>
      )}

      {!loading && initiatives.length > 0 && (
        <div className="flex flex-col gap-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Initiatives ({initiatives.length})
          </p>
          <div className="overflow-x-auto rounded-xl border border-border/60">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/60 bg-muted/30 text-left text-muted-foreground">
                  <th className="px-3 py-2.5 font-medium">Title</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Priority</th>
                  <th className="px-3 py-2.5 font-medium">Category</th>
                  <th className="px-3 py-2.5 font-medium">Target</th>
                  <th className="px-3 py-2.5 font-medium">Owner</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40">
                {initiatives.map((init) => {
                  const StatusIcon = STATUS_ICON[init.status] ?? Clock;
                  const statusCls = STATUS_BADGE[init.status] ?? "text-slate-400 bg-slate-400/10";
                  const priCls = PRIORITY_COLOR[init.priority?.toLowerCase() ?? ""] ?? "text-muted-foreground";
                  return (
                    <tr key={init.id ?? init.title} className="bg-card hover:bg-muted/20 transition-colors">
                      <td className="max-w-[220px] truncate px-3 py-2 font-medium text-foreground" title={init.title}>
                        {init.title}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${statusCls}`}>
                          <StatusIcon className="h-2.5 w-2.5" />
                          {init.status?.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className={`px-3 py-2 font-medium capitalize ${priCls}`}>
                        {init.priority ?? "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground capitalize">
                        {init.category ?? "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {init.target_date
                          ? new Date(init.target_date).toLocaleDateString()
                          : "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">{init.owner || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Gaps */}
      {!loading && gaps.length > 0 && (
        <div className="flex flex-col gap-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            Security Gaps ({gaps.length})
          </p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {gaps.map((gap) => {
              const sevCls = SEV_COLOR[gap.severity?.toLowerCase() ?? ""] ?? "bg-slate-400/10 text-slate-400";
              return (
                <div
                  key={gap.id ?? gap.title}
                  className="rounded-lg border border-border/60 bg-card px-4 py-3 flex flex-col gap-1"
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs font-medium text-foreground line-clamp-2">{gap.title}</p>
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${sevCls}`}>
                      {gap.severity ?? "—"}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground capitalize">{gap.gap_type?.replace(/_/g, " ") ?? "—"}</p>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
