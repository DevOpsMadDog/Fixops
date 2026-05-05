/**
 * ExceptionsListPanel — live exceptions from /api/v1/security-exceptions/{org_id}
 * Shows risk-accepted exceptions with status, risk level, expiry, and stats bar.
 */

import { useEffect, useState } from "react";
import { ShieldOff, RefreshCw, Clock, AlertTriangle } from "lucide-react";
import { securityExceptionsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface SecurityException {
  exception_id: string;
  title: string;
  exception_type: string;
  risk_level: string;
  status: string;
  requestor?: string;
  approver?: string;
  business_justification?: string;
  expires_at?: string;
  created_at?: string;
}

interface ExceptionStats {
  total: number;
  pending: number;
  approved: number;
  rejected: number;
  expired: number;
  expiring_soon: number;
}

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-slate-600 text-slate-200",
};

const STATUS_COLORS: Record<string, string> = {
  approved: "bg-green-800 text-green-200",
  pending: "bg-amber-800 text-amber-200",
  rejected: "bg-red-800 text-red-200",
  expired: "bg-slate-700 text-slate-300",
  revoked: "bg-purple-800 text-purple-200",
};

function riskClass(r: string) {
  return RISK_COLORS[r?.toLowerCase()] ?? RISK_COLORS.low;
}
function statusClass(s: string) {
  return STATUS_COLORS[s?.toLowerCase()] ?? STATUS_COLORS.pending;
}

export function ExceptionsListPanel() {
  const [exceptions, setExceptions] = useState<SecurityException[]>([]);
  const [stats, setStats] = useState<ExceptionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      securityExceptionsApi.list("default"),
      securityExceptionsApi.stats("default"),
    ])
      .then(([listRes, statsRes]) => {
        const raw = listRes.data;
        setExceptions(Array.isArray(raw) ? raw : raw?.exceptions ?? raw?.items ?? []);
        setStats(statsRes.data as ExceptionStats);
      })
      .catch((e: Error) => setError(e.message ?? "Failed to load exceptions"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 mt-4">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-14 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  const filtered = filter === "all" ? exceptions : exceptions.filter(e => e.status === filter);

  return (
    <div className="space-y-4 mt-2">
      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: "Total", value: stats.total, color: "text-slate-300" },
            { label: "Approved", value: stats.approved, color: "text-green-400" },
            { label: "Pending", value: stats.pending, color: "text-amber-400" },
            { label: "Rejected", value: stats.rejected, color: "text-red-400" },
            { label: "Expiring Soon", value: stats.expiring_soon, color: "text-orange-400" },
          ].map(s => (
            <div key={s.label} className="rounded-lg bg-muted/30 border border-border p-3 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value ?? 0}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter + refresh */}
      <div className="flex items-center gap-2">
        {["all", "pending", "approved", "rejected", "expired"].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              filter === f
                ? "bg-primary text-primary-foreground"
                : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
        <button
          onClick={load}
          className="ml-auto p-1.5 rounded-md hover:bg-muted/40 text-muted-foreground"
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={ShieldOff}
          title="No exceptions"
          description={filter === "all" ? "No security exceptions recorded yet." : `No ${filter} exceptions.`}
        />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/30">
              <tr>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Title</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Type</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Risk</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Status</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Expires</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Requestor</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(ex => (
                <tr key={ex.exception_id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-medium truncate max-w-[200px]">{ex.title}</td>
                  <td className="px-4 py-3 text-muted-foreground text-xs">{ex.exception_type}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${riskClass(ex.risk_level)}`}>
                      {ex.risk_level}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusClass(ex.status)}`}>
                      {ex.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {ex.expires_at ? (
                      <span className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        {new Date(ex.expires_at).toLocaleDateString()}
                      </span>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{ex.requestor ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {exceptions.length > 0 && (
        <p className="text-xs text-muted-foreground text-right">
          Showing {filtered.length} of {exceptions.length} exceptions
        </p>
      )}
    </div>
  );
}
