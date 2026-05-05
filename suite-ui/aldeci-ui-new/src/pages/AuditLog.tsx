/**
 * Audit Log — Live API
 * API: GET /api/v1/audit/logs  (via auditApi.recentLogs)
 *
 * Columns: timestamp · user · action · resource · status
 */

import { useState, useEffect, useCallback } from "react";
import { RefreshCw, ScrollText, CheckCircle2, XCircle, Clock } from "lucide-react";
import { auditApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

// ── Types ────────────────────────────────────────────────────────────────────

interface AuditLogEntry {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource: string;
  status: string;
  /** Any extra fields the backend sends — surfaced in detail expansion */
  [key: string]: unknown;
}

interface AuditStats {
  [key: string]: unknown;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function normalizeLog(raw: Record<string, unknown>, idx: number): AuditLogEntry {
  return {
    id: String(raw.id ?? raw.log_id ?? raw.audit_id ?? `log-${idx}`),
    timestamp: String(raw.timestamp ?? raw.created_at ?? raw.ts ?? "—"),
    user: String(raw.user_id ?? raw.user ?? raw.actor ?? raw.performed_by ?? "—"),
    action: String(raw.action ?? raw.event_type ?? raw.event ?? "—"),
    resource: String(raw.resource ?? raw.resource_id ?? raw.target ?? "—"),
    status: String(raw.status ?? raw.result ?? "—"),
    ...raw,
  };
}

function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase();
  if (s === "success" || s === "allowed" || s === "ok") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        <CheckCircle2 className="w-3 h-3" /> {status}
      </span>
    );
  }
  if (s === "failure" || s === "denied" || s === "error" || s === "failed") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/15 text-red-400 border border-red-500/30">
        <XCircle className="w-3 h-3" /> {status}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-slate-700/60 text-slate-300 border border-slate-600/40">
      <Clock className="w-3 h-3" /> {status}
    </span>
  );
}

function formatTs(raw: string): string {
  if (!raw || raw === "—") return "—";
  try {
    return new Date(raw).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return raw;
  }
}

// ── AuditLogsTable ────────────────────────────────────────────────────────────

interface AuditLogsTableProps {
  logs: AuditLogEntry[];
}

export function AuditLogsTable({ logs }: AuditLogsTableProps) {
  if (logs.length === 0) {
    return (
      <EmptyState
        icon={ScrollText}
        title="No audit logs"
        description="Audit events will appear here once the backend records activity."
      />
    );
  }

  return (
    <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700">
      <div className="px-5 py-3.5 border-b border-slate-700 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white">
          Audit Log
          <span className="ml-2 text-xs font-normal text-slate-400">({logs.length} entries)</span>
        </h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-700 bg-slate-800/60">
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap">
                Timestamp
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                User
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Action
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Resource
              </th>
              <th className="px-4 py-2.5 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700/60">
            {logs.map((row) => (
              <tr key={row.id} className="hover:bg-slate-700/30 transition-colors">
                <td className="px-4 py-2.5 text-[11px] text-slate-300 font-mono whitespace-nowrap">
                  {formatTs(row.timestamp)}
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-200 max-w-[160px] truncate">
                  {row.user}
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-200 max-w-[200px] truncate">
                  {row.action}
                </td>
                <td className="px-4 py-2.5 text-xs text-slate-300 font-mono max-w-[200px] truncate">
                  {row.resource}
                </td>
                <td className="px-4 py-2.5">
                  <StatusBadge status={row.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function AuditLog() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await auditApi.recentLogs(100);
      const raw = res.data;
      const rawList: Record<string, unknown>[] = Array.isArray(raw)
        ? raw
        : (raw?.logs ?? raw?.items ?? raw?.data ?? []);
      setLogs(rawList.map((entry, i) => normalizeLog(entry as Record<string, unknown>, i)));

      // Stats are returned alongside logs in some endpoints
      if (raw && typeof raw === "object" && !Array.isArray(raw)) {
        const { logs: _l, items: _i, data: _d, ...rest } = raw as Record<string, unknown>;
        if (Object.keys(rest).length > 0) setStats(rest);
      }
    } catch (e) {
      setError((e as Error).message ?? "Failed to load audit logs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ScrollText className="w-6 h-6 text-indigo-400" /> Audit Log
          </h1>
          <p className="text-slate-400 text-sm mt-1">
            Live — /api/v1/audit/logs
          </p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Stats bar */}
      {stats && !loading && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {(Object.entries(stats) as [string, unknown][])
            .filter(([, v]) => typeof v === "number")
            .slice(0, 4)
            .map(([k, v]) => (
              <div key={k} className="bg-slate-800 rounded-lg p-5 border border-slate-700">
                <p className="text-slate-400 text-xs capitalize">{k.replace(/_/g, " ")}</p>
                <p className="text-3xl font-bold mt-1 text-indigo-400">{String(v)}</p>
              </div>
            ))}
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : (
        <AuditLogsTable logs={logs} />
      )}
    </div>
  );
}
