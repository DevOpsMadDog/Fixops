/**
 * AdminAuditLogPage
 * Route: /admin/audit-log
 * API:   GET /api/v1/audit/recent  (falls back to /api/v1/audit/logs?limit=200)
 *
 * Features:
 *  - Last 200 audit events in a sortable table
 *  - Columns: timestamp · actor · action · resource · status
 *  - Sort: click any column header (asc / desc toggle)
 *  - Filter: action-type dropdown + free-text search across actor / resource
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import {
  ScrollText,
  RefreshCw,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  Filter,
} from "lucide-react";
import { auditApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

// ── Types ─────────────────────────────────────────────────────────────────────

interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  status: string;
}

type SortKey = keyof AuditEntry;
type SortDir = "asc" | "desc";

// ── Normaliser ────────────────────────────────────────────────────────────────

function normalise(raw: Record<string, unknown>, idx: number): AuditEntry {
  return {
    id: String(raw.id ?? raw.log_id ?? raw.audit_id ?? `entry-${idx}`),
    timestamp: String(raw.timestamp ?? raw.created_at ?? raw.ts ?? ""),
    actor: String(raw.actor ?? raw.user_id ?? raw.user ?? raw.performed_by ?? "—"),
    action: String(raw.action ?? raw.event_type ?? raw.event ?? "—"),
    resource: String(raw.resource ?? raw.resource_id ?? raw.target ?? "—"),
    status: String(raw.status ?? raw.result ?? "—"),
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTs(raw: string): string {
  if (!raw) return "—";
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

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase();
  if (["success", "allowed", "ok", "passed"].includes(s)) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
        <CheckCircle2 className="w-3 h-3" />
        {status}
      </span>
    );
  }
  if (["failure", "denied", "error", "failed", "blocked"].includes(s)) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/15 text-red-400 border border-red-500/30">
        <XCircle className="w-3 h-3" />
        {status}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-slate-700/60 text-slate-300 border border-slate-600/40">
      <Clock className="w-3 h-3" />
      {status}
    </span>
  );
}

function SortIcon({ col, sortKey, sortDir }: { col: SortKey; sortKey: SortKey; sortDir: SortDir }) {
  if (col !== sortKey) return <ChevronsUpDown className="w-3 h-3 opacity-40" />;
  return sortDir === "asc"
    ? <ChevronUp className="w-3 h-3 text-indigo-400" />
    : <ChevronDown className="w-3 h-3 text-indigo-400" />;
}

// ── Skeleton ──────────────────────────────────────────────────────────────────

function TableSkeleton() {
  return (
    <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700 animate-pulse">
      <div className="px-5 py-3.5 border-b border-slate-700">
        <div className="h-4 w-40 bg-slate-700 rounded" />
      </div>
      {Array.from({ length: 8 }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-3 border-b border-slate-700/50">
          <div className="h-3 w-36 bg-slate-700 rounded" />
          <div className="h-3 w-24 bg-slate-700 rounded" />
          <div className="h-3 w-32 bg-slate-700 rounded" />
          <div className="h-3 w-40 bg-slate-700 rounded" />
          <div className="h-3 w-16 bg-slate-700 rounded" />
        </div>
      ))}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AdminAuditLogPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // Primary: /api/v1/audit/recent   Fallback: /api/v1/audit/logs?limit=200
      let raw: unknown;
      try {
        const res = await (auditApi as unknown as { recent?: (n: number) => Promise<{ data: unknown }> })
          .recent?.(200) ?? auditApi.recentLogs(200);
        raw = res.data;
      } catch {
        const res = await auditApi.recentLogs(200);
        raw = res.data;
      }

      const list: Record<string, unknown>[] = Array.isArray(raw)
        ? (raw as Record<string, unknown>[])
        : ((raw as Record<string, unknown>)?.logs ??
           (raw as Record<string, unknown>)?.items ??
           (raw as Record<string, unknown>)?.data ??
           (raw as Record<string, unknown>)?.events ??
           []) as Record<string, unknown>[];

      setEntries(list.map((r, i) => normalise(r, i)));
    } catch (e) {
      setError((e as Error).message ?? "Failed to load audit logs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Unique action types for filter dropdown
  const actionTypes = useMemo(() => {
    const set = new Set(entries.map((e) => e.action));
    return ["all", ...Array.from(set).sort()];
  }, [entries]);

  // Filtered + sorted slice
  const visible = useMemo(() => {
    let rows = entries;
    if (actionFilter !== "all") rows = rows.filter((r) => r.action === actionFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      rows = rows.filter(
        (r) =>
          r.actor.toLowerCase().includes(q) ||
          r.resource.toLowerCase().includes(q) ||
          r.action.toLowerCase().includes(q),
      );
    }
    return [...rows].sort((a, b) => {
      const va = a[sortKey] ?? "";
      const vb = b[sortKey] ?? "";
      const cmp = String(va).localeCompare(String(vb));
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [entries, actionFilter, search, sortKey, sortDir]);

  function handleSort(col: SortKey) {
    if (col === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(col);
      setSortDir("asc");
    }
  }

  const COLS: { key: SortKey; label: string; cls?: string }[] = [
    { key: "timestamp", label: "Timestamp",  cls: "whitespace-nowrap" },
    { key: "actor",     label: "Actor" },
    { key: "action",    label: "Action" },
    { key: "resource",  label: "Resource" },
    { key: "status",    label: "Status" },
  ];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-5">
      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ScrollText className="w-6 h-6 text-indigo-400" />
            Admin Audit Log
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Last 200 events — GET /api/v1/audit/recent
          </p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded-lg text-sm transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search actor, action, resource…"
            className="w-full pl-9 pr-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
          />
        </div>

        {/* Action-type filter */}
        <div className="relative">
          <Filter className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400 pointer-events-none" />
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="pl-9 pr-8 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 appearance-none"
          >
            {actionTypes.map((a) => (
              <option key={a} value={a}>
                {a === "all" ? "All action types" : a}
              </option>
            ))}
          </select>
        </div>

        {/* Count badge */}
        {!loading && (
          <div className="flex items-center px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-400">
            {visible.length.toLocaleString()} of {entries.length.toLocaleString()} events
          </div>
        )}
      </div>

      {/* ── Content ── */}
      {loading ? (
        <TableSkeleton />
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : entries.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No audit events"
          description="Audit events will appear here once the backend records activity."
        />
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/80">
                  {COLS.map(({ key, label, cls }) => (
                    <th
                      key={key}
                      onClick={() => handleSort(key)}
                      className={`px-4 py-3 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider cursor-pointer select-none hover:text-slate-200 transition-colors ${cls ?? ""}`}
                    >
                      <span className="inline-flex items-center gap-1">
                        {label}
                        <SortIcon col={key} sortKey={sortKey} sortDir={sortDir} />
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {visible.map((row) => (
                  <tr
                    key={row.id}
                    className="hover:bg-slate-700/30 transition-colors"
                  >
                    <td className="px-4 py-2.5 text-[11px] text-slate-300 font-mono whitespace-nowrap">
                      {fmtTs(row.timestamp)}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-200 max-w-[160px] truncate">
                      {row.actor}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-200 max-w-[200px] truncate">
                      {row.action}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-slate-300 font-mono max-w-[220px] truncate">
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

          {visible.length === 0 && (
            <div className="px-6 py-10 text-center text-slate-500 text-sm">
              No events match your filters.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
