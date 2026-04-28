/**
 * FindingsExplorerView — universal Pattern-2 component
 *
 * Extends GenericDashboard with:
 *   - Severity filter buttons (critical / high / medium / low / all)
 *   - Severity badge column auto-rendering (colour-coded)
 *   - Optional second API path for "findings" sub-resource
 *   - Status badge rendering
 *   - Pagination (pageSize default 50)
 *
 * Replaces ~40 homogeneous pages (116-200 LOC) following the pattern:
 *   apiFetch → KPI bar → severity filter → findings table → pagination
 *
 * Usage (via findingsExplorerRoutes.ts config):
 *   <FindingsExplorerView
 *     title="Security Findings"
 *     apiPath="/api/v1/security-findings/findings"
 *     statsPath="/api/v1/security-findings/summary"
 *     itemsKey="findings"
 *     severityKey="severity"
 *     columns={[...]}
 *   />
 *
 * Generated 2026-04-27 — Pattern-2 mechanical collapse (UX Phase 3 Wave 4)
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { RefreshCw, ShieldAlert } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// ── Types ─────────────────────────────────────────────────────────────────────

export interface FindingsColumnDef {
  key: string;
  label: string;
  format?: (value: unknown) => string;
  /** If true, render as severity badge */
  isSeverity?: boolean;
  /** If true, render as status badge */
  isStatus?: boolean;
  className?: string;
}

export interface FindingsKpiDef {
  key: string;
  label: string;
  colorClass?: string;
}

export interface FindingsExplorerViewProps {
  /** Page heading */
  title: string;
  /** Sub-heading description */
  description?: string;
  /** Primary API path (items list) */
  apiPath: string;
  /** Key hint for extracting array from JSON envelope */
  itemsKey?: string;
  /** Stats / summary endpoint — defaults to apiPath + "/stats" */
  statsPath?: string;
  /** Column definitions. Auto-detected from first row if omitted (up to 6 cols). */
  columns?: FindingsColumnDef[];
  /** KPI definitions. Auto-detected from stats numeric keys if omitted. */
  kpis?: FindingsKpiDef[];
  /**
   * Field name used as the severity filter.
   * Defaults to "severity". Set to null to disable the filter bar.
   */
  severityKey?: string | null;
  /** Filter options shown in the filter bar. Defaults to standard severity levels. */
  filterOptions?: string[];
  /** Max rows per page (default 50) */
  pageSize?: number;
  /** Empty state message */
  emptyMessage?: string;
}

// ── Severity / status colour maps ─────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high:     "bg-orange-600/80 text-orange-100",
  medium:   "bg-amber-600/80 text-amber-100",
  low:      "bg-blue-600/80 text-blue-100",
  info:     "bg-slate-600/80 text-slate-200",
  none:     "bg-slate-700/60 text-slate-300",
};

const STATUS_CLASS: Record<string, string> = {
  open:           "bg-red-700/70 text-red-100",
  in_progress:    "bg-blue-700/70 text-blue-100",
  resolved:       "bg-emerald-700/70 text-emerald-100",
  suppressed:     "bg-slate-600/70 text-slate-200",
  false_positive: "bg-purple-700/70 text-purple-100",
  active:         "bg-blue-600/70 text-blue-100",
  completed:      "bg-emerald-600/70 text-emerald-100",
  failed:         "bg-red-600/70 text-red-100",
  pending:        "bg-amber-600/70 text-amber-100",
};

const DEFAULT_FILTER_OPTIONS = ["critical", "high", "medium", "low"];

// ── Internal apiFetch ─────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractArray(value: unknown, hint?: string): unknown[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (hint && Array.isArray(obj[hint])) return obj[hint] as unknown[];
    for (const k of ["items", "data", "findings", "results", "records", "list"]) {
      if (Array.isArray(obj[k])) return obj[k] as unknown[];
    }
    for (const k of Object.keys(obj)) {
      if (Array.isArray(obj[k])) return obj[k] as unknown[];
    }
  }
  return [];
}

function autoColumns(row: Record<string, unknown>): FindingsColumnDef[] {
  return Object.keys(row)
    .slice(0, 6)
    .map((k) => ({
      key: k,
      label: k.replace(/_/g, " "),
      isSeverity: k === "severity",
      isStatus: k === "status",
    }));
}

function autoKpis(stats: Record<string, unknown>): FindingsKpiDef[] {
  return (Object.entries(stats) as [string, unknown][])
    .filter(([, v]) => typeof v === "number")
    .slice(0, 4)
    .map(([k]) => ({ key: k, label: k.replace(/_/g, " ") }));
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string" && value.length === 0) return "—";
  return String(value);
}

function humanize(str: string): string {
  return str.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function SeverityBadge({ value }: { value: unknown }) {
  const s = String(value ?? "").toLowerCase();
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold capitalize ${SEV_CLASS[s] ?? SEV_CLASS.none}`}>
      {s || "—"}
    </span>
  );
}

function StatusBadge({ value }: { value: unknown }) {
  const s = String(value ?? "").toLowerCase();
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${STATUS_CLASS[s] ?? "bg-slate-700/60 text-slate-300"}`}>
      {s.replace(/_/g, " ") || "—"}
    </span>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export function FindingsExplorerView({
  title,
  description,
  apiPath,
  itemsKey,
  statsPath,
  columns,
  kpis,
  severityKey = "severity",
  filterOptions = DEFAULT_FILTER_OPTIONS,
  pageSize = 50,
  emptyMessage,
}: FindingsExplorerViewProps) {
  const [items, setItems] = useState<unknown[]>([]);
  const [stats, setStats] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [page, setPage] = useState(0);

  const effectiveStatsPath = statsPath ?? `${apiPath}/stats`;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [itemsRes, statsRes] = await Promise.allSettled([
        apiFetch<unknown>(apiPath),
        apiFetch<unknown>(effectiveStatsPath),
      ]);
      if (itemsRes.status === "fulfilled") {
        setItems(extractArray(itemsRes.value, itemsKey));
      } else {
        setItems([]);
      }
      if (statsRes.status === "fulfilled" && statsRes.value && typeof statsRes.value === "object") {
        setStats(statsRes.value as Record<string, unknown>);
      } else {
        setStats(null);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [apiPath, effectiveStatsPath, itemsKey]);

  useEffect(() => {
    void load();
  }, [load]);

  // Reset page when filter changes
  useEffect(() => { setPage(0); }, [filter]);

  if (loading) return <PageSkeleton />;

  const firstRow = items[0] as Record<string, unknown> | undefined;
  const resolvedColumns: FindingsColumnDef[] =
    columns ?? (firstRow ? autoColumns(firstRow) : []);
  const resolvedKpis: FindingsKpiDef[] =
    kpis ?? (stats ? autoKpis(stats) : []);

  // Severity filter
  const filtered =
    filter === "all" || severityKey === null
      ? items
      : items.filter((item) => {
          const row = item as Record<string, unknown>;
          return String(row[severityKey ?? "severity"] ?? "").toLowerCase() === filter;
        });

  const totalPages = Math.ceil(filtered.length / pageSize);
  const pageItems = filtered.slice(page * pageSize, (page + 1) * pageSize);

  // Severity counts for filter bar badges
  const sevCounts: Record<string, number> = {};
  if (severityKey) {
    items.forEach((item) => {
      const row = item as Record<string, unknown>;
      const s = String(row[severityKey] ?? "").toLowerCase();
      if (s) sevCounts[s] = (sevCounts[s] ?? 0) + 1;
    });
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-red-400" />
            {title}
          </h1>
          {description && (
            <p className="text-gray-400 mt-1 text-sm">{description}</p>
          )}
        </div>
        <button
          onClick={() => { void load(); }}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 rounded-lg text-sm text-gray-100 transition-colors"
          aria-label="Refresh"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {error ? (
        <ErrorState message={error} onRetry={() => { void load(); }} />
      ) : items.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title={`No ${title.toLowerCase()} data`}
          description={emptyMessage ?? "Data will appear here once the backend has records."}
        />
      ) : (
        <>
          {/* KPI bar */}
          {resolvedKpis.length > 0 && stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {resolvedKpis.map((kpi) => (
                <div key={kpi.key} className="bg-gray-800 rounded-lg p-5">
                  <p className="text-gray-400 text-sm capitalize">{humanize(kpi.label)}</p>
                  <p className={`text-3xl font-bold mt-1 ${kpi.colorClass ?? "text-indigo-400"}`}>
                    {formatCell(stats[kpi.key])}
                  </p>
                </div>
              ))}
            </div>
          )}

          {/* Severity filter bar */}
          {severityKey !== null && filterOptions.length > 0 && (
            <div className="flex gap-2 flex-wrap items-center">
              <button
                onClick={() => setFilter("all")}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  filter === "all"
                    ? "bg-indigo-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                }`}
              >
                All ({items.length})
              </button>
              {filterOptions.map((opt) => (
                <button
                  key={opt}
                  onClick={() => setFilter(opt)}
                  className={`px-3 py-1.5 rounded text-xs font-medium capitalize transition-colors ${
                    filter === opt
                      ? "bg-indigo-600 text-white"
                      : "bg-gray-800 text-gray-400 hover:text-white"
                  }`}
                >
                  {opt} {sevCounts[opt] !== undefined ? `(${sevCounts[opt]})` : ""}
                </button>
              ))}
            </div>
          )}

          {/* Table */}
          {resolvedColumns.length > 0 && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white">
                  {title}{" "}
                  <span className="text-sm font-normal text-gray-400">
                    ({filtered.length} {filter !== "all" ? filter : "total"})
                  </span>
                </h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-700">
                      {resolvedColumns.map((col) => (
                        <th
                          key={col.key}
                          className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider"
                        >
                          {humanize(col.label)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {pageItems.map((row, i) => {
                      const r = row as Record<string, unknown>;
                      return (
                        <tr
                          key={(r["id"] as string) ?? i}
                          className="hover:bg-gray-750 transition-colors"
                        >
                          {resolvedColumns.map((col) => (
                            <td
                              key={col.key}
                              className={`px-4 py-3 text-sm text-gray-300 max-w-xs truncate ${col.className ?? ""}`}
                            >
                              {col.isSeverity ? (
                                <SeverityBadge value={r[col.key]} />
                              ) : col.isStatus ? (
                                <StatusBadge value={r[col.key]} />
                              ) : col.format ? (
                                col.format(r[col.key])
                              ) : (
                                formatCell(r[col.key])
                              )}
                            </td>
                          ))}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-6 py-3 border-t border-gray-700">
                  <span className="text-xs text-gray-400">
                    Page {page + 1} of {totalPages} ({filtered.length} records)
                  </span>
                  <div className="flex gap-2">
                    <button
                      disabled={page === 0}
                      onClick={() => setPage((p) => p - 1)}
                      className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded text-gray-200 transition-colors"
                    >
                      Previous
                    </button>
                    <button
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage((p) => p + 1)}
                      className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded text-gray-200 transition-colors"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </motion.div>
  );
}

export default FindingsExplorerView;
