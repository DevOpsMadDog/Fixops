/**
 * GenericDashboard — universal data-fetching dashboard shell
 *
 * Replaces ~69 homogeneous *Dashboard.tsx pages that all follow the same
 * pattern: apiFetch → stats KPI bar → paginated item table → empty/error state.
 *
 * Usage (via dashboardRoutes.ts config):
 *   <GenericDashboard
 *     title="DAST"
 *     description="Dynamic application security testing scans"
 *     apiPath="/api/v1/dast"
 *     itemsKey="scans"
 *     statsPath="/api/v1/dast/stats"       // optional — defaults to apiPath + "/stats"
 *     columns={[{ key: "id", label: "ID" }, ...]}
 *   />
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { RefreshCw, Database } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

// ── Types ────────────────────────────────────────────────────────────────────

export interface ColumnDef {
  key: string;
  label: string;
  /** Optional formatter — receives raw cell value, returns display string */
  format?: (value: unknown) => string;
  /** Tailwind class(es) applied to the <td> */
  className?: string;
}

export interface KpiDef {
  /** Key to read from the stats response object */
  key: string;
  label: string;
  /** Optional colour class for the value text */
  colorClass?: string;
}

export interface GenericDashboardProps {
  /** Page heading */
  title: string;
  /** Sub-heading description */
  description?: string;
  /**
   * Base API path for the items list.
   * The component will try: apiPath (array response), then apiPath + /items,
   * then apiPath + /list, then apiPath + /{itemsKey}.
   */
  apiPath: string;
  /**
   * Hint for the array key inside a JSON object response.
   * e.g. "scans" means we look for response.scans first.
   */
  itemsKey?: string;
  /**
   * Explicit path for the stats endpoint.
   * Defaults to apiPath + "/stats".
   */
  statsPath?: string;
  /**
   * Column definitions for the table.
   * If omitted, the component auto-detects up to 6 columns from the first row.
   */
  columns?: ColumnDef[];
  /**
   * KPI definitions for the stats bar.
   * If omitted, the component auto-detects up to 4 numeric keys from the stats response.
   */
  kpis?: KpiDef[];
  /** Max rows to show per page (default 50) */
  pageSize?: number;
  /** Empty state message */
  emptyMessage?: string;
}

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
    // Try hint first
    if (hint && Array.isArray(obj[hint])) return obj[hint] as unknown[];
    // Common envelope keys
    for (const k of ["items", "data", "results", "records", "list"]) {
      if (Array.isArray(obj[k])) return obj[k] as unknown[];
    }
    // Any array value in the object
    for (const k of Object.keys(obj)) {
      if (Array.isArray(obj[k])) return obj[k] as unknown[];
    }
  }
  return [];
}

function autoColumns(row: Record<string, unknown>): ColumnDef[] {
  return Object.keys(row)
    .slice(0, 6)
    .map((k) => ({ key: k, label: k.replace(/_/g, " ") }));
}

function autoKpis(stats: Record<string, unknown>): KpiDef[] {
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

// ── Component ─────────────────────────────────────────────────────────────────

export function GenericDashboard({
  title,
  description,
  apiPath,
  itemsKey,
  statsPath,
  columns,
  kpis,
  pageSize = 50,
  emptyMessage,
}: GenericDashboardProps) {
  const [items, setItems] = useState<unknown[]>([]);
  const [stats, setStats] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
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

  if (loading) return <PageSkeleton />;

  // Derive columns + kpis from first row / stats if not provided
  const firstRow = items[0] as Record<string, unknown> | undefined;
  const resolvedColumns: ColumnDef[] =
    columns ?? (firstRow ? autoColumns(firstRow) : []);
  const resolvedKpis: KpiDef[] =
    kpis ?? (stats ? autoKpis(stats) : []);

  const totalPages = Math.ceil(items.length / pageSize);
  const pageItems = items.slice(page * pageSize, (page + 1) * pageSize);

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
          <h1 className="text-2xl font-bold text-white">{title}</h1>
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
          icon={Database}
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

          {/* Table */}
          {resolvedColumns.length > 0 && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white">
                  {title}{" "}
                  <span className="text-sm font-normal text-gray-400">
                    ({items.length} total)
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
                        <tr key={(r["id"] as string) ?? i} className="hover:bg-gray-750">
                          {resolvedColumns.map((col) => (
                            <td
                              key={col.key}
                              className={`px-4 py-3 text-sm text-gray-300 max-w-xs truncate ${col.className ?? ""}`}
                            >
                              {col.format
                                ? col.format(r[col.key])
                                : formatCell(r[col.key])}
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
                    Page {page + 1} of {totalPages}
                  </span>
                  <div className="flex gap-2">
                    <button
                      disabled={page === 0}
                      onClick={() => setPage((p) => p - 1)}
                      className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded text-gray-200"
                    >
                      Previous
                    </button>
                    <button
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage((p) => p + 1)}
                      className="px-3 py-1 text-xs bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded text-gray-200"
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

export default GenericDashboard;
