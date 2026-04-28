// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Waivers Explorer — Live API
 * Multica: 70b1b89d-359d-4038-95f8-16cd2534c5e8
 * API: GET /api/v1/auto-waiver/rules + /api/v1/auto-waiver/stats
 *
 * Lists active auto-waiver rules with their match counts and reasons. The
 * `auto=true` filter from the spec maps to the auto-waiver endpoint family;
 * manual waivers (if any) are merged when present. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { Filter, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function WaiversExplorer() {
  const [rules, setRules] = useState<Record<string, unknown>[]>([]);
  const [stats, setStats] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [autoOnly, setAutoOnly] = useState(true);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesRes, statsRes] = await Promise.allSettled([
        apiFetch<{ items?: Record<string, unknown>[] } | Record<string, unknown>[]>(
          "/api/v1/auto-waiver/rules",
        ),
        apiFetch<Record<string, unknown>>("/api/v1/auto-waiver/stats"),
      ]);
      if (rulesRes.status === "fulfilled") {
        const v = rulesRes.value;
        setRules(Array.isArray(v) ? v : (v.items as Record<string, unknown>[]) ?? []);
      }
      if (statsRes.status === "fulfilled") setStats(statsRes.value);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const visible = autoOnly
    ? rules.filter((r) => (r.source ?? r.kind ?? "auto") !== "manual")
    : rules;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Filter className="w-6 h-6 text-indigo-400" /> Waivers Explorer
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/auto-waiver/rules</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 text-xs text-gray-400">
            <input
              type="checkbox"
              checked={autoOnly}
              onChange={(e) => setAutoOnly(e.target.checked)}
              className="accent-indigo-500"
            />
            auto only
          </label>
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : visible.length === 0 ? (
        <EmptyState
          icon={Filter}
          title="No waivers"
          description="Auto-waiver rules will appear once the AutoWaiverEngine has matched any findings."
        />
      ) : (
        <>
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {(Object.entries(stats) as [string, unknown][])
                .filter(([, v]) => typeof v === "number")
                .slice(0, 4)
                .map(([k, v]) => (
                  <div key={k} className="bg-gray-800 rounded-lg p-5">
                    <p className="text-gray-400 text-sm capitalize">{k.replace(/_/g, " ")}</p>
                    <p className="text-3xl font-bold mt-1 text-indigo-400">{String(v)}</p>
                  </div>
                ))}
            </div>
          )}
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-semibold text-white">
                Waivers ({visible.length})
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    {Object.keys(visible[0] || {})
                      .slice(0, 6)
                      .map((col) => (
                        <th
                          key={col}
                          className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase"
                        >
                          {col.replace(/_/g, " ")}
                        </th>
                      ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {visible.slice(0, 100).map((row, i) => (
                    <tr key={(row.id as string) ?? i} className="hover:bg-gray-750">
                      {Object.values(row)
                        .slice(0, 6)
                        .map((cell, j) => (
                          <td
                            key={j}
                            className="px-4 py-3 text-sm text-gray-300 max-w-xs truncate"
                          >
                            {typeof cell === "boolean"
                              ? cell
                                ? "Yes"
                                : "No"
                              : typeof cell === "object" && cell !== null
                              ? JSON.stringify(cell).slice(0, 80)
                              : String(cell ?? "—")}
                          </td>
                        ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
