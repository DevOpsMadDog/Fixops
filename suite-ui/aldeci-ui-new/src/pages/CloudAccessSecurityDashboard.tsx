// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Cloud Access Security - Live API
 * API: GET /api/v1/cloud-access-security/apps
 */

import { useState, useEffect } from "react";
import { RefreshCw, Cloud } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function CloudAccessSecurityDashboard() {
  const [apps, setApps] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [itemsRes, statsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/cloud-access-security/apps"),
        apiFetch<any>("/api/v1/cloud-access-security/stats"),
      ]);
      if (itemsRes.status === "fulfilled") {
        const v = itemsRes.value as any;
        setApps(Array.isArray(v) ? v : (v.apps ?? v.items ?? v.data ?? []));
      }
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value);
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Cloud className="w-6 h-6 text-indigo-400" /> Cloud Access Security
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/cloud-access-security</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : apps.length === 0 ? (
        <EmptyState icon={Cloud} title="No apps found" description="Data will appear here once the backend has records." />
      ) : (
        <>
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {(Object.entries(stats) as [string, unknown][]).filter(([, v]) => typeof v === "number").slice(0, 4).map(([k, v]) => (
                <div key={k} className="bg-gray-800 rounded-lg p-5">
                  <p className="text-gray-400 text-sm capitalize">{k.replace(/_/g, " ")}</p>
                  <p className="text-3xl font-bold mt-1 text-indigo-400">{String(v)}</p>
                </div>
              ))}
            </div>
          )}
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-semibold text-white">Cloud Access Security ({apps.length})</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    {Object.keys(apps[0] || {}).slice(0, 6).map(col => (
                      <th key={col} className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        {col.replace(/_/g, " ")}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {apps.slice(0, 50).map((row, i) => (
                    <tr key={row.id ?? i} className="hover:bg-gray-750">
                      {(Object.values(row as Record<string, unknown>)).slice(0, 6).map((cell, j) => (
                        <td key={j} className="px-4 py-3 text-sm text-gray-300 max-w-xs truncate">
                          {typeof cell === "boolean" ? (cell ? "Yes" : "No") : String(cell ?? "—")}
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
