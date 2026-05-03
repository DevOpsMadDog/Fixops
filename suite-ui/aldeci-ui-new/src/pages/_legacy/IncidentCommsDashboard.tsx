// FOLDED into IncidentExtensionsHub at /remediate/incidents/extensions?tab=comms
// Phase 3 UX consolidation 2026-05-02 — see docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.22
// Legacy route /incident-comms now redirects to the unified hub. This file is kept and
// lazy-loaded inside IncidentExtensionsHub so behavior + API calls are preserved.
// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Incident Comms - Live API
 * API: GET /api/v1/incident-comms/communications
 */

import { useState, useEffect } from "react";
import { RefreshCw, MessageCircle } from "lucide-react";
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

export default function IncidentCommsDashboard() {
  const [communications, setCommunications] = useState<any[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [itemsRes, statsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/incident-comms/communications"),
        apiFetch<any>("/api/v1/incident-comms/stats"),
      ]);
      if (itemsRes.status === "fulfilled") {
        const v = itemsRes.value as any;
        setCommunications(Array.isArray(v) ? v : (v.communications ?? v.items ?? v.data ?? []));
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
            <MessageCircle className="w-6 h-6 text-indigo-400" /> Incident Comms
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/incident-comms</p>
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
      ) : communications.length === 0 ? (
        <EmptyState icon={MessageCircle} title="No communications found" description="Data will appear here once the backend has records." />
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
              <h2 className="text-lg font-semibold text-white">Incident Comms ({communications.length})</h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    {Object.keys(communications[0] || {}).slice(0, 6).map(col => (
                      <th key={col} className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                        {col.replace(/_/g, " ")}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {communications.slice(0, 50).map((row, i) => (
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
