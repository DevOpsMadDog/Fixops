// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Zero Trust Policy Dashboard - Live API
 * Route: /zero-trust-policy
 * API: GET /api/v1/zero-trust-policy/{policies,access-events,stats}
 */
import { useState, useEffect } from "react";
import { Lock, RefreshCw, CheckCircle2, XCircle } from "lucide-react";
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

export default function ZeroTrustPolicyDashboard() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [p, e, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/zero-trust-policy/policies"),
        apiFetch<any>("/api/v1/zero-trust-policy/access-events"),
        apiFetch<any>("/api/v1/zero-trust-policy/stats"),
      ]);
      if (p.status === "fulfilled") { const v = p.value as any; setPolicies(Array.isArray(v) ? v : (v.policies ?? v.items ?? [])); }
      if (e.status === "fulfilled") { const v = e.value as any; setEvents(Array.isArray(v) ? v : (v.events ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const allowed = events.filter(e => (e.decision ?? e.action) === "allow" || (e.decision ?? e.action) === "permit").length;
  const denied = events.filter(e => (e.decision ?? e.action) === "deny" || (e.decision ?? e.action) === "block").length;
  const allowRate = (allowed + denied) ? Math.round((allowed / (allowed + denied)) * 100) : 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Lock className="w-6 h-6 text-cyan-400" /> Zero Trust Policy</h1>
          <p className="text-gray-400 text-sm mt-1">Continuous access evaluation, NIST SP 800-207</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : policies.length === 0 && events.length === 0 ? <EmptyState icon={Lock} title="No zero-trust data" description="Define access policies to start enforcement." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Active Policies</p><p className="text-3xl font-bold text-blue-400 mt-1">{policies.filter(p => p.enabled !== false).length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Access Requests</p><p className="text-3xl font-bold text-cyan-400 mt-1">{stats?.access_requests ?? events.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Allow Rate</p><p className="text-3xl font-bold text-green-400 mt-1">{allowRate}%</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Violations</p><p className="text-3xl font-bold text-red-400 mt-1">{denied}</p></div>
          </div>
          {policies.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Policies</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Resource</th><th className="text-left pb-2 pr-4">Action</th><th className="text-left pb-2">Status</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{policies.map(p => (
                <tr key={p.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{p.name ?? p.policy_name}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs font-mono">{p.resource ?? "—"}</td>
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs ${p.action === "allow" ? "bg-green-700 text-green-100" : "bg-red-700 text-red-100"}`}>{p.action ?? "—"}</span></td>
                  <td className="py-3 text-gray-300 text-xs">{p.enabled !== false ? "Active" : "Disabled"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
          {events.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Access Decision Log</h2>
            <div className="space-y-1 max-h-96 overflow-y-auto">{events.slice(0, 50).map(e => {
              const dec = e.decision ?? e.action ?? "deny";
              const allow = dec === "allow" || dec === "permit";
              return (
                <div key={e.id} className="flex items-center gap-2 p-2 bg-gray-700/30 rounded text-xs">
                  {allow ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <XCircle className="w-3 h-3 text-red-400" />}
                  <span className={`font-medium ${allow ? "text-green-400" : "text-red-400"}`}>{dec.toUpperCase()}</span>
                  <span className="text-gray-400 truncate">{e.user ?? e.principal} → {e.resource}</span>
                  <span className="text-gray-600 ml-auto">{e.timestamp ?? "—"}</span>
                </div>
              );
            })}</div>
          </div>}
        </>}
    </div>
  );
}
