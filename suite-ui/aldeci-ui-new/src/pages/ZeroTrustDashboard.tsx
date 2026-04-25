/**
 * Zero Trust Dashboard - Live API
 * Route: /zero-trust
 * API: GET /api/v1/zero-trust-policy/{policies,access-events,stats,compliance}
 */
import { useState, useEffect } from "react";
import { Lock, RefreshCw, Shield, CheckCircle2, XCircle } from "lucide-react";
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

const decisionColor = (d: string) => d === "allow" || d === "permit" ? "text-green-400" : "text-red-400";

export default function ZeroTrustDashboard() {
  const [policies, setPolicies] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [compliance, setCompliance] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [p, e, s, c] = await Promise.allSettled([
        apiFetch<any>("/api/v1/zero-trust-policy/policies"),
        apiFetch<any>("/api/v1/zero-trust-policy/access-events"),
        apiFetch<any>("/api/v1/zero-trust-policy/stats"),
        apiFetch<any>("/api/v1/zero-trust-policy/compliance"),
      ]);
      if (p.status === "fulfilled") { const v = p.value as any; setPolicies(Array.isArray(v) ? v : (v.policies ?? v.items ?? [])); }
      if (e.status === "fulfilled") { const v = e.value as any; setEvents(Array.isArray(v) ? v : (v.events ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
      if (c.status === "fulfilled") { setCompliance(c.value); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const ztScore = compliance?.maturity_score ?? compliance?.score ?? stats?.zero_trust_score ?? 0;
  const allowed = events.filter(e => (e.decision ?? e.action) === "allow" || (e.decision ?? e.action) === "permit").length;
  const denied = events.filter(e => (e.decision ?? e.action) === "deny" || (e.decision ?? e.action) === "block").length;
  const pillars = compliance?.pillars ?? [];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Lock className="w-6 h-6 text-cyan-400" /> Zero Trust Policy</h1>
          <p className="text-gray-400 text-sm mt-1">NIST SP 800-207 policies, access events, maturity score</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : policies.length === 0 && events.length === 0 ? <EmptyState icon={Lock} title="No zero-trust data" description="Create policies and start logging access events." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">ZT Maturity Score</p><p className="text-3xl font-bold text-cyan-400 mt-1">{ztScore}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Active Policies</p><p className="text-3xl font-bold text-blue-400 mt-1">{policies.filter(p => p.enabled !== false && p.active !== false).length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Allowed (24h)</p><p className="text-3xl font-bold text-green-400 mt-1">{allowed}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Denied (24h)</p><p className="text-3xl font-bold text-red-400 mt-1">{denied}</p></div>
          </div>

          {pillars.length > 0 && <div className="grid grid-cols-2 md:grid-cols-5 gap-4">{pillars.map((p: any) => (
            <div key={p.name} className="bg-gray-800 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2"><p className="text-white font-medium text-sm">{p.name}</p><Shield className="w-4 h-4 text-cyan-400" /></div>
              <p className={`text-2xl font-bold ${(p.score ?? 0) >= 70 ? "text-green-400" : (p.score ?? 0) >= 40 ? "text-amber-400" : "text-red-400"}`}>{p.score ?? 0}</p>
              <div className="w-full bg-gray-700 rounded-full h-1.5 mt-2"><div className={`h-1.5 rounded-full ${(p.score ?? 0) >= 70 ? "bg-green-500" : (p.score ?? 0) >= 40 ? "bg-amber-500" : "bg-red-500"}`} style={{ width: `${p.score ?? 0}%` }} /></div>
            </div>
          ))}</div>}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4">Active Policies</h2>
              {policies.length === 0 ? <p className="text-gray-500 text-sm">No policies defined.</p>
                : <div className="overflow-x-auto"><table className="w-full text-sm">
                  <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Resource</th><th className="text-left pb-2 pr-4">Action</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2">Created</th></tr></thead>
                  <tbody className="divide-y divide-gray-700/50">{policies.map(p => (
                    <tr key={p.id} className="hover:bg-gray-700/30">
                      <td className="py-3 pr-4 text-gray-200 font-medium">{p.name ?? p.policy_name}</td>
                      <td className="py-3 pr-4 text-gray-400 text-xs font-mono">{p.resource ?? "—"}</td>
                      <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${p.action === "allow" ? "bg-green-700 text-green-100" : "bg-red-700 text-red-100"}`}>{p.action ?? "—"}</span></td>
                      <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs ${(p.enabled ?? p.active ?? true) ? "bg-blue-700 text-blue-100" : "bg-gray-700 text-gray-400"}`}>{(p.enabled ?? p.active ?? true) ? "Active" : "Disabled"}</span></td>
                      <td className="py-3 text-gray-400 text-xs">{p.created_at ?? "—"}</td>
                    </tr>
                  ))}</tbody>
                </table></div>}
            </div>
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4">Recent Access Events</h2>
              {events.length === 0 ? <p className="text-gray-500 text-sm">No events recorded.</p>
                : <div className="space-y-2 max-h-96 overflow-y-auto">{events.slice(0, 20).map(e => {
                  const dec = e.decision ?? e.action ?? "deny";
                  const allow = dec === "allow" || dec === "permit";
                  return (
                    <div key={e.id} className="flex items-start gap-2 p-2 bg-gray-700/30 rounded text-xs">
                      {allow ? <CheckCircle2 className="w-3 h-3 text-green-400 mt-0.5 shrink-0" /> : <XCircle className="w-3 h-3 text-red-400 mt-0.5 shrink-0" />}
                      <div className="flex-1 min-w-0">
                        <p className={`font-medium ${decisionColor(dec)}`}>{dec.toUpperCase()}</p>
                        <p className="text-gray-400 truncate">{e.user ?? e.principal} → {e.resource}</p>
                        {e.timestamp && <p className="text-gray-600 text-[10px]">{e.timestamp}</p>}
                      </div>
                    </div>
                  );
                })}</div>}
            </div>
          </div>
        </>}
    </div>
  );
}
