/**
 * Security Chaos Dashboard - Live API
 * Route: /security-chaos
 * API: GET /api/v1/security-chaos/{experiments,observations,findings}
 */
import { useState, useEffect } from "react";
import { Zap, RefreshCw } from "lucide-react";
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

export default function SecurityChaosDashboard() {
  const [experiments, setExperiments] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [e, f] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-chaos/experiments"),
        apiFetch<any>("/api/v1/security-chaos/findings"),
      ]);
      if (e.status === "fulfilled") { const v = e.value as any; setExperiments(Array.isArray(v) ? v : (v.experiments ?? v.items ?? [])); }
      if (f.status === "fulfilled") { const v = f.value as any; setFindings(Array.isArray(v) ? v : (v.findings ?? v.items ?? [])); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const active = experiments.filter(e => e.status === "active" || e.status === "running").length;
  const avgScore = experiments.length ? Math.round(experiments.reduce((s, e) => s + (e.resilience_score ?? 0), 0) / experiments.length) : 0;
  const open = findings.filter(f => f.status === "open").length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Zap className="w-6 h-6 text-yellow-400" /> Security Chaos Engineering</h1>
          <p className="text-gray-400 text-sm mt-1">Resilience experiments, observations, findings</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-yellow-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : experiments.length === 0 && findings.length === 0 ? <EmptyState icon={Zap} title="No experiments" description="Define chaos experiments to test resilience." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Experiments</p><p className="text-3xl font-bold text-blue-400 mt-1">{experiments.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Active</p><p className="text-3xl font-bold text-yellow-400 mt-1">{active}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Avg Resilience</p><p className="text-3xl font-bold text-green-400 mt-1">{avgScore}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Open Findings</p><p className="text-3xl font-bold text-red-400 mt-1">{open}</p></div>
          </div>
          {experiments.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Experiments</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Hypothesis</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2">Resilience</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{experiments.map(e => (
                <tr key={e.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{e.name ?? e.experiment_name}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs max-w-md truncate">{e.hypothesis ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-300 capitalize">{e.status}</td>
                  <td className="py-3 text-yellow-400 font-bold">{e.resilience_score ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
          {findings.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Findings</h2>
            <div className="space-y-2">{findings.slice(0, 20).map(f => (
              <div key={f.id} className="p-3 bg-gray-700/30 rounded">
                <p className="text-gray-200 text-sm font-medium">{f.title ?? f.finding}</p>
                <p className="text-gray-500 text-xs mt-1">{f.experiment_name ?? f.experiment} · {f.status}</p>
              </div>
            ))}</div>
          </div>}
        </>}
    </div>
  );
}
