/**
 * Posture Benchmarking Dashboard - Live API
 * Route: /posture-benchmarking
 * API: GET /api/v1/posture-benchmarking/{benchmarks,comparisons,stats}
 */
import { useState, useEffect } from "react";
import { Target, RefreshCw } from "lucide-react";
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

export default function PostureBenchmarkingDashboard() {
  const [benchmarks, setBenchmarks] = useState<any[]>([]);
  const [comparisons, setComparisons] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [b, c, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/posture-benchmarking/benchmarks"),
        apiFetch<any>("/api/v1/posture-benchmarking/comparisons"),
        apiFetch<any>("/api/v1/posture-benchmarking/stats"),
      ]);
      if (b.status === "fulfilled") { const v = b.value as any; setBenchmarks(Array.isArray(v) ? v : (v.benchmarks ?? v.items ?? [])); }
      if (c.status === "fulfilled") { const v = c.value as any; setComparisons(Array.isArray(v) ? v : (v.comparisons ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Target className="w-6 h-6 text-purple-400" /> Posture Benchmarking</h1>
          <p className="text-gray-400 text-sm mt-1">Compare against industry standards & frameworks</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : benchmarks.length === 0 ? <EmptyState icon={Target} title="No benchmarks defined" description="Configure benchmarks to compare your posture against peers." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total Benchmarks", value: stats?.total_benchmarks ?? benchmarks.length, color: "text-blue-400" },
              { label: "Active", value: stats?.active_benchmarks ?? benchmarks.filter(b => b.active).length, color: "text-green-400" },
              { label: "Avg Score", value: stats?.avg_score ?? Math.round(benchmarks.reduce((s, b) => s + (b.score ?? 0), 0) / (benchmarks.length || 1)), color: "text-purple-400" },
              { label: "Above Industry", value: stats?.above_industry_avg ?? benchmarks.filter(b => (b.score ?? 0) > (b.industry_avg ?? 50)).length, color: "text-emerald-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Benchmarks</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Framework</th><th className="text-left pb-2 pr-4">Score</th><th className="text-left pb-2 pr-4">Industry Avg</th><th className="text-left pb-2">Status</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{benchmarks.map(b => (
                <tr key={b.id ?? b.name} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{b.name ?? b.benchmark_name}</td>
                  <td className="py-3 pr-4"><span className="bg-purple-900 text-purple-300 px-2 py-0.5 rounded text-xs">{b.framework ?? "—"}</span></td>
                  <td className="py-3 pr-4 text-purple-400 font-bold">{b.score ?? 0}</td>
                  <td className="py-3 pr-4 text-gray-400">{b.industry_avg ?? "—"}</td>
                  <td className="py-3">{b.active ? <span className="text-green-400 text-xs">Active</span> : <span className="text-gray-500 text-xs">Inactive</span>}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
          {comparisons.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Recent Comparisons</h2>
            <div className="space-y-2">{comparisons.slice(0, 10).map((c, i) => (
              <div key={c.id ?? i} className="flex items-center justify-between p-2 bg-gray-700/30 rounded text-sm">
                <span className="text-gray-300">{c.benchmark_name} vs {c.peer_group ?? "industry"}</span>
                <span className={`font-bold ${(c.delta ?? 0) >= 0 ? "text-green-400" : "text-red-400"}`}>{(c.delta ?? 0) >= 0 ? "+" : ""}{c.delta ?? 0}</span>
              </div>
            ))}</div>
          </div>}
        </>}
    </div>
  );
}
