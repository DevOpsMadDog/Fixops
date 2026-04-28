// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Posture Scoring Dashboard - Live API
 * Route: /posture-scoring
 * API: GET /api/v1/posture-scoring/{score,controls,snapshots}
 */
import { useState, useEffect } from "react";
import { ShieldCheck, RefreshCw } from "lucide-react";
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

export default function PostureScoringDashboard() {
  const [score, setScore] = useState<any | null>(null);
  const [controls, setControls] = useState<any[]>([]);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, c, sn] = await Promise.allSettled([
        apiFetch<any>("/api/v1/posture-scoring/score"),
        apiFetch<any>("/api/v1/posture-scoring/controls"),
        apiFetch<any>("/api/v1/posture-scoring/snapshots"),
      ]);
      if (s.status === "fulfilled") { setScore(s.value); }
      if (c.status === "fulfilled") { const v = c.value as any; setControls(Array.isArray(v) ? v : (v.controls ?? v.items ?? [])); }
      if (sn.status === "fulfilled") { const v = sn.value as any; setSnapshots(Array.isArray(v) ? v : (v.snapshots ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const overall = score?.overall_score ?? score?.score ?? 0;
  const implemented = controls.filter(c => c.status === "implemented" || c.implemented).length;
  const gaps = controls.filter(c => c.status === "gap" || !c.implemented).length;
  const level = overall >= 80 ? "Excellent" : overall >= 60 ? "Good" : overall >= 40 ? "Fair" : "Poor";

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><ShieldCheck className="w-6 h-6 text-blue-400" /> Posture Scoring</h1>
          <p className="text-gray-400 text-sm mt-1">Weighted control implementation scoring</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : !score && controls.length === 0 ? <EmptyState icon={ShieldCheck} title="No posture data" description="Configure controls to start scoring." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Overall Score</p><p className={`text-3xl font-bold mt-1 ${overall >= 80 ? "text-green-400" : overall >= 60 ? "text-amber-400" : "text-red-400"}`}>{overall}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Implemented</p><p className="text-3xl font-bold text-green-400 mt-1">{implemented}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Gaps</p><p className="text-3xl font-bold text-red-400 mt-1">{gaps}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Level</p><p className="text-3xl font-bold text-purple-400 mt-1">{level}</p></div>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Controls</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Control</th><th className="text-left pb-2 pr-4">Category</th><th className="text-left pb-2 pr-4">Weight</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2">Score</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{controls.map(c => (
                <tr key={c.id ?? c.control_id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200">{c.name ?? c.control_name}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{c.category ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-300">{c.weight ?? 1}</td>
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs ${c.status === "implemented" || c.implemented ? "bg-green-700 text-green-100" : "bg-red-700 text-red-100"}`}>{c.status ?? (c.implemented ? "implemented" : "gap")}</span></td>
                  <td className="py-3 text-gray-300">{c.score ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
          {snapshots.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Recent Snapshots</h2>
            <div className="space-y-2">{snapshots.slice(0, 10).map((s, i) => (
              <div key={s.id ?? i} className="flex items-center justify-between p-2 bg-gray-700/30 rounded text-sm">
                <span className="text-gray-300">{s.date ?? s.created_at}</span>
                <span className={`font-bold ${(s.score ?? 0) >= 80 ? "text-green-400" : (s.score ?? 0) >= 60 ? "text-amber-400" : "text-red-400"}`}>{s.score}</span>
              </div>
            ))}</div>
          </div>}
        </>}
    </div>
  );
}
