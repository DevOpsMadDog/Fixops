/**
 * Security Tabletop Dashboard - Live API
 * Route: /security-tabletop
 * API: GET /api/v1/tabletop/{exercises,findings,participants}
 */
import { useState, useEffect } from "react";
import { Users, RefreshCw } from "lucide-react";
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

export default function SecurityTabletopDashboard() {
  const [exercises, setExercises] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [e, f] = await Promise.allSettled([
        apiFetch<any>("/api/v1/tabletop/exercises"),
        apiFetch<any>("/api/v1/tabletop/findings"),
      ]);
      if (e.status === "fulfilled") { const v = e.value as any; setExercises(Array.isArray(v) ? v : (v.exercises ?? v.items ?? [])); }
      if (f.status === "fulfilled") { const v = f.value as any; setFindings(Array.isArray(v) ? v : (v.findings ?? v.items ?? [])); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const completed = exercises.filter(e => e.status === "completed").length;
  const open = findings.filter(f => f.status === "open").length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Users className="w-6 h-6 text-purple-400" /> Security Tabletop</h1>
          <p className="text-gray-400 text-sm mt-1">Tabletop exercises, scoring, findings</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : exercises.length === 0 && findings.length === 0 ? <EmptyState icon={Users} title="No tabletop exercises" description="Schedule a tabletop exercise to start." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Exercises</p><p className="text-3xl font-bold text-blue-400 mt-1">{exercises.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Completed</p><p className="text-3xl font-bold text-green-400 mt-1">{completed}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Findings</p><p className="text-3xl font-bold text-amber-400 mt-1">{findings.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Open Findings</p><p className="text-3xl font-bold text-red-400 mt-1">{open}</p></div>
          </div>
          {exercises.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Exercises</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Scenario</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2 pr-4">Score</th><th className="text-left pb-2">Date</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{exercises.map(e => (
                <tr key={e.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{e.name ?? e.exercise_name}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{e.scenario_type ?? e.scenario}</td>
                  <td className="py-3 pr-4 text-gray-300 capitalize">{e.status}</td>
                  <td className="py-3 pr-4 text-purple-400 font-bold">{e.score ?? "—"}</td>
                  <td className="py-3 text-gray-400 text-xs">{e.date ?? e.scheduled_date}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
