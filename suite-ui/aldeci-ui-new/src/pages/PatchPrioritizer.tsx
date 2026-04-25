/**
 * Patch Prioritizer - Live API
 * Route: /patch-prioritizer
 * API: GET /api/v1/patch-priority/{queue,stats}
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

export default function PatchPrioritizer() {
  const [queue, setQueue] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [q, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/patch-priority/queue"),
        apiFetch<any>("/api/v1/patch-priority/stats"),
      ]);
      if (q.status === "fulfilled") { const v = q.value as any; setQueue(Array.isArray(v) ? v : (v.queue ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Zap className="w-6 h-6 text-yellow-400" /> Patch Prioritizer</h1>
          <p className="text-gray-400 text-sm mt-1">CVSS + EPSS + KEV composite scoring</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-yellow-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : queue.length === 0 ? <EmptyState icon={Zap} title="No patches in queue" description="The prioritization engine has no patches to score." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Critical Due", value: stats?.critical_due ?? queue.filter(q => q.priority === "P1" || q.severity === "critical").length, color: "text-red-400" },
              { label: "High Priority (week)", value: stats?.high_priority_week ?? queue.filter(q => q.priority === "P2" || q.severity === "high").length, color: "text-orange-400" },
              { label: "SLA Compliance", value: stats?.sla_compliance !== undefined ? `${stats.sla_compliance}%` : "—", color: "text-blue-400" },
              { label: "Avg Time to Patch", value: stats?.avg_time_to_patch ?? "—", color: "text-purple-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Priority Queue</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">CVE</th><th className="text-left pb-2 pr-4">Package</th><th className="text-left pb-2 pr-4">Priority</th><th className="text-left pb-2 pr-4">Score</th><th className="text-left pb-2 pr-4">CVSS</th><th className="text-left pb-2 pr-4">EPSS</th><th className="text-left pb-2">KEV</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{queue.slice(0, 100).map(q => (
                <tr key={q.id ?? q.cve_id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 font-mono text-cyan-300 text-xs">{q.cve_id ?? q.cve}</td>
                  <td className="py-3 pr-4 text-gray-200 font-mono text-xs">{q.package ?? q.package_name ?? "—"}</td>
                  <td className="py-3 pr-4"><span className="bg-yellow-700 text-yellow-100 px-2 py-0.5 rounded text-xs font-bold">{q.priority ?? "—"}</span></td>
                  <td className="py-3 pr-4 text-white font-bold">{q.score ?? q.composite_score ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-300">{q.cvss ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-300">{q.epss !== undefined ? `${(q.epss * 100).toFixed(1)}%` : "—"}</td>
                  <td className="py-3">{q.kev ? <span className="bg-red-700 text-red-100 px-2 py-0.5 rounded text-xs font-bold">KEV</span> : <span className="text-gray-600">—</span>}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
        </>}
    </div>
  );
}
