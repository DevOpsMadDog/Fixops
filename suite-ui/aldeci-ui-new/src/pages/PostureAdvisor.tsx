// FOLDED into Remediate hero 2026-04-27 — preserve for git history
// Tab path: /remediate?tab=posture-advisor
/**
 * Posture Advisor - Live API
 * Route: /posture-advisor
 * API: GET /api/v1/posture-advisor/{score,recommendations,roadmap,stats}
 */
import { useState, useEffect } from "react";
import { Lightbulb, RefreshCw, Target, CheckCircle2, AlertCircle } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...init, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const sevColor: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
};
const statusColor: Record<string, string> = {
  open: "bg-amber-700 text-amber-100",
  accepted: "bg-blue-700 text-blue-100",
  in_progress: "bg-purple-700 text-purple-100",
  completed: "bg-green-700 text-green-100",
  dismissed: "bg-gray-600 text-gray-200",
};

export default function PostureAdvisor() {
  const [score, setScore] = useState<any | null>(null);
  const [recs, setRecs] = useState<any[]>([]);
  const [roadmap, setRoadmap] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, r, rm, st] = await Promise.allSettled([
        apiFetch<any>("/api/v1/posture-advisor/score"),
        apiFetch<any>("/api/v1/posture-advisor/recommendations"),
        apiFetch<any>("/api/v1/posture-advisor/roadmap"),
        apiFetch<any>("/api/v1/posture-advisor/stats"),
      ]);
      if (s.status === "fulfilled") { setScore(s.value); }
      if (r.status === "fulfilled") { const v = r.value as any; setRecs(Array.isArray(v) ? v : (v.recommendations ?? v.items ?? [])); }
      if (rm.status === "fulfilled") { const v = rm.value as any; setRoadmap(Array.isArray(v) ? v : (v.roadmap ?? v.items ?? [])); }
      if (st.status === "fulfilled") { setStats(st.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const action = async (recId: string, kind: "accept" | "complete" | "dismiss") => {
    try {
      await apiFetch<any>(`/api/v1/posture-advisor/recommendations/${recId}/${kind}`, { method: "POST" });
      load();
    } catch (e) { setError((e as Error).message); }
  };

  const filtered = filter === "all" ? recs : recs.filter(r => r.severity === filter || r.status === filter);
  const sevs = Array.from(new Set(recs.map(r => r.severity).filter(Boolean)));

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Lightbulb className="w-6 h-6 text-amber-400" /> Posture Advisor</h1>
          <p className="text-gray-400 text-sm mt-1">AI-driven security posture recommendations & roadmap</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-amber-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : recs.length === 0 && !score ? <EmptyState icon={Lightbulb} title="No advisor data" description="Run a posture analysis to generate recommendations." />
        : <>
          {(score || stats) && <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Overall Score</p><p className="text-3xl font-bold text-amber-400 mt-1">{score?.score ?? score?.overall_score ?? 0}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Recommendations</p><p className="text-3xl font-bold text-blue-400 mt-1">{stats?.total_recommendations ?? recs.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Open</p><p className="text-3xl font-bold text-orange-400 mt-1">{recs.filter(r => r.status === "open").length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Completed</p><p className="text-3xl font-bold text-green-400 mt-1">{recs.filter(r => r.status === "completed").length}</p></div>
          </div>}

          {sevs.length > 0 && <div className="flex gap-2 flex-wrap">
            <button onClick={() => setFilter("all")} className={`px-3 py-1.5 rounded text-xs font-medium ${filter === "all" ? "bg-amber-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>All</button>
            {sevs.map(s => (
              <button key={s} onClick={() => setFilter(s)} className={`px-3 py-1.5 rounded text-xs font-medium capitalize ${filter === s ? "bg-amber-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>{s}</button>
            ))}
          </div>}

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><AlertCircle className="w-4 h-4 text-amber-400" /> Recommendations</h2>
            {filtered.length === 0 ? <p className="text-gray-500 text-sm">No recommendations match.</p>
              : <div className="space-y-3">{filtered.map(r => (
                <div key={r.id} className="p-4 rounded-lg border border-gray-700 bg-gray-700/30">
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        {r.severity && <span className={`px-2 py-0.5 rounded text-xs font-bold ${sevColor[r.severity] ?? "bg-gray-700 text-gray-200"}`}>{r.severity}</span>}
                        {r.status && <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[r.status] ?? "bg-gray-700 text-gray-200"}`}>{r.status.replace("_", " ")}</span>}
                        {r.category && <span className="bg-gray-600 text-gray-200 px-2 py-0.5 rounded text-xs">{r.category}</span>}
                      </div>
                      <p className="text-white text-sm font-medium">{r.title ?? r.recommendation}</p>
                      {r.description && <p className="text-gray-400 text-xs mt-1">{r.description}</p>}
                    </div>
                    {r.status === "open" && (
                      <div className="flex flex-col gap-1 shrink-0">
                        <button onClick={() => action(r.id, "accept")} className="px-3 py-1 bg-blue-600 hover:bg-blue-700 rounded text-xs">Accept</button>
                        <button onClick={() => action(r.id, "complete")} className="px-3 py-1 bg-green-600 hover:bg-green-700 rounded text-xs">Complete</button>
                        <button onClick={() => action(r.id, "dismiss")} className="px-3 py-1 bg-gray-600 hover:bg-gray-700 rounded text-xs">Dismiss</button>
                      </div>
                    )}
                  </div>
                </div>
              ))}</div>}
          </div>

          {roadmap.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Target className="w-4 h-4 text-purple-400" /> Improvement Roadmap</h2>
            <div className="space-y-2">{roadmap.map((r, i) => (
              <div key={r.id ?? i} className="flex items-start gap-3 p-3 bg-gray-700/30 rounded-lg">
                <span className="text-purple-400 font-bold">{i + 1}.</span>
                <div className="flex-1">
                  <p className="text-white text-sm font-medium">{r.title ?? r.task}</p>
                  {r.description && <p className="text-gray-400 text-xs mt-1">{r.description}</p>}
                  <div className="flex gap-2 mt-2">
                    {r.priority && <span className="text-xs bg-purple-900 text-purple-300 px-2 py-0.5 rounded">{r.priority}</span>}
                    {r.effort && <span className="text-xs bg-blue-900 text-blue-300 px-2 py-0.5 rounded">{r.effort}</span>}
                    {r.impact && <span className="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded">+{r.impact}</span>}
                  </div>
                </div>
                {r.completed && <CheckCircle2 className="w-5 h-5 text-green-400" />}
              </div>
            ))}</div>
          </div>}
        </>}
    </div>
  );
}
