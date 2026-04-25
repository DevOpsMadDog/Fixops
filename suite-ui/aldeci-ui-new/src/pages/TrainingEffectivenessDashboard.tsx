/**
 * Security Training Effectiveness Dashboard - Live API
 * Route: /training-effectiveness
 * API: GET /api/v1/training-effectiveness/programs
 */
import { useState, useEffect } from "react";
import { BookOpen, RefreshCw, Award } from "lucide-react";
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

const typeColor: Record<string, string> = {
  phishing: "bg-red-800 text-red-200",
  password_security: "bg-blue-800 text-blue-200",
  compliance: "bg-purple-800 text-purple-200",
  secure_coding: "bg-cyan-800 text-cyan-200",
  incident_response: "bg-orange-800 text-orange-200",
};

export default function TrainingEffectivenessDashboard() {
  const [programs, setPrograms] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/training-effectiveness/programs");
      setPrograms(Array.isArray(v) ? v : (v.programs ?? v.items ?? []));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const avgCompletion = programs.length ? (programs.reduce((s, p) => s + (p.completion_rate ?? 0), 0) / programs.length).toFixed(1) : "0";
  const avgScore = programs.length ? (programs.reduce((s, p) => s + (p.avg_score ?? 0), 0) / programs.length).toFixed(1) : "0";
  const totalEnrolled = programs.reduce((s, p) => s + (p.enrolled_count ?? 0), 0);
  const totalCompleted = programs.reduce((s, p) => s + (p.completed_count ?? 0), 0);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><BookOpen className="w-6 h-6 text-green-400" /> Training Effectiveness</h1>
          <p className="text-gray-400 text-sm mt-1">Completion rates, score improvements, retention trends</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-green-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : programs.length === 0 ? <EmptyState icon={BookOpen} title="No training programs" description="Enroll programs to track effectiveness." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Avg Completion", value: `${avgCompletion}%`, color: "text-green-400" },
              { label: "Avg Score", value: `${avgScore}%`, color: "text-blue-400" },
              { label: "Total Enrolled", value: totalEnrolled, color: "text-purple-400" },
              { label: "Total Completed", value: totalCompleted, color: "text-cyan-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><Award className="w-4 h-4 text-green-400" /> Training Programs</h2>
            <div className="space-y-4">{programs.map(prog => (
              <div key={prog.id} className="bg-gray-700/30 rounded-lg p-4 border border-gray-700">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${typeColor[prog.training_type] || "bg-gray-700 text-gray-200"}`}>{(prog.training_type ?? "").replace("_", " ")}</span>
                      <span className="text-white font-medium">{prog.program_name ?? prog.name}</span>
                    </div>
                    <p className="text-gray-400 text-xs">{prog.completed_count ?? 0} / {prog.enrolled_count ?? 0} completed</p>
                  </div>
                  <div className="text-right">
                    <div className="text-green-400 font-bold text-sm">+{Number(prog.score_improvement ?? 0).toFixed(1)}%</div>
                    <div className="text-gray-500 text-xs">improvement</div>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">Completion</span><span className="text-gray-300">{Number(prog.completion_rate ?? 0).toFixed(1)}%</span></div>
                    <div className="w-full bg-gray-700 rounded-full h-2"><div className="h-2 rounded-full bg-green-500" style={{ width: `${prog.completion_rate ?? 0}%` }} /></div>
                  </div>
                  <div>
                    <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">Avg Score</span><span className="text-gray-300">{Number(prog.avg_score ?? 0).toFixed(1)}%</span></div>
                    <div className="w-full bg-gray-700 rounded-full h-2"><div className="h-2 rounded-full bg-blue-500" style={{ width: `${prog.avg_score ?? 0}%` }} /></div>
                  </div>
                </div>
              </div>
            ))}</div>
          </div>
        </>}
    </div>
  );
}
