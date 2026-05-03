// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Security OKR Dashboard - Live API
 * Route: /security-okrs
 * API: GET /api/v1/security-okrs/{objectives,key-results}
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

const krStatusCfg: Record<string, { label: string; color: string }> = {
  on_track: { label: "On Track", color: "bg-green-700 text-green-100" },
  at_risk: { label: "At Risk", color: "bg-amber-700 text-amber-100" },
  off_track: { label: "Off Track", color: "bg-red-700 text-red-100" },
  completed: { label: "Completed", color: "bg-blue-700 text-blue-100" },
};
const progressColor = (pct: number) => pct >= 70 ? "bg-green-500" : pct >= 30 ? "bg-amber-500" : "bg-red-500";
const progressTextColor = (pct: number) => pct >= 70 ? "text-green-400" : pct >= 30 ? "text-amber-400" : "text-red-400";

function krProgress(kr: any) {
  const target = kr.target ?? 0, current = kr.current ?? 0;
  if (target === 0) return current === 0 ? 100 : Math.max(0, 100 - current * 10);
  return Math.min(100, Math.round((current / target) * 100));
}

export default function SecurityOKRDashboard() {
  const [objectives, setObjectives] = useState<any[]>([]);
  const [keyResults, setKeyResults] = useState<any[]>([]);
  const [period, setPeriod] = useState<string>("");
  const [selectedObjective, setSelectedObjective] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [o, k] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-okrs/objectives"),
        apiFetch<any>("/api/v1/security-okrs/key-results"),
      ]);
      if (o.status === "fulfilled") {
        const v = o.value as any;
        const arr = Array.isArray(v) ? v : (v.objectives ?? v.items ?? []);
        setObjectives(arr);
        if (arr.length) {
          if (!selectedObjective) setSelectedObjective(arr[0].id);
          if (!period) setPeriod(arr[0].period);
        }
      }
      if (k.status === "fulfilled") {
        const v = k.value as any;
        setKeyResults(Array.isArray(v) ? v : (v.key_results ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const periods = Array.from(new Set(objectives.map(o => o.period).filter(Boolean)));
  const filteredObj = period ? objectives.filter(o => o.period === period) : objectives;
  const onTrack = filteredObj.filter(o => (o.overall_progress ?? 0) >= 70).length;
  const atRisk = filteredObj.filter(o => (o.overall_progress ?? 0) >= 30 && (o.overall_progress ?? 0) < 70).length;
  const offTrack = filteredObj.filter(o => (o.overall_progress ?? 0) < 30).length;
  const selectedObj = filteredObj.find(o => o.id === selectedObjective);
  const selectedKRs = keyResults.filter(kr => kr.objective_id === selectedObjective);
  const teams = Array.from(new Set(filteredObj.map(o => o.team).filter(Boolean)));

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Target className="w-6 h-6 text-blue-400" /> Security OKRs</h1>
          <p className="text-gray-400 mt-1">Objectives and Key Results for the security program</p>
        </div>
        <div className="flex gap-2 items-center">
          {periods.length > 0 && <div className="flex gap-2 bg-gray-800 rounded-lg p-1">{periods.map(p => (
            <button key={p} onClick={() => setPeriod(p)} className={`px-3 py-1.5 rounded text-sm font-medium ${period === p ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>{p}</button>
          ))}</div>}
          <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
        </div>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : objectives.length === 0 ? <EmptyState icon={Target} title="No OKRs defined" description="Create objectives and key results to start tracking." />
        : <>
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: "On Track", value: onTrack, color: "text-green-400", border: "border-green-800" },
              { label: "At Risk", value: atRisk, color: "text-amber-400", border: "border-amber-800" },
              { label: "Off Track", value: offTrack, color: "text-red-400", border: "border-red-800" },
            ].map(s => (
              <div key={s.label} className={`bg-gray-800 rounded-lg p-6 border ${s.border}`}>
                <p className="text-gray-400 text-sm">{s.label}</p>
                <p className={`text-4xl font-bold mt-1 ${s.color}`}>{s.value}</p>
                <p className="text-gray-500 text-xs mt-1">objective{s.value !== 1 ? "s" : ""}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-3">
              <h2 className="text-lg font-semibold text-white">Objectives</h2>
              {filteredObj.length === 0 ? <p className="text-gray-500 text-sm">No objectives for this period.</p>
                : filteredObj.map(obj => (
                  <div key={obj.id} onClick={() => setSelectedObjective(obj.id)} className={`bg-gray-800 rounded-lg p-4 cursor-pointer border-2 ${selectedObjective === obj.id ? "border-blue-500" : "border-transparent hover:border-gray-600"}`}>
                    <p className="text-white text-sm font-medium leading-snug">{obj.title}</p>
                    <p className="text-gray-500 text-xs mt-1">{obj.team} · {obj.owner}</p>
                    <div className="mt-3 flex items-center gap-2">
                      <div className="flex-1 bg-gray-700 rounded-full h-2"><div className={`h-2 rounded-full ${progressColor(obj.overall_progress ?? 0)}`} style={{ width: `${obj.overall_progress ?? 0}%` }} /></div>
                      <span className={`text-xs font-bold ${progressTextColor(obj.overall_progress ?? 0)}`}>{obj.overall_progress ?? 0}%</span>
                    </div>
                  </div>
                ))}
            </div>
            <div className="lg:col-span-2 space-y-4">
              <h2 className="text-lg font-semibold text-white">Key Results — {selectedObj?.title?.slice(0, 50) ?? "Select objective"}</h2>
              {selectedKRs.length === 0 ? <p className="text-gray-500 text-sm">No key results for this objective.</p>
                : selectedKRs.map(kr => {
                  const progress = krProgress(kr);
                  return (
                    <div key={kr.id} className="bg-gray-800 rounded-lg p-5 space-y-3">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1">
                          <p className="text-white font-medium">{kr.title}</p>
                          <p className="text-gray-400 text-xs mt-0.5">Owner: {kr.owner ?? "—"}</p>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${(krStatusCfg[kr.status] ?? krStatusCfg.on_track).color}`}>{(krStatusCfg[kr.status] ?? { label: kr.status }).label}</span>
                      </div>
                      <div className="flex items-center gap-4 text-sm">
                        <div><p className="text-gray-500 text-xs">Current</p><p className={`font-bold text-lg ${progressTextColor(progress)}`}>{kr.current ?? 0} <span className="text-xs font-normal text-gray-400">{kr.unit}</span></p></div>
                        <div className="flex-1 h-px bg-gray-700" />
                        <div className="text-right"><p className="text-gray-500 text-xs">Target</p><p className="font-bold text-lg text-gray-300">{kr.target ?? 0} <span className="text-xs font-normal text-gray-400">{kr.unit}</span></p></div>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2"><div className={`h-2 rounded-full ${progressColor(progress)}`} style={{ width: `${Math.min(100, progress)}%` }} /></div>
                      {kr.notes && <p className="text-gray-400 text-xs italic">{kr.notes}</p>}
                    </div>
                  );
                })}
            </div>
          </div>

          {teams.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Team OKR View</h2>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">{teams.map(team => {
              const teamObjs = filteredObj.filter(o => o.team === team);
              const avg = Math.round(teamObjs.reduce((s, o) => s + (o.overall_progress ?? 0), 0) / (teamObjs.length || 1));
              return (
                <div key={team} className="bg-gray-700/50 rounded-lg p-4 text-center">
                  <p className="text-gray-300 text-xs font-medium mb-2">{team}</p>
                  <div className="relative w-16 h-16 mx-auto">
                    <svg viewBox="0 0 36 36" className="w-16 h-16 -rotate-90">
                      <circle cx="18" cy="18" r="15.9" fill="none" stroke="#374151" strokeWidth="3" />
                      <circle cx="18" cy="18" r="15.9" fill="none" stroke={avg >= 70 ? "#22c55e" : avg >= 30 ? "#f59e0b" : "#ef4444"} strokeWidth="3" strokeDasharray={`${avg} 100`} strokeLinecap="round" />
                    </svg>
                    <span className="absolute inset-0 flex items-center justify-center text-white text-xs font-bold">{avg}%</span>
                  </div>
                  <p className="text-gray-500 text-xs mt-2">{teamObjs.length} obj</p>
                </div>
              );
            })}</div>
          </div>}
        </>}
    </div>
  );
}
