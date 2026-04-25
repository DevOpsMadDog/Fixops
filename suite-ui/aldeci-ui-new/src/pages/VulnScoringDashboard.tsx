/**
 * Vulnerability Scoring Dashboard - Live API
 * Route: /vuln-scoring
 * API: GET /api/v1/vuln-scoring/scores, /distribution
 */

import { useState, useEffect } from "react";
import { ShieldAlert, BarChart2, SlidersHorizontal, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

type Priority = "P1" | "P2" | "P3" | "P4";

interface VulnEntry {
  id: string; cve: string; title: string; priority: Priority;
  composite_score: number; cvss: number; epss: number; kev: boolean;
  exposure: number; assets_affected: number; status: string;
}

const MODEL_WEIGHTS = [
  { component: "CVSS Base Score", weight: 30 },
  { component: "EPSS Probability", weight: 25 },
  { component: "KEV Status", weight: 25 },
  { component: "Exposure Score", weight: 20 },
];

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const priorityColor = (p: Priority) => p === "P1" ? { bg: "bg-red-500/20", text: "text-red-300" }
  : p === "P2" ? { bg: "bg-orange-500/20", text: "text-orange-300" }
  : p === "P3" ? { bg: "bg-yellow-500/20", text: "text-yellow-300" }
  : { bg: "bg-gray-500/20", text: "text-gray-400" };
const scoreColor = (s: number) => s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-yellow-400" : "text-green-400";
const scoreBarColor = (s: number) => s >= 80 ? "bg-red-500" : s >= 60 ? "bg-orange-400" : s >= 40 ? "bg-yellow-400" : "bg-green-500";
const statusBadge = (s: string) => s === "open" ? "bg-red-500/20 text-red-300" : s === "in-progress" ? "bg-blue-500/20 text-blue-300" : "bg-green-500/20 text-green-300";
const priorityFromScore = (s: number): Priority => s >= 80 ? "P1" : s >= 60 ? "P2" : s >= 40 ? "P3" : "P4";

export default function VulnScoringDashboard() {
  const [vulns, setVulns] = useState<VulnEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filterPriority, setFilterPriority] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/vuln-scoring/scores");
      const arr = Array.isArray(v) ? v : (v.scores ?? v.items ?? []);
      const mapped: VulnEntry[] = arr.map((s: any, i: number) => ({
        id: s.id ?? s.score_id ?? `v${i}`,
        cve: s.cve ?? s.vuln_id ?? "—",
        title: s.title ?? s.summary ?? "Untitled",
        priority: priorityFromScore(s.composite_score ?? 0),
        composite_score: Math.round(s.composite_score ?? 0),
        cvss: s.cvss ?? 0, epss: s.epss ?? 0, kev: !!s.kev,
        exposure: s.exposure ?? 0, assets_affected: s.assets_affected ?? 0,
        status: s.status ?? "open",
      }));
      setVulns(mapped);
      if (mapped.length && !selectedId) setSelectedId(mapped[0].id);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const selected = vulns.find(v => v.id === selectedId) ?? null;
  const filtered = filterPriority === "all" ? vulns : vulns.filter(v => v.priority === filterPriority);
  const distribution = [
    { label: "P1", count: vulns.filter(v => v.priority === "P1").length, color: "#ef4444" },
    { label: "P2", count: vulns.filter(v => v.priority === "P2").length, color: "#f97316" },
    { label: "P3", count: vulns.filter(v => v.priority === "P3").length, color: "#eab308" },
    { label: "P4", count: vulns.filter(v => v.priority === "P4").length, color: "#6b7280" },
  ];
  const total = distribution.reduce((s, d) => s + d.count, 0);
  const avgScore = vulns.length ? Math.round(vulns.reduce((s, v) => s + v.composite_score, 0) / vulns.length) : 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><ShieldAlert className="w-6 h-6 text-orange-400" /> Vulnerability Scoring</h1>
          <p className="text-gray-400 text-sm mt-1">Composite risk prioritization — CVSS + EPSS + KEV + Exposure</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : vulns.length === 0 ? <EmptyState icon={ShieldAlert} title="No scored vulnerabilities" description="Once vulnerabilities are scored, they appear here." />
        : <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[{label:"Total",value:vulns.length,color:"text-white"},{label:"P1",value:vulns.filter(v=>v.priority==="P1").length,color:"text-red-400"},{label:"KEV",value:vulns.filter(v=>v.kev).length,color:"text-orange-400"},{label:"Avg Score",value:avgScore,color:"text-amber-400"}].map(k=>(
              <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
                <div className={`text-3xl font-bold ${k.color}`}>{k.value}</div>
                <div className="text-gray-400 text-xs mt-1">{k.label}</div>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            {["all","P1","P2","P3","P4"].map(p => (
              <button key={p} onClick={() => setFilterPriority(p)} className={`px-3 py-1 rounded-full text-xs font-medium ${filterPriority===p?"bg-indigo-600 text-white":"bg-gray-700 text-gray-300 hover:bg-gray-600"}`}>{p === "all" ? "All" : p}</button>
            ))}
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white">Priority Queue</h2></div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                    <th className="text-left p-3">Pri</th><th className="text-left p-3">CVE</th>
                    <th className="text-left p-3 hidden sm:table-cell">Title</th><th className="text-left p-3">Score</th>
                    <th className="text-left p-3 hidden md:table-cell">KEV</th><th className="text-left p-3">Status</th>
                  </tr></thead>
                  <tbody>
                    {filtered.map(v => {
                      const pc = priorityColor(v.priority);
                      return (
                        <tr key={v.id} onClick={() => setSelectedId(v.id)} className={`border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/40 ${selectedId === v.id ? "bg-gray-700/60" : ""}`}>
                          <td className="p-3"><span className={`px-2 py-0.5 rounded-full text-xs font-bold ${pc.bg} ${pc.text}`}>{v.priority}</span></td>
                          <td className="p-3 text-gray-300 font-mono text-xs">{v.cve}</td>
                          <td className="p-3 text-gray-200 hidden sm:table-cell max-w-[180px] truncate">{v.title}</td>
                          <td className="p-3"><div className="flex items-center gap-2"><span className={`font-bold text-sm ${scoreColor(v.composite_score)}`}>{v.composite_score}</span><div className="w-16 bg-gray-700 rounded-full h-1.5 hidden sm:block"><div className={`h-1.5 rounded-full ${scoreBarColor(v.composite_score)}`} style={{ width: `${v.composite_score}%` }} /></div></div></td>
                          <td className="p-3 hidden md:table-cell">{v.kev ? <span className="bg-red-500/20 text-red-300 text-xs px-2 py-0.5 rounded-full font-medium">KEV</span> : <span className="text-gray-600 text-xs">—</span>}</td>
                          <td className="p-3"><span className={`text-xs px-2 py-0.5 rounded-full capitalize ${statusBadge(v.status)}`}>{v.status}</span></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
            <div className="space-y-4">
              {selected && (
                <div className="bg-gray-800 rounded-lg p-5">
                  <h2 className="font-semibold text-white text-sm mb-3">Score Breakdown: {selected.cve}</h2>
                  <div className={`text-4xl font-bold mb-4 ${scoreColor(selected.composite_score)}`}>{selected.composite_score}<span className="text-lg text-gray-400">/100</span></div>
                  <div className="space-y-3">
                    {[{label:"CVSS",value:Math.round(selected.cvss*10),display:selected.cvss.toFixed(1)},{label:"EPSS",value:Math.round(selected.epss*100),display:`${(selected.epss*100).toFixed(0)}%`},{label:"KEV",value:selected.kev?100:0,display:selected.kev?"Listed":"Not Listed"},{label:"Exposure",value:selected.exposure,display:`${selected.exposure}%`}].map(c => (
                      <div key={c.label}>
                        <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">{c.label}</span><span className="text-gray-300 font-medium">{c.display}</span></div>
                        <div className="w-full bg-gray-700 rounded-full h-2"><div className={`h-2 rounded-full ${scoreBarColor(c.value)}`} style={{ width: `${c.value}%` }} /></div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 text-xs text-gray-400">Assets affected: <span className="text-white font-semibold">{selected.assets_affected}</span></div>
                </div>
              )}
              <div className="bg-gray-800 rounded-lg p-5">
                <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2"><SlidersHorizontal className="w-4 h-4 text-indigo-400" /> Model Weights</h2>
                <div className="space-y-3">{MODEL_WEIGHTS.map(w => (
                  <div key={w.component}>
                    <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">{w.component}</span><span className="text-gray-300">{w.weight}%</span></div>
                    <div className="w-full bg-gray-700 rounded-full h-1.5"><div className="h-1.5 rounded-full bg-indigo-500" style={{ width: `${w.weight}%` }} /></div>
                  </div>
                ))}</div>
              </div>
              <div className="bg-gray-800 rounded-lg p-5">
                <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-orange-400" /> Distribution</h2>
                <div className="space-y-2">{distribution.map(d => (
                  <div key={d.label} className="flex items-center gap-3">
                    <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                    <div className="flex-1">
                      <div className="flex justify-between text-xs mb-0.5"><span className="text-gray-300">{d.label}</span><span className="text-gray-400">{d.count}/{total}</span></div>
                      <div className="w-full bg-gray-700 rounded-full h-2"><div className="h-2 rounded-full" style={{ backgroundColor: d.color, width: total ? `${(d.count/total)*100}%` : "0%" }} /></div>
                    </div>
                  </div>
                ))}</div>
              </div>
            </div>
          </div>
        </>}
    </div>
  );
}
