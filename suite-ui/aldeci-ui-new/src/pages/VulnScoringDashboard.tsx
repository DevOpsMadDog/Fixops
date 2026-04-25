/**
 * Vulnerability Scoring Dashboard - Live API
 * Route: /vuln-scoring
 * API: GET /api/v1/vuln-scoring/scores
 */

import { useState, useEffect } from "react";
import { ShieldAlert, BarChart2, SlidersHorizontal, RefreshCw } from "lucide-react";
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

type Priority = "P1" | "P2" | "P3" | "P4";

function priorityColor(p: Priority) {
  return p === "P1" ? { bg: "bg-red-500/20", text: "text-red-300" }
    : p === "P2" ? { bg: "bg-orange-500/20", text: "text-orange-300" }
    : p === "P3" ? { bg: "bg-yellow-500/20", text: "text-yellow-300" }
    : { bg: "bg-gray-500/20", text: "text-gray-400" };
}
function scoreColor(s: number) { return s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-yellow-400" : "text-green-400"; }
function scoreBarColor(s: number) { return s >= 80 ? "bg-red-500" : s >= 60 ? "bg-orange-400" : s >= 40 ? "bg-yellow-400" : "bg-green-500"; }
function statusBadge(s: string) { return s === "open" ? "bg-red-500/20 text-red-300" : s === "in-progress" || s === "in_progress" ? "bg-blue-500/20 text-blue-300" : "bg-green-500/20 text-green-300"; }

function priorityFromScore(score: number): Priority {
  return score >= 80 ? "P1" : score >= 60 ? "P2" : score >= 40 ? "P3" : "P4";
}

export default function VulnScoringDashboard() {
  const [vulns, setVulns] = useState<any[]>([]);
  const [overrides, setOverrides] = useState<any[]>([]);
  const [assetRisks, setAssetRisks] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filterPriority, setFilterPriority] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [scoresRes, overridesRes, assetsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/vuln-scoring/scores"),
        apiFetch<any>("/api/v1/vuln-scoring/overrides"),
        apiFetch<any>("/api/v1/vuln-scoring/asset-risks"),
      ]);
      if (scoresRes.status === "fulfilled") {
        const v = scoresRes.value;
        const arr = Array.isArray(v) ? v : (v.scores ?? v.items ?? v.vulns ?? []);
        const normalized = arr.map((x: any) => ({
          ...x,
          priority: x.priority ?? priorityFromScore(x.composite_score ?? x.score ?? 0),
          composite_score: x.composite_score ?? x.score ?? 0,
        }));
        setVulns(normalized);
        if (normalized.length && !selectedId) setSelectedId(normalized[0].id);
      }
      if (overridesRes.status === "fulfilled") {
        const v = overridesRes.value;
        setOverrides(Array.isArray(v) ? v : (v.overrides ?? v.items ?? []));
      }
      if (assetsRes.status === "fulfilled") {
        const v = assetsRes.value;
        setAssetRisks(Array.isArray(v) ? v : (v.assets ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const selected = vulns.find(v => v.id === selectedId) ?? null;
  const filtered = filterPriority === "all" ? vulns : vulns.filter(v => v.priority === filterPriority);
  const distribution = (["P1", "P2", "P3", "P4"] as Priority[]).map((p, i) => ({
    label: ["P1 Critical", "P2 High", "P3 Medium", "P4 Low"][i],
    count: vulns.filter(v => v.priority === p).length,
    color: ["#ef4444", "#f97316", "#eab308", "#6b7280"][i],
  }));
  const total = distribution.reduce((s, d) => s + d.count, 0);
  const MODEL_WEIGHTS = [
    { component: "CVSS Base Score", weight: 30 },
    { component: "EPSS Probability", weight: 25 },
    { component: "KEV Status", weight: 25 },
    { component: "Exposure Score", weight: 20 },
  ];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><ShieldAlert className="w-6 h-6 text-orange-400" /> Vulnerability Scoring</h1>
          <p className="text-gray-400 text-sm mt-1">Composite risk prioritization — CVSS + EPSS + KEV + Exposure</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : vulns.length === 0 ? <EmptyState icon={ShieldAlert} title="No vulnerability scores" description="No scored vulnerabilities yet. Trigger a scan to populate." />
        : <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Total", value: vulns.length, color: "text-white" },
              { label: "P1 Critical", value: vulns.filter(v => v.priority === "P1").length, color: "text-red-400" },
              { label: "KEV Listed", value: vulns.filter(v => v.kev).length, color: "text-orange-400" },
              { label: "Avg Score", value: vulns.length ? Math.round(vulns.reduce((s, v) => s + (v.composite_score ?? 0), 0) / vulns.length) : 0, color: "text-amber-400" },
            ].map(k => (
              <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
                <div className={`text-3xl font-bold ${k.color}`}>{k.value}</div>
                <div className="text-gray-400 text-xs mt-1">{k.label}</div>
              </div>
            ))}
          </div>

          <div className="flex gap-2">
            {["all", "P1", "P2", "P3", "P4"].map(p => (
              <button key={p} onClick={() => setFilterPriority(p)} className={`px-3 py-1 rounded-full text-xs font-medium ${filterPriority === p ? "bg-indigo-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}>{p === "all" ? "All" : p}</button>
            ))}
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white">Priority Queue</h2></div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead><tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                    <th className="text-left p-3">Priority</th><th className="text-left p-3">CVE</th><th className="text-left p-3 hidden sm:table-cell">Title</th><th className="text-left p-3">Score</th><th className="text-left p-3 hidden md:table-cell">KEV</th><th className="text-left p-3">Status</th>
                  </tr></thead>
                  <tbody>
                    {filtered.map(v => {
                      const pc = priorityColor(v.priority);
                      return (
                        <tr key={v.id} onClick={() => setSelectedId(v.id)} className={`border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/40 ${selectedId === v.id ? "bg-gray-700/60" : ""}`}>
                          <td className="p-3"><span className={`px-2 py-0.5 rounded-full text-xs font-bold ${pc.bg} ${pc.text}`}>{v.priority}</span></td>
                          <td className="p-3 text-gray-300 font-mono text-xs">{v.cve ?? v.cve_id ?? "—"}</td>
                          <td className="p-3 text-gray-200 hidden sm:table-cell max-w-[180px] truncate">{v.title ?? v.name ?? "—"}</td>
                          <td className="p-3"><div className="flex items-center gap-2"><span className={`font-bold text-sm ${scoreColor(v.composite_score)}`}>{v.composite_score}</span><div className="w-16 bg-gray-700 rounded-full h-1.5 hidden sm:block"><div className={`h-1.5 rounded-full ${scoreBarColor(v.composite_score)}`} style={{ width: `${v.composite_score}%` }} /></div></div></td>
                          <td className="p-3 hidden md:table-cell">{v.kev ? <span className="bg-red-500/20 text-red-300 text-xs px-2 py-0.5 rounded-full font-medium">KEV</span> : <span className="text-gray-600 text-xs">—</span>}</td>
                          <td className="p-3"><span className={`text-xs px-2 py-0.5 rounded-full capitalize ${statusBadge(v.status ?? "open")}`}>{(v.status ?? "open").replace("_", "-")}</span></td>
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
                  <h2 className="font-semibold text-white text-sm mb-3">Score Breakdown: {selected.cve ?? selected.cve_id ?? selected.id}</h2>
                  <div className={`text-4xl font-bold mb-4 ${scoreColor(selected.composite_score)}`}>{selected.composite_score}<span className="text-lg text-gray-400">/100</span></div>
                  <div className="space-y-3">
                    {[
                      { label: "CVSS", value: Math.round((selected.cvss ?? 0) * 10), display: (selected.cvss ?? 0).toFixed(1) },
                      { label: "EPSS", value: Math.round((selected.epss ?? 0) * 100), display: `${((selected.epss ?? 0) * 100).toFixed(0)}%` },
                      { label: "KEV", value: selected.kev ? 100 : 0, display: selected.kev ? "Listed" : "Not Listed" },
                      { label: "Exposure", value: selected.exposure ?? 0, display: `${selected.exposure ?? 0}%` },
                    ].map(c => (
                      <div key={c.label}>
                        <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">{c.label}</span><span className="text-gray-300 font-medium">{c.display}</span></div>
                        <div className="w-full bg-gray-700 rounded-full h-2"><div className={`h-2 rounded-full ${scoreBarColor(c.value)}`} style={{ width: `${c.value}%` }} /></div>
                      </div>
                    ))}
                  </div>
                  <div className="mt-3 text-xs text-gray-400">Assets affected: <span className="text-white font-semibold">{selected.assets_affected ?? 0}</span></div>
                </div>
              )}

              <div className="bg-gray-800 rounded-lg p-5">
                <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2"><SlidersHorizontal className="w-4 h-4 text-indigo-400" /> Model Weights</h2>
                <div className="space-y-3">
                  {MODEL_WEIGHTS.map(w => (
                    <div key={w.component}>
                      <div className="flex justify-between text-xs mb-1"><span className="text-gray-400">{w.component}</span><span className="text-gray-300">{w.weight}%</span></div>
                      <div className="w-full bg-gray-700 rounded-full h-1.5"><div className="h-1.5 rounded-full bg-indigo-500" style={{ width: `${w.weight}%` }} /></div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-gray-800 rounded-lg p-5">
                <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2"><BarChart2 className="w-4 h-4 text-orange-400" /> Distribution</h2>
                <div className="space-y-2">
                  {distribution.map(d => (
                    <div key={d.label} className="flex items-center gap-3">
                      <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                      <div className="flex-1">
                        <div className="flex justify-between text-xs mb-0.5"><span className="text-gray-300">{d.label}</span><span className="text-gray-400">{d.count}/{total}</span></div>
                        <div className="w-full bg-gray-700 rounded-full h-2"><div className="h-2 rounded-full" style={{ backgroundColor: d.color, width: total ? `${(d.count / total) * 100}%` : "0%" }} /></div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white text-sm">Override History</h2></div>
              {overrides.length === 0 ? <div className="p-6 text-gray-500 text-sm">No score overrides recorded.</div>
                : <div className="divide-y divide-gray-700/50">{overrides.map(ov => (
                  <div key={ov.id} className="p-4">
                    <div className="flex items-center gap-2 mb-1"><span className="font-mono text-xs text-gray-300">{ov.cve ?? ov.cve_id}</span><span className="text-gray-500 text-xs">{ov.original_score} → <span className="text-white font-semibold">{ov.override_score}</span></span></div>
                    <p className="text-gray-400 text-xs">{ov.reason}</p>
                    <div className="text-gray-500 text-xs mt-1">{ov.overridden_by} · {ov.date}</div>
                  </div>
                ))}</div>}
            </div>

            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white text-sm">Asset Risk Scores</h2></div>
              {assetRisks.length === 0 ? <div className="p-6 text-gray-500 text-sm">No asset risk scores yet.</div>
                : <div className="overflow-x-auto"><table className="w-full text-sm">
                  <thead><tr className="border-b border-gray-700 text-gray-400 text-xs uppercase"><th className="text-left p-3">Asset</th><th className="text-left p-3">Type</th><th className="text-left p-3">Risk</th><th className="text-left p-3">Vulns</th></tr></thead>
                  <tbody>{assetRisks.map(a => (
                    <tr key={a.asset ?? a.id} className="border-b border-gray-700/50">
                      <td className="p-3 text-gray-200 font-mono text-xs">{a.asset ?? a.name}</td>
                      <td className="p-3 text-gray-400 text-xs">{a.asset_type ?? a.type ?? "—"}</td>
                      <td className="p-3"><div className="flex items-center gap-2"><span className={`font-bold text-sm ${scoreColor(a.risk_score ?? 0)}`}>{a.risk_score ?? 0}</span><div className="w-12 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${scoreBarColor(a.risk_score ?? 0)}`} style={{ width: `${a.risk_score ?? 0}%` }} /></div></div></td>
                      <td className="p-3"><span className="text-gray-300 text-xs">{a.open_vulns ?? 0}</span>{(a.critical_count ?? 0) > 0 && <span className="text-red-400 text-xs ml-1">({a.critical_count} crit)</span>}</td>
                    </tr>
                  ))}</tbody>
                </table></div>}
            </div>
          </div>
        </>}
    </div>
  );
}
