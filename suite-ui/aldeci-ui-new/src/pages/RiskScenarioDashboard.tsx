/**
 * Risk Scenario Dashboard - Live API
 * Route: /risk-scenarios
 * API: GET /api/v1/risk-scenarios/{scenarios,mitigations}
 */
import { useState, useEffect } from "react";
import { ShieldAlert, TrendingDown, BarChart2, Target, Activity, RefreshCw } from "lucide-react";
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

const riskColor: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-black",
  low: "bg-green-600 text-white",
};
const riskText: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-green-400",
};
const mitTypeColor: Record<string, string> = {
  preventive: "bg-blue-900 text-blue-300",
  detective: "bg-purple-900 text-purple-300",
  corrective: "bg-teal-900 text-teal-300",
};

function cellColor(l: number, i: number) {
  const score = l * i;
  if (score >= 64) return "bg-red-700/70";
  if (score >= 36) return "bg-orange-700/60";
  if (score >= 16) return "bg-yellow-700/50";
  return "bg-green-700/40";
}

export default function RiskScenarioDashboard() {
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [mitigationsBySc, setMitigationsBySc] = useState<Record<string, any[]>>({});
  const [selected, setSelected] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [sc, mt] = await Promise.allSettled([
        apiFetch<any>("/api/v1/risk-scenarios/scenarios"),
        apiFetch<any>("/api/v1/risk-scenarios/mitigations"),
      ]);
      let arr: any[] = [];
      if (sc.status === "fulfilled") {
        const v = sc.value as any;
        arr = Array.isArray(v) ? v : (v.scenarios ?? v.items ?? []);
        setScenarios(arr);
        if (arr.length && !selected) setSelected(arr[0]);
      }
      if (mt.status === "fulfilled") {
        const v = mt.value as any;
        const list = Array.isArray(v) ? v : (v.mitigations ?? v.items ?? []);
        const m: Record<string, any[]> = {};
        list.forEach((x: any) => {
          const sid = x.scenario_id ?? x.scenarioId;
          if (!sid) return;
          (m[sid] ||= []).push(x);
        });
        // also embedded mitigations
        arr.forEach(s => { if (Array.isArray(s.mitigations) && !m[s.id]) m[s.id] = s.mitigations; });
        setMitigationsBySc(m);
      } else {
        const m: Record<string, any[]> = {};
        arr.forEach(s => { if (Array.isArray(s.mitigations)) m[s.id] = s.mitigations; });
        setMitigationsBySc(m);
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const avgInherent = scenarios.length ? Math.round(scenarios.reduce((s, r) => s + (r.inherent_risk ?? 0), 0) / scenarios.length) : 0;
  const avgResidual = scenarios.length ? Math.round(scenarios.reduce((s, r) => s + (r.residual_risk ?? 0), 0) / scenarios.length) : 0;
  const byLevel = (lvl: string) => scenarios.filter(r => r.risk_level === lvl).length;
  const topRisks = [...scenarios].sort((a, b) => (b.residual_risk ?? 0) - (a.residual_risk ?? 0)).slice(0, 10);
  const selectedMits = selected ? (mitigationsBySc[selected.id] ?? []) : [];

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><ShieldAlert className="w-6 h-6 text-orange-400" /> Risk Scenarios</h1>
          <p className="text-gray-400 text-sm mt-1">Inherent vs residual risk analysis with mitigation tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : scenarios.length === 0 ? <EmptyState icon={ShieldAlert} title="No risk scenarios" description="Add risk scenarios to analyse inherent and residual risk." />
        : <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {(["critical","high","medium","low"] as const).map(lvl => (
              <div key={lvl} className="bg-gray-800 rounded-lg p-5">
                <div className="text-gray-400 text-xs uppercase tracking-wide mb-2 capitalize">{lvl} Risk</div>
                <div className={`text-3xl font-bold ${riskText[lvl]}`}>{byLevel(lvl)}</div>
                <div className="text-gray-500 text-xs mt-1">scenarios</div>
              </div>
            ))}
          </div>

          <div className="grid lg:grid-cols-3 gap-6">
            <div className="bg-gray-800 rounded-lg p-5">
              <div className="font-semibold mb-4 flex items-center gap-2"><Target className="w-4 h-4 text-orange-400" /> Risk Matrix</div>
              <div className="grid gap-1" style={{ gridTemplateColumns: "repeat(5, 1fr)" }}>
                {[10,8,6,4,2].map(l => [2,4,6,8,10].map(i => {
                  const dot = scenarios.find(s => Math.abs((s.likelihood ?? 0) - l) <= 1 && Math.abs((s.impact ?? 0) - i) <= 1);
                  return <div key={`${l}-${i}`} className={`w-10 h-6 rounded flex items-center justify-center ${cellColor(l, i)}`} title={dot ? dot.scenario_name : ""}>{dot && <div className="w-2 h-2 bg-white rounded-full opacity-80" />}</div>;
                }))}
              </div>
            </div>
            <div className="bg-gray-800 rounded-lg p-5">
              <div className="font-semibold mb-4 flex items-center gap-2"><Activity className="w-4 h-4 text-red-400" /> Top Risks (Residual)</div>
              <div className="space-y-2">{topRisks.map((r, idx) => (
                <div key={r.id} onClick={() => setSelected(r)} className={`flex items-center gap-3 p-2 rounded-lg cursor-pointer hover:bg-gray-700/50 ${selected?.id === r.id ? "bg-blue-900/30" : ""}`}>
                  <span className="text-gray-500 text-xs w-4">{idx + 1}</span>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium truncate">{r.scenario_name ?? r.name}</div>
                    <div className="w-full bg-gray-700 rounded-full h-1 mt-1"><div className={`h-1 rounded-full ${r.risk_level === "critical" ? "bg-red-500" : r.risk_level === "high" ? "bg-orange-500" : r.risk_level === "medium" ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${r.residual_risk ?? 0}%` }} /></div>
                  </div>
                  <span className={`text-xs font-bold ${riskText[r.risk_level] ?? "text-gray-400"}`}>{r.residual_risk ?? 0}</span>
                </div>
              ))}</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-5 space-y-4">
              <div className="font-semibold flex items-center gap-2"><BarChart2 className="w-4 h-4 text-blue-400" /> Risk Reduction</div>
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1"><span>Avg Inherent</span><span className="text-orange-400 font-bold">{avgInherent}</span></div>
                <div className="w-full bg-gray-700 rounded-full h-2"><div className="h-2 bg-orange-500 rounded-full" style={{ width: `${avgInherent}%` }} /></div>
              </div>
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1"><span>Avg Residual</span><span className="text-green-400 font-bold">{avgResidual}</span></div>
                <div className="w-full bg-gray-700 rounded-full h-2"><div className="h-2 bg-green-500 rounded-full" style={{ width: `${avgResidual}%` }} /></div>
              </div>
            </div>
          </div>

          <div className="grid lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700 font-semibold flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-orange-400" /> Scenario List</div>
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead className="bg-gray-700/50"><tr>{["Scenario","Category","Inherent","Residual","Reduction","Level"].map(h => <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>)}</tr></thead>
                <tbody>{scenarios.map(s => (
                  <tr key={s.id} onClick={() => setSelected(s)} className={`border-t border-gray-700 hover:bg-gray-700/40 cursor-pointer ${selected?.id === s.id ? "bg-blue-900/20" : ""}`}>
                    <td className="px-4 py-3 font-medium text-sm">{s.scenario_name ?? s.name}</td>
                    <td className="px-4 py-3"><span className="bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded text-xs">{s.threat_category ?? "—"}</span></td>
                    <td className="px-4 py-3 text-orange-400 font-bold">{s.inherent_risk ?? 0}</td>
                    <td className="px-4 py-3 text-green-400 font-bold">{s.residual_risk ?? 0}</td>
                    <td className="px-4 py-3"><div className="flex items-center gap-2"><div className="w-16 bg-gray-700 rounded-full h-1.5"><div className="h-1.5 bg-blue-500 rounded-full" style={{ width: `${s.reduction_pct ?? 0}%` }} /></div><span className="text-xs text-blue-300">{s.reduction_pct ?? 0}%</span></div></td>
                    <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${riskColor[s.risk_level] ?? "bg-gray-600 text-white"}`}>{s.risk_level}</span></td>
                  </tr>
                ))}</tbody>
              </table></div>
            </div>
            <div className="bg-gray-800 rounded-lg p-4 space-y-3">
              <div className="font-semibold flex items-center gap-2"><TrendingDown className="w-4 h-4 text-green-400" /> {selected ? `Mitigations` : "Select a scenario"}</div>
              {selected ? selectedMits.length === 0 ? <p className="text-gray-500 text-sm">No mitigations recorded.</p>
                : <div className="space-y-3">{selectedMits.map(m => (
                  <div key={m.id} className="bg-gray-700/50 rounded-lg p-3 space-y-2">
                    <div className="flex items-center justify-between"><span className="text-sm font-medium">{m.mitigation_name ?? m.name}</span><span className={`w-2 h-2 rounded-full ${m.implemented ? "bg-green-400" : "bg-gray-500"}`} /></div>
                    <div className="flex items-center gap-2"><span className={`px-2 py-0.5 rounded text-xs ${mitTypeColor[m.type] ?? "bg-gray-700 text-gray-300"}`}>{m.type}</span><span className={`text-xs ${m.implemented ? "text-green-400" : "text-gray-500"}`}>{m.implemented ? "Implemented" : "Planned"}</span></div>
                    <div><div className="flex justify-between text-xs text-gray-400 mb-1"><span>Effectiveness</span><span>{m.effectiveness ?? 0}%</span></div><div className="w-full bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${(m.effectiveness ?? 0) >= 75 ? "bg-green-500" : (m.effectiveness ?? 0) >= 50 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${m.effectiveness ?? 0}%` }} /></div></div>
                  </div>
                ))}</div>
                : <p className="text-gray-500 text-sm">Click a scenario to view its mitigations.</p>}
            </div>
          </div>
        </>}
    </div>
  );
}
