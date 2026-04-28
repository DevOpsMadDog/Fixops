// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Threat Modeling Pipeline Dashboard - Live API
 * Route: /threat-modeling-pipeline
 * API: GET /api/v1/threat-modeling-pipeline/{models,stride,unmitigated}
 */
import { useState, useEffect } from "react";
import { ShieldOff, RefreshCw, AlertTriangle, CheckCircle2 } from "lucide-react";
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

const RISK_SCORE_CONFIG: Record<number, { label: string; color: string; bg: string }> = {
  1: { label: "Low", color: "text-gray-400", bg: "bg-gray-500/20" },
  2: { label: "Medium", color: "text-yellow-400", bg: "bg-yellow-500/20" },
  3: { label: "High", color: "text-orange-400", bg: "bg-orange-500/20" },
  4: { label: "Critical", color: "text-red-400", bg: "bg-red-500/20" },
};
const RISK_LEVEL_COLOR: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
  low: "bg-gray-600/40 text-gray-400",
};
const STATUS_COLOR: Record<string, string> = {
  draft: "bg-gray-600/40 text-gray-400",
  in_review: "bg-yellow-500/20 text-yellow-300",
  finalized: "bg-green-500/20 text-green-300",
  archived: "bg-blue-500/20 text-blue-300",
};
const METHOD_COLOR: Record<string, string> = {
  STRIDE: "bg-blue-500/20 text-blue-300",
  PASTA: "bg-purple-500/20 text-purple-300",
  VAST: "bg-teal-500/20 text-teal-300",
  OCTAVE: "bg-orange-500/20 text-orange-300",
  LINDDUN: "bg-pink-500/20 text-pink-300",
};
const STRIDE_COLOR: Record<string, string> = {
  Spoofing: "bg-red-500/20 text-red-300",
  Tampering: "bg-orange-500/20 text-orange-300",
  Repudiation: "bg-yellow-500/20 text-yellow-300",
  InfoDisclosure: "bg-pink-500/20 text-pink-300",
  DoS: "bg-purple-500/20 text-purple-300",
  ElevationOfPrivilege: "bg-red-700/30 text-red-200",
};

function RiskGauge({ score }: { score: number }) {
  const cfg = RISK_SCORE_CONFIG[score] ?? RISK_SCORE_CONFIG[1];
  return (
    <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-bold ${cfg.bg} ${cfg.color}`}>
      {Array.from({ length: 4 }, (_, i) => (
        <span key={i} className="w-2 h-2 rounded-sm" style={{ backgroundColor: i < score ? (score === 4 ? "#ef4444" : score === 3 ? "#f97316" : score === 2 ? "#eab308" : "#6b7280") : "#374151" }} />
      ))}
      {cfg.label}
    </div>
  );
}

function MatrixCell({ likelihood, impact }: { likelihood: number; impact: number }) {
  const risk = likelihood * impact;
  const color = risk >= 16 ? "bg-red-600 text-white" : risk >= 9 ? "bg-orange-500 text-white" : risk >= 4 ? "bg-yellow-500 text-black" : "bg-gray-600 text-gray-200";
  return <span className={`inline-flex items-center justify-center w-8 h-6 rounded text-xs font-bold ${color}`}>{risk}</span>;
}

export default function ThreatModelingPipelineDashboard() {
  const [models, setModels] = useState<any[]>([]);
  const [stride, setStride] = useState<any[]>([]);
  const [unmitigated, setUnmitigated] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [m, s, u] = await Promise.allSettled([
        apiFetch<any>("/api/v1/threat-modeling-pipeline/models"),
        apiFetch<any>("/api/v1/threat-modeling-pipeline/stride"),
        apiFetch<any>("/api/v1/threat-modeling-pipeline/unmitigated"),
      ]);
      if (m.status === "fulfilled") { const v = m.value as any; setModels(Array.isArray(v) ? v : (v.models ?? v.items ?? [])); }
      if (s.status === "fulfilled") { const v = s.value as any; setStride(Array.isArray(v) ? v : (v.stride ?? v.items ?? [])); }
      if (u.status === "fulfilled") { const v = u.value as any; setUnmitigated(Array.isArray(v) ? v : (v.unmitigated ?? v.threats ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldOff className="text-violet-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Threat Modeling Pipeline</h1>
            <p className="text-gray-400 text-sm">STRIDE/PASTA pipeline, threat coverage, mitigation tracking</p>
          </div>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-violet-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : models.length === 0 && unmitigated.length === 0 ? <EmptyState icon={ShieldOff} title="No threat models" description="Create a STRIDE/PASTA model to start." />
        : <>
          {models.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Threat Models</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">{models.map(m => {
              const mc = m.mitigated_count ?? 0, tc = m.threats_count ?? 0;
              const mitPct = tc ? Math.round((mc / tc) * 100) : 0;
              return (
                <div key={m.id} className="bg-gray-700/50 rounded-lg p-4">
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <span className="font-semibold text-sm text-gray-200">{m.model_name ?? m.name}</span>
                    <RiskGauge score={m.risk_score ?? 1} />
                  </div>
                  <div className="flex flex-wrap gap-1.5 mb-3">
                    {m.methodology && <span className={`px-2 py-0.5 rounded text-xs ${METHOD_COLOR[m.methodology] ?? "bg-gray-700 text-gray-300"}`}>{m.methodology}</span>}
                    {m.component_type && <span className="px-2 py-0.5 rounded text-xs bg-sky-500/20 text-sky-300">{m.component_type}</span>}
                    {m.status && <span className={`px-2 py-0.5 rounded text-xs ${STATUS_COLOR[m.status] ?? "bg-gray-700 text-gray-300"}`}>{m.status}</span>}
                  </div>
                  <div className="text-xs text-gray-400 mb-1">{mc}/{tc} threats mitigated ({mitPct}%)</div>
                  <div className="bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${mitPct === 100 ? "bg-green-500" : mitPct >= 70 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${mitPct}%` }} /></div>
                  {m.last_updated && <div className="text-xs text-gray-500 mt-2">Updated {m.last_updated}</div>}
                </div>
              );
            })}</div>
          </div>}

          {stride.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">STRIDE Coverage</h2>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">{stride.map(s => {
              const pct = (s.count ?? 0) ? Math.round(((s.mitigated ?? 0) / s.count) * 100) : 0;
              return (
                <div key={s.category} className="bg-gray-700/50 rounded-lg p-3 text-center">
                  <div className={`text-xs font-bold mb-1 px-1 py-0.5 rounded ${RISK_LEVEL_COLOR[s.risk_level] ?? "bg-gray-700 text-gray-300"}`}>{s.risk_level}</div>
                  <div className={`text-sm font-semibold mt-2 ${(STRIDE_COLOR[s.category] ?? "text-gray-300").split(" ")[1] ?? "text-gray-300"}`}>{s.category}</div>
                  <div className="text-2xl font-bold text-white mt-1">{s.count}</div>
                  <div className="text-xs text-gray-400">{s.mitigated} mitigated</div>
                  <div className="bg-gray-700 rounded-full h-1 mt-2"><div className="bg-violet-500 h-1 rounded-full" style={{ width: `${pct}%` }} /></div>
                  <div className="text-xs text-gray-500 mt-0.5">{pct}%</div>
                </div>
              );
            })}</div>
          </div>}

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold flex items-center gap-2 mb-4"><AlertTriangle size={18} className="text-red-400" /> Unmitigated Threats</h2>
            {unmitigated.length === 0
              ? <div className="text-center py-8 text-green-400 flex flex-col items-center gap-2"><CheckCircle2 size={32} /><p className="font-medium">All threats mitigated.</p></div>
              : <table className="w-full text-sm">
                <thead><tr className="text-gray-400 border-b border-gray-700"><th className="text-left py-2">Threat</th><th className="text-left py-2">STRIDE</th><th className="text-center py-2">L×I</th><th className="text-left py-2">Risk</th><th className="text-left py-2">Model</th></tr></thead>
                <tbody>{unmitigated.map(t => (
                  <tr key={t.id} className="border-b border-gray-700/50">
                    <td className="py-2 text-gray-200 max-w-xs"><span className="line-clamp-2">{t.threat_name ?? t.name}</span></td>
                    <td className="py-2"><span className={`px-2 py-0.5 rounded text-xs ${STRIDE_COLOR[t.stride_category] ?? "bg-gray-700 text-gray-300"}`}>{t.stride_category}</span></td>
                    <td className="py-2 text-center"><MatrixCell likelihood={t.likelihood ?? 1} impact={t.impact ?? 1} /></td>
                    <td className="py-2"><span className={`px-2 py-0.5 rounded text-xs font-medium ${RISK_LEVEL_COLOR[t.risk_level] ?? "bg-gray-700 text-gray-300"}`}>{t.risk_level}</span></td>
                    <td className="py-2 text-gray-400 text-xs">{t.model_name ?? "—"}</td>
                  </tr>
                ))}</tbody>
              </table>}
          </div>
        </>}
    </div>
  );
}
