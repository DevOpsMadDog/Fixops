/**
 * Threat Modeling - Live API
 * Route: /threat-modeling
 * API: GET /api/v1/cyber-threat-models/{models,unmitigated,summary}
 */
import { useState, useEffect } from "react";
import { Workflow, RefreshCw, ShieldOff, AlertTriangle, CheckCircle2 } from "lucide-react";
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

export default function ThreatModeling() {
  const [models, setModels] = useState<any[]>([]);
  const [unmitigated, setUnmitigated] = useState<any[]>([]);
  const [summary, setSummary] = useState<any | null>(null);
  const [selected, setSelected] = useState<any | null>(null);
  const [modelDetails, setModelDetails] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [u, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/cyber-threat-models/unmitigated"),
        apiFetch<any>("/api/v1/cyber-threat-models/summary"),
      ]);
      if (u.status === "fulfilled") { const v = u.value as any; setUnmitigated(Array.isArray(v) ? v : (v.unmitigated ?? v.threats ?? v.items ?? [])); }
      if (s.status === "fulfilled") {
        const v = s.value as any;
        setSummary(v);
        const arr = Array.isArray(v?.models) ? v.models : Array.isArray(v) ? v : [];
        setModels(arr);
        if (arr.length && !selected) setSelected(arr[0]);
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  useEffect(() => {
    if (!selected?.id) return;
    apiFetch<any>(`/api/v1/cyber-threat-models/models/${selected.id}`).then(setModelDetails).catch(() => setModelDetails(null));
  }, [selected]);

  const mitigate = async (treeId: string) => {
    try {
      await apiFetch<any>(`/api/v1/cyber-threat-models/trees/${treeId}/mitigate`, { method: "PUT", body: JSON.stringify({}) });
      load();
    } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Workflow className="w-6 h-6 text-violet-400" /> Threat Modeling (STRIDE)</h1>
          <p className="text-gray-400 text-sm mt-1">STRIDE analysis workspace, attack trees, mitigation tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-violet-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : models.length === 0 && unmitigated.length === 0 ? <EmptyState icon={Workflow} title="No threat models" description="Create a STRIDE model to begin analysis." />
        : <>
          {summary && <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Models</p><p className="text-3xl font-bold text-blue-400 mt-1">{summary.total_models ?? models.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Threats</p><p className="text-3xl font-bold text-orange-400 mt-1">{summary.total_threats ?? 0}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Mitigated</p><p className="text-3xl font-bold text-green-400 mt-1">{summary.mitigated ?? 0}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Unmitigated</p><p className="text-3xl font-bold text-red-400 mt-1">{unmitigated.length}</p></div>
          </div>}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1 space-y-3">
              <h2 className="text-lg font-semibold">Models</h2>
              {models.length === 0 ? <p className="text-gray-500 text-sm">No models.</p>
                : models.map(m => (
                  <div key={m.id} onClick={() => setSelected(m)} className={`bg-gray-800 rounded-lg p-4 cursor-pointer border-2 ${selected?.id === m.id ? "border-violet-500" : "border-transparent hover:border-gray-600"}`}>
                    <p className="text-white text-sm font-medium">{m.model_name ?? m.name}</p>
                    {m.methodology && <p className="text-gray-400 text-xs mt-1">{m.methodology}</p>}
                    <div className="flex gap-2 mt-2 text-xs">
                      <span className="text-gray-500">{m.threats_count ?? 0} threats</span>
                      <span className="text-green-400">{m.mitigated_count ?? 0} mitigated</span>
                    </div>
                  </div>
                ))}
            </div>
            <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-red-400" /> Unmitigated Threats</h2>
              {unmitigated.length === 0
                ? <div className="text-center py-8 text-green-400 flex flex-col items-center gap-2"><CheckCircle2 size={32} /><p className="font-medium">All threats mitigated.</p></div>
                : <div className="overflow-x-auto"><table className="w-full text-sm">
                  <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Threat</th><th className="text-left pb-2 pr-4">STRIDE</th><th className="text-left pb-2 pr-4">Severity</th><th className="text-left pb-2 pr-4">Model</th><th className="text-left pb-2">Action</th></tr></thead>
                  <tbody className="divide-y divide-gray-700/50">{unmitigated.map(t => (
                    <tr key={t.id} className="hover:bg-gray-700/30">
                      <td className="py-3 pr-4 text-gray-200 max-w-xs"><span className="line-clamp-2">{t.threat_name ?? t.name ?? t.description}</span></td>
                      <td className="py-3 pr-4"><span className="bg-violet-900 text-violet-300 px-2 py-0.5 rounded text-xs">{t.stride_category ?? t.category}</span></td>
                      <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-bold ${sevColor[t.severity] ?? "bg-gray-700 text-gray-200"}`}>{t.severity}</span></td>
                      <td className="py-3 pr-4 text-gray-400 text-xs">{t.model_name ?? "—"}</td>
                      <td className="py-3"><button onClick={() => mitigate(t.tree_id ?? t.id)} className="px-3 py-1 bg-violet-700 hover:bg-violet-600 rounded text-xs">Mitigate</button></td>
                    </tr>
                  ))}</tbody>
                </table></div>}
            </div>
          </div>

          {modelDetails && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><ShieldOff className="w-4 h-4 text-violet-400" /> {selected?.model_name ?? selected?.name} — Details</h2>
            <pre className="text-xs text-gray-400 overflow-x-auto bg-gray-900 rounded p-3">{JSON.stringify(modelDetails, null, 2)}</pre>
          </div>}
        </>}
    </div>
  );
}
