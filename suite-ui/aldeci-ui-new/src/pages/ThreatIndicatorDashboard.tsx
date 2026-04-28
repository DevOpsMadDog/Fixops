// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Threat Indicator Dashboard - Live API
 * Route: /threat-indicators
 * API: GET /api/v1/threat-indicators/indicators
 */
import { useState, useEffect } from "react";
import { AlertTriangle, RefreshCw, Eye } from "lucide-react";
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
  ip: "bg-red-800 text-red-200",
  domain: "bg-orange-800 text-orange-200",
  hash: "bg-purple-800 text-purple-200",
  url: "bg-blue-800 text-blue-200",
  email: "bg-cyan-800 text-cyan-200",
};

export default function ThreatIndicatorDashboard() {
  const [indicators, setIndicators] = useState<any[]>([]);
  const [filter, setFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/threat-indicators/indicators");
      setIndicators(Array.isArray(v) ? v : (v.indicators ?? v.items ?? []));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filtered = filter === "all" ? indicators : indicators.filter(i => i.indicator_type === filter);
  const active = indicators.filter(i => i.active).length;
  const highConf = indicators.filter(i => (i.confidence ?? 0) >= 0.8).length;
  const types = Array.from(new Set(indicators.map(i => i.indicator_type).filter(Boolean)));

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><AlertTriangle className="w-6 h-6 text-orange-400" /> Threat Indicators</h1>
          <p className="text-gray-400 text-sm mt-1">IOC lifecycle, sighting tracking, confidence scoring</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : indicators.length === 0 ? <EmptyState icon={AlertTriangle} title="No indicators" description="Indicators of compromise will appear here once ingested." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total IOCs", value: indicators.length, color: "text-blue-400" },
              { label: "Active", value: active, color: "text-green-400" },
              { label: "High Confidence", value: highConf, color: "text-purple-400" },
              { label: "Types", value: types.length, color: "text-amber-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white flex items-center gap-2"><Eye className="w-4 h-4 text-orange-400" /> Indicators</h2>
              <div className="flex gap-2 flex-wrap">{["all", ...types].map(t => (
                <button key={t} onClick={() => setFilter(t)} className={`px-3 py-1 rounded text-xs font-medium ${filter === t ? "bg-orange-700 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}>{t}</button>
              ))}</div>
            </div>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Type</th><th className="text-left pb-2 pr-4">Value</th><th className="text-left pb-2 pr-4">Confidence</th><th className="text-left pb-2 pr-4">Sightings</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2">Created</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{filtered.map(ioc => (
                <tr key={ioc.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${typeColor[ioc.indicator_type] || "bg-gray-700 text-gray-200"}`}>{ioc.indicator_type}</span></td>
                  <td className="py-3 pr-4 text-gray-200 font-mono text-xs">{ioc.value}</td>
                  <td className="py-3 pr-4"><div className="flex items-center gap-2"><div className="w-16 bg-gray-700 rounded-full h-1.5"><div className="h-1.5 rounded-full bg-purple-500" style={{ width: `${(ioc.confidence ?? 0) * 100}%` }} /></div><span className="text-gray-400 text-xs">{Math.round((ioc.confidence ?? 0) * 100)}%</span></div></td>
                  <td className="py-3 pr-4 text-gray-300">{ioc.sighting_count ?? 0}</td>
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${ioc.active ? "bg-green-800 text-green-200" : "bg-gray-700 text-gray-400"}`}>{ioc.active ? "Active" : "Expired"}</span></td>
                  <td className="py-3 text-gray-400 text-xs">{ioc.created_at ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
        </>}
    </div>
  );
}
