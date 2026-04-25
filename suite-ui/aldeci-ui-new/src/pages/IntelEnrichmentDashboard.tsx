/**
 * Intel Enrichment Dashboard - Live API
 * Route: /intel-enrichment
 * API: GET /api/v1/intel-enrichment/requests
 */

import { useState, useEffect } from "react";
import { Search, RefreshCw } from "lucide-react";
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

const typeColors: Record<string, string> = {
  ip: "bg-blue-700 text-blue-100",
  domain: "bg-purple-700 text-purple-100",
  url: "bg-cyan-700 text-cyan-100",
  hash: "bg-gray-600 text-gray-200",
  email: "bg-pink-700 text-pink-100",
  asn: "bg-indigo-700 text-indigo-100",
};
const statusColors: Record<string, string> = {
  pending: "bg-gray-600 text-gray-200",
  in_progress: "bg-blue-700 text-blue-100",
  completed: "bg-green-700 text-green-100",
  failed: "bg-red-700 text-red-100",
};

export default function IntelEnrichmentDashboard() {
  const [requests, setRequests] = useState<any[]>([]);
  const [sources, setSources] = useState<any[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [reqRes, srcRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/intel-enrichment/requests"),
        apiFetch<any>("/api/v1/intel-enrichment/sources"),
      ]);
      if (reqRes.status === "fulfilled") {
        const v = reqRes.value;
        const arr = Array.isArray(v) ? v : (v.requests ?? v.items ?? []);
        setRequests(arr);
        if (arr.length && !selectedRequest) setSelectedRequest(arr[0].id);
      }
      if (srcRes.status === "fulfilled") {
        const v = srcRes.value;
        setSources(Array.isArray(v) ? v : (v.sources ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const selected = requests.find(r => r.id === selectedRequest);
  const totalCompleted = requests.filter(r => r.status === "completed").length;
  const totalPending = requests.filter(r => r.status === "pending" || r.status === "in_progress").length;
  const completedReqs = requests.filter(r => r.status === "completed");
  const avgSources = completedReqs.length ? Math.round(completedReqs.reduce((s, r) => s + (r.sources_queried ?? 0), 0) / completedReqs.length) : 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Search className="w-6 h-6 text-cyan-400" /> Intel Enrichment</h1>
          <p className="text-gray-400 mt-1">IOC enrichment requests, source analysis, and reputation scoring</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : requests.length === 0 && sources.length === 0 ? <EmptyState icon={Search} title="No enrichment data" description="No enrichment requests or sources configured yet." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total Requests", value: requests.length, color: "text-blue-400" },
              { label: "Completed", value: totalCompleted, color: "text-green-400" },
              { label: "Pending", value: totalPending, color: "text-amber-400" },
              { label: "Avg Sources", value: avgSources, color: "text-purple-400" },
            ].map(kpi => (
              <div key={kpi.label} className="bg-gray-800 rounded-lg p-6">
                <p className="text-gray-400 text-sm">{kpi.label}</p>
                <p className={`text-3xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {requests.length > 0 && <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Enrichment Requests</h2>
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="border-b border-gray-700 text-gray-400 text-left">
                  <th className="pb-3 pr-4">Indicator</th><th className="pb-3 pr-4">Type</th><th className="pb-3 pr-4">Status</th><th className="pb-3 pr-4">Sources</th><th className="pb-3">Created</th>
                </tr></thead>
                <tbody className="divide-y divide-gray-700">{requests.map(req => (
                  <tr key={req.id} onClick={() => setSelectedRequest(req.id)} className={`cursor-pointer ${selectedRequest === req.id ? "bg-blue-900/30" : "hover:bg-gray-700/50"}`}>
                    <td className="py-3 pr-4 font-mono text-xs text-white max-w-[180px] truncate">{req.indicator}</td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium uppercase ${typeColors[req.ioc_type] ?? "bg-gray-700"}`}>{req.ioc_type}</span></td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColors[req.status] ?? "bg-gray-600"}`}>{(req.status ?? "").replace("_", " ")}</span></td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">{req.sources_responded ?? 0}/{req.sources_queried ?? 0}</td>
                    <td className="py-3 text-gray-500 text-xs">{req.created_at ?? "—"}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            </div>}

            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-4">Result Details</h2>
                {selected && selected.status === "completed" ? (
                  <div className="space-y-4">
                    <div><p className="text-gray-400 text-xs mb-1">Indicator</p><p className="text-white text-xs font-mono break-all">{selected.indicator}</p></div>
                    <div>
                      <div className="flex justify-between mb-1">
                        <p className="text-gray-400 text-xs">Reputation Score</p>
                        <span className={`text-sm font-bold ${(selected.reputation_score ?? 0) >= 70 ? "text-red-400" : (selected.reputation_score ?? 0) >= 40 ? "text-amber-400" : "text-green-400"}`}>{selected.reputation_score ?? "N/A"}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2"><div className={`h-2 rounded-full ${(selected.reputation_score ?? 0) >= 70 ? "bg-red-500" : (selected.reputation_score ?? 0) >= 40 ? "bg-amber-500" : "bg-green-500"}`} style={{ width: `${selected.reputation_score ?? 0}%` }} /></div>
                    </div>
                    <div className="flex items-center gap-3">
                      <div><p className="text-gray-400 text-xs">Verdict</p><span className={`font-bold text-sm ${selected.malicious ? "text-red-400" : "text-green-400"}`}>{selected.malicious ? "MALICIOUS" : "CLEAN"}</span></div>
                      <div className="ml-auto"><p className="text-gray-400 text-xs">Confidence</p><span className="text-white font-semibold">{selected.confidence ?? 0}%</span></div>
                    </div>
                    {Array.isArray(selected.tags) && selected.tags.length > 0 && (
                      <div>
                        <p className="text-gray-400 text-xs mb-2">Tags</p>
                        <div className="flex flex-wrap gap-1">{selected.tags.map((tag: string) => (<span key={tag} className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{tag}</span>))}</div>
                      </div>
                    )}
                  </div>
                ) : <p className="text-gray-500 text-sm">Select a completed request to view details</p>}
              </div>
            </div>
          </div>

          {sources.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Enrichment Sources</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700 text-gray-400 text-left"><th className="pb-3 pr-4">Source</th><th className="pb-3 pr-4">Supported Types</th><th className="pb-3 pr-4">Success Rate</th><th className="pb-3 pr-4">Avg Response</th><th className="pb-3">Total Queries</th></tr></thead>
              <tbody className="divide-y divide-gray-700">{sources.map(src => (
                <tr key={src.id} className="hover:bg-gray-700/50">
                  <td className="py-3 pr-4 text-white font-medium">{src.name}</td>
                  <td className="py-3 pr-4"><div className="flex flex-wrap gap-1">{(src.ioc_types ?? []).map((t: string) => (<span key={t} className={`px-1.5 py-0.5 rounded text-xs font-medium uppercase ${typeColors[t] ?? "bg-gray-700"}`}>{t}</span>))}</div></td>
                  <td className="py-3 pr-4"><div className="flex items-center gap-2"><div className="w-20 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${(src.success_rate ?? 0) >= 95 ? "bg-green-500" : (src.success_rate ?? 0) >= 85 ? "bg-amber-500" : "bg-red-500"}`} style={{ width: `${src.success_rate ?? 0}%` }} /></div><span className={`text-xs font-medium ${(src.success_rate ?? 0) >= 95 ? "text-green-400" : (src.success_rate ?? 0) >= 85 ? "text-amber-400" : "text-red-400"}`}>{src.success_rate ?? 0}%</span></div></td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{src.avg_response_ms ?? 0}ms</td>
                  <td className="py-3 text-gray-400">{(src.total_queries ?? 0).toLocaleString()}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
