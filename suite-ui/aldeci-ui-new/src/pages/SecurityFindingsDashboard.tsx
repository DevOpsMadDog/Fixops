/**
 * Security Findings Dashboard - Live API
 * Route: /security-findings
 * API: GET /api/v1/security-findings/findings, /summary
 */
import { useState, useEffect } from "react";
import { ShieldAlert, RefreshCw } from "lucide-react";
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

const sevColor: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
  info: "bg-gray-600 text-gray-200",
};
const statusColor: Record<string, string> = {
  open: "bg-red-700 text-red-100",
  in_progress: "bg-blue-700 text-blue-100",
  resolved: "bg-green-700 text-green-100",
  suppressed: "bg-gray-600 text-gray-200",
  false_positive: "bg-purple-700 text-purple-100",
};

export default function SecurityFindingsDashboard() {
  const [findings, setFindings] = useState<any[]>([]);
  const [summary, setSummary] = useState<any | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [f, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-findings/findings"),
        apiFetch<any>("/api/v1/security-findings/summary"),
      ]);
      if (f.status === "fulfilled") { const v = f.value as any; setFindings(Array.isArray(v) ? v : (v.findings ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setSummary(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filtered = filter === "all" ? findings : findings.filter(f => f.severity === filter || f.status === filter);
  const sevCounts: any = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => { if (sevCounts[f.severity] !== undefined) sevCounts[f.severity]++; });

  const top5Assets: Record<string, number> = {};
  findings.forEach(f => { if (f.status === "open" && f.asset) top5Assets[f.asset] = (top5Assets[f.asset] ?? 0) + 1; });
  const top5 = Object.entries(top5Assets).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><ShieldAlert className="w-6 h-6 text-red-400" /> Security Findings</h1>
          <p className="text-gray-400 text-sm mt-1">Aggregated findings from all scanners with lifecycle tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : findings.length === 0 ? <EmptyState icon={ShieldAlert} title="No findings" description="Findings from connected scanners will appear here." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {(["critical", "high", "medium", "low"] as const).map(sv => (
              <div key={sv} className="bg-gray-800 rounded-lg p-5">
                <p className="text-gray-400 text-sm capitalize">{sv}</p>
                <p className={`text-3xl font-bold mt-1 ${sv === "critical" ? "text-red-400" : sv === "high" ? "text-orange-400" : sv === "medium" ? "text-amber-400" : "text-blue-400"}`}>{summary?.[sv] ?? sevCounts[sv]}</p>
              </div>
            ))}
          </div>

          <div className="flex gap-2 flex-wrap">
            <button onClick={() => setFilter("all")} className={`px-3 py-1.5 rounded text-xs font-medium ${filter === "all" ? "bg-red-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>All</button>
            {["critical", "high", "medium", "low", "open", "resolved"].map(s => (
              <button key={s} onClick={() => setFilter(s)} className={`px-3 py-1.5 rounded text-xs font-medium capitalize ${filter === s ? "bg-red-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>{s}</button>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4">Findings ({filtered.length})</h2>
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Title</th><th className="text-left pb-2 pr-4">Severity</th><th className="text-left pb-2 pr-4">CVSS</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2 pr-4">Asset</th><th className="text-left pb-2">Detected</th></tr></thead>
                <tbody className="divide-y divide-gray-700/50">{filtered.slice(0, 100).map(f => (
                  <tr key={f.id} className="hover:bg-gray-700/30">
                    <td className="py-3 pr-4 text-gray-200 max-w-xs truncate">{f.title ?? f.name}</td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-bold ${sevColor[f.severity] ?? sevColor.info}`}>{f.severity}</span></td>
                    <td className="py-3 pr-4 text-white font-bold">{f.cvss ?? "—"}</td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[f.status] ?? "bg-gray-700 text-gray-200"}`}>{(f.status ?? "").replace("_", " ")}</span></td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">{f.asset ?? f.asset_id ?? "—"}</td>
                    <td className="py-3 text-gray-400 text-xs">{f.detected_at ?? f.created_at ?? "—"}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            </div>
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4">Top 5 Assets (Open)</h2>
              {top5.length === 0 ? <p className="text-gray-500 text-sm">No assets with open findings.</p>
                : <div className="space-y-2">{top5.map(([asset, count], i) => (
                  <div key={asset} className="flex items-center gap-2 p-2 bg-gray-700/30 rounded">
                    <span className="text-gray-500 w-4">{i + 1}.</span>
                    <span className="flex-1 text-gray-200 text-sm font-mono truncate">{asset}</span>
                    <span className="text-red-400 font-bold">{count}</span>
                  </div>
                ))}</div>}
            </div>
          </div>
        </>}
    </div>
  );
}
