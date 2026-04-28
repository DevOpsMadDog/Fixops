// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Upgrade Path Dashboard - Live API
 * Route: /upgrade-path
 * API: GET /api/v1/upgrade-path/recent, POST /api/v1/upgrade-path/resolve
 */
import { useState, useEffect } from "react";
import { GitBranch, RefreshCw, Search } from "lucide-react";
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

export default function UpgradePathDashboard() {
  const [recent, setRecent] = useState<any[]>([]);
  const [purl, setPurl] = useState("");
  const [cves, setCves] = useState("");
  const [resolution, setResolution] = useState<any | null>(null);
  const [resolving, setResolving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/upgrade-path/recent");
      setRecent(Array.isArray(v) ? v : (v.recent ?? v.items ?? []));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const resolve = async () => {
    if (!purl.trim()) return;
    setResolving(true); setResolution(null);
    try {
      const cveList = cves.split(",").map(s => s.trim()).filter(Boolean);
      const v = await apiFetch<any>("/api/v1/upgrade-path/resolve", { method: "POST", body: JSON.stringify({ purl, cves: cveList }) });
      setResolution(v);
      load();
    } catch (e) { setError((e as Error).message); }
    finally { setResolving(false); }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><GitBranch className="w-6 h-6 text-emerald-400" /> Upgrade Path Resolver</h1>
          <p className="text-gray-400 text-sm mt-1">Compute minimal safe upgrade for vulnerable packages</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Search className="w-4 h-4 text-emerald-400" /> Resolve Upgrade</h2>
        <div className="space-y-3">
          <input value={purl} onChange={e => setPurl(e.target.value)} placeholder="pkg:npm/lodash@4.17.20" className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm" />
          <input value={cves} onChange={e => setCves(e.target.value)} placeholder="CVE-2021-23337, CVE-2020-8203" className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm" />
          <button onClick={resolve} disabled={!purl.trim() || resolving} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:bg-gray-700 rounded text-sm font-medium">{resolving ? "Resolving..." : "Resolve Upgrade"}</button>
        </div>
        {resolution && <div className="mt-4 p-4 bg-gray-900 rounded">
          <pre className="text-xs text-gray-300 overflow-x-auto">{JSON.stringify(resolution, null, 2)}</pre>
        </div>}
      </div>

      {loading ? <div className="flex items-center justify-center h-32"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : recent.length === 0 ? <EmptyState icon={GitBranch} title="No recent upgrades" description="Upgrade paths you resolve will appear here." />
        : <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Recent Resolutions</h2>
          <div className="overflow-x-auto"><table className="w-full text-sm">
            <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Package</th><th className="text-left pb-2 pr-4">From</th><th className="text-left pb-2 pr-4">To</th><th className="text-left pb-2 pr-4">CVEs Fixed</th><th className="text-left pb-2">Date</th></tr></thead>
            <tbody className="divide-y divide-gray-700/50">{recent.map(r => (
              <tr key={r.id ?? r.purl} className="hover:bg-gray-700/30">
                <td className="py-3 pr-4 text-gray-200 font-mono text-xs">{r.package ?? r.purl}</td>
                <td className="py-3 pr-4 text-gray-400 text-xs">{r.from_version ?? r.current_version}</td>
                <td className="py-3 pr-4 text-emerald-400 font-bold text-xs">{r.to_version ?? r.target_version}</td>
                <td className="py-3 pr-4 text-gray-300 text-xs">{Array.isArray(r.cves_fixed) ? r.cves_fixed.length : (r.cves_fixed_count ?? "—")}</td>
                <td className="py-3 text-gray-400 text-xs">{r.resolved_at ?? r.created_at}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>}
    </div>
  );
}
