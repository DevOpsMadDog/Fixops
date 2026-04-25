/**
 * SBOM Dashboard - Live API
 * Route: /sbom
 * API: GET /api/v1/sbom/{assets,components,licenses,stats}
 */
import { useState, useEffect } from "react";
import { Package, RefreshCw } from "lucide-react";
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

export default function SBOMDashboard() {
  const [assets, setAssets] = useState<any[]>([]);
  const [components, setComponents] = useState<any[]>([]);
  const [licenses, setLicenses] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, c, l, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/sbom/assets"),
        apiFetch<any>("/api/v1/sbom/components"),
        apiFetch<any>("/api/v1/sbom/licenses"),
        apiFetch<any>("/api/v1/sbom/stats"),
      ]);
      if (a.status === "fulfilled") { const v = a.value as any; setAssets(Array.isArray(v) ? v : (v.assets ?? v.items ?? [])); }
      if (c.status === "fulfilled") { const v = c.value as any; setComponents(Array.isArray(v) ? v : (v.components ?? v.items ?? [])); }
      if (l.status === "fulfilled") { const v = l.value as any; setLicenses(Array.isArray(v) ? v : (v.licenses ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const vulnerable = components.filter(c => (c.vuln_count ?? 0) > 0).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Package className="w-6 h-6 text-cyan-400" /> SBOM</h1>
          <p className="text-gray-400 text-sm mt-1">Software Bill of Materials lifecycle management</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : assets.length === 0 && components.length === 0 ? <EmptyState icon={Package} title="No SBOM data" description="Generate or upload SBOMs to populate this dashboard." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Assets</p><p className="text-3xl font-bold text-blue-400 mt-1">{stats?.total_assets ?? assets.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Components</p><p className="text-3xl font-bold text-cyan-400 mt-1">{stats?.total_components ?? components.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Vulnerable</p><p className="text-3xl font-bold text-red-400 mt-1">{stats?.vulnerable_components ?? vulnerable}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">License Risks</p><p className="text-3xl font-bold text-amber-400 mt-1">{stats?.license_risks ?? licenses.filter(l => l.risk === "high").length}</p></div>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Components</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Version</th><th className="text-left pb-2 pr-4">Type</th><th className="text-left pb-2 pr-4">License</th><th className="text-left pb-2">Vulns</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{components.slice(0, 100).map(c => (
                <tr key={c.id ?? `${c.name}-${c.version}`} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-mono">{c.name ?? c.component_name}</td>
                  <td className="py-3 pr-4 text-gray-300">{c.version}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{c.type ?? c.component_type ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{c.license ?? "—"}</td>
                  <td className="py-3"><span className={`font-bold ${(c.vuln_count ?? 0) > 0 ? "text-red-400" : "text-gray-500"}`}>{c.vuln_count ?? 0}</span></td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
        </>}
    </div>
  );
}
