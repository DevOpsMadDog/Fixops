// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * SCA Dashboard - Live API
 * Route: /sca
 * API: GET /api/v1/sca/{projects,scans,vulns,licenses,stats}
 */
import { useState, useEffect } from "react";
import { Layers, RefreshCw } from "lucide-react";
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
};

export default function SCADashboard() {
  const [projects, setProjects] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [licenses, setLicenses] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [p, s, v, l, st] = await Promise.allSettled([
        apiFetch<any>("/api/v1/sca/projects"),
        apiFetch<any>("/api/v1/sca/scans"),
        apiFetch<any>("/api/v1/sca/vulns"),
        apiFetch<any>("/api/v1/sca/licenses"),
        apiFetch<any>("/api/v1/sca/stats"),
      ]);
      if (p.status === "fulfilled") { const x = p.value as any; setProjects(Array.isArray(x) ? x : (x.projects ?? x.items ?? [])); }
      if (s.status === "fulfilled") { const x = s.value as any; setScans(Array.isArray(x) ? x : (x.scans ?? x.items ?? [])); }
      if (v.status === "fulfilled") { const x = v.value as any; setVulns(Array.isArray(x) ? x : (x.vulns ?? x.items ?? [])); }
      if (l.status === "fulfilled") { const x = l.value as any; setLicenses(Array.isArray(x) ? x : (x.licenses ?? x.items ?? [])); }
      if (st.status === "fulfilled") { setStats(st.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Layers className="w-6 h-6 text-cyan-400" /> Software Composition Analysis</h1>
          <p className="text-gray-400 text-sm mt-1">Open-source dependency scanning, license compliance</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : projects.length === 0 && scans.length === 0 && vulns.length === 0 ? <EmptyState icon={Layers} title="No SCA data" description="Run an SCA scan to populate dependency analysis." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Projects</p><p className="text-3xl font-bold text-blue-400 mt-1">{stats?.projects ?? projects.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Scans</p><p className="text-3xl font-bold text-cyan-400 mt-1">{stats?.scans ?? scans.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Vulnerable Deps</p><p className="text-3xl font-bold text-red-400 mt-1">{stats?.vulnerable_dependencies ?? vulns.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">License Violations</p><p className="text-3xl font-bold text-amber-400 mt-1">{stats?.license_violations ?? licenses.filter(l => l.violation).length}</p></div>
          </div>
          {vulns.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Vulnerable Dependencies</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Package</th><th className="text-left pb-2 pr-4">Version</th><th className="text-left pb-2 pr-4">CVE</th><th className="text-left pb-2 pr-4">Severity</th><th className="text-left pb-2">Fixed In</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{vulns.slice(0, 100).map(v => (
                <tr key={v.id ?? v.cve_id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-mono">{v.package ?? v.package_name}</td>
                  <td className="py-3 pr-4 text-gray-300">{v.version}</td>
                  <td className="py-3 pr-4 font-mono text-cyan-300 text-xs">{v.cve_id ?? v.cve}</td>
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-bold ${sevColor[v.severity] ?? "bg-gray-700 text-gray-200"}`}>{v.severity}</span></td>
                  <td className="py-3 text-gray-400 text-xs">{v.fixed_in ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
          {licenses.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">License Compliance</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Package</th><th className="text-left pb-2 pr-4">License</th><th className="text-left pb-2 pr-4">Risk</th><th className="text-left pb-2">Violation</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{licenses.slice(0, 100).map(l => (
                <tr key={l.id ?? `${l.package}-${l.license}`} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-mono">{l.package ?? l.package_name}</td>
                  <td className="py-3 pr-4 text-gray-300">{l.license}</td>
                  <td className={`py-3 pr-4 font-bold ${l.risk === "high" ? "text-red-400" : l.risk === "medium" ? "text-amber-400" : "text-green-400"}`}>{l.risk ?? "low"}</td>
                  <td className="py-3">{l.violation ? <span className="text-red-400 text-xs">Yes</span> : <span className="text-green-400 text-xs">No</span>}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
