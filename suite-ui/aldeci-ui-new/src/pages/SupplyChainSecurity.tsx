/**
 * Supply Chain Security - Live API
 * Route: /supply-chain
 * API: GET /api/v1/supply-chain-intel/{packages,vulns,malicious,stats}
 */
import { useState, useEffect } from "react";
import { Package, RefreshCw, AlertTriangle, ShieldAlert } from "lucide-react";
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
const ecoColor: Record<string, string> = {
  npm: "bg-red-500/20 text-red-400",
  PyPI: "bg-blue-500/20 text-blue-400",
  pypi: "bg-blue-500/20 text-blue-400",
  Maven: "bg-orange-500/20 text-orange-400",
  maven: "bg-orange-500/20 text-orange-400",
  nuget: "bg-purple-500/20 text-purple-400",
  go: "bg-cyan-500/20 text-cyan-400",
  rubygems: "bg-pink-500/20 text-pink-400",
};

export default function SupplyChainSecurity() {
  const [packages, setPackages] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [malicious, setMalicious] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [tab, setTab] = useState<"packages" | "vulns" | "malicious">("packages");
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [p, v, m, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/supply-chain-intel/packages"),
        apiFetch<any>("/api/v1/supply-chain-intel/vulns"),
        apiFetch<any>("/api/v1/supply-chain-intel/malicious"),
        apiFetch<any>("/api/v1/supply-chain-intel/stats"),
      ]);
      if (p.status === "fulfilled") { const x = p.value as any; setPackages(Array.isArray(x) ? x : (x.packages ?? x.items ?? [])); }
      if (v.status === "fulfilled") { const x = v.value as any; setVulns(Array.isArray(x) ? x : (x.vulns ?? x.items ?? [])); }
      if (m.status === "fulfilled") { const x = m.value as any; setMalicious(Array.isArray(x) ? x : (x.malicious ?? x.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const ecosystems = Array.from(new Set(packages.map(p => p.ecosystem).filter(Boolean)));
  const filteredPkgs = filter === "all" ? packages : packages.filter(p => p.ecosystem === filter);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Package className="w-6 h-6 text-cyan-400" /> Supply Chain Security</h1>
          <p className="text-gray-400 text-sm mt-1">Package inventory, vulnerable & malicious dependency tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : packages.length === 0 && vulns.length === 0 && malicious.length === 0 ? <EmptyState icon={Package} title="No supply chain data" description="Ingest SBOMs to populate package inventory." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total Packages", value: stats?.total_packages ?? packages.length, color: "text-blue-400" },
              { label: "Vulnerable", value: stats?.vulnerable_packages ?? vulns.length, color: "text-orange-400" },
              { label: "Malicious", value: stats?.malicious_packages ?? malicious.length, color: "text-red-400" },
              { label: "Ecosystems", value: ecosystems.length, color: "text-purple-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>

          <div className="flex gap-2 bg-gray-800 rounded-lg p-1 w-fit">
            {(["packages", "vulns", "malicious"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded text-sm font-medium capitalize ${tab === t ? "bg-cyan-600 text-white" : "text-gray-400 hover:text-white"}`}>{t}</button>
            ))}
          </div>

          {tab === "packages" && <>
            {ecosystems.length > 0 && <div className="flex gap-2 flex-wrap">
              <button onClick={() => setFilter("all")} className={`px-3 py-1.5 rounded text-xs font-medium ${filter === "all" ? "bg-cyan-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>All</button>
              {ecosystems.map(e => (
                <button key={e} onClick={() => setFilter(e)} className={`px-3 py-1.5 rounded text-xs font-medium ${filter === e ? "bg-cyan-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>{e}</button>
              ))}
            </div>}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4">Packages ({filteredPkgs.length})</h2>
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Package</th><th className="text-left pb-2 pr-4">Version</th><th className="text-left pb-2 pr-4">Ecosystem</th><th className="text-left pb-2 pr-4">License</th><th className="text-left pb-2">Vulns</th></tr></thead>
                <tbody className="divide-y divide-gray-700/50">{filteredPkgs.slice(0, 200).map(p => (
                  <tr key={p.id ?? `${p.name}-${p.version}`} className="hover:bg-gray-700/30">
                    <td className="py-3 pr-4 text-gray-200 font-mono">{p.name ?? p.package_name}</td>
                    <td className="py-3 pr-4 text-gray-300">{p.version}</td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${ecoColor[p.ecosystem] ?? "bg-gray-700 text-gray-300"}`}>{p.ecosystem}</span></td>
                    <td className="py-3 pr-4 text-gray-400 text-xs">{p.license ?? "—"}</td>
                    <td className="py-3 text-gray-300">{p.vuln_count ?? 0}</td>
                  </tr>
                ))}</tbody>
              </table></div>
            </div>
          </>}

          {tab === "vulns" && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-orange-400" /> Vulnerable Packages</h2>
            {vulns.length === 0 ? <p className="text-gray-500 text-sm">No vulnerabilities found.</p>
              : <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">CVE</th><th className="text-left pb-2 pr-4">Package</th><th className="text-left pb-2 pr-4">Severity</th><th className="text-left pb-2 pr-4">CVSS</th><th className="text-left pb-2">Fixed In</th></tr></thead>
                <tbody className="divide-y divide-gray-700/50">{vulns.map(v => (
                  <tr key={v.id ?? v.cve_id} className="hover:bg-gray-700/30">
                    <td className="py-3 pr-4 font-mono text-cyan-300 text-xs">{v.cve_id ?? v.cve}</td>
                    <td className="py-3 pr-4 text-gray-200 font-mono text-xs">{v.package_name ?? v.package}@{v.affected_version ?? v.version ?? ""}</td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-bold ${sevColor[v.severity] ?? "bg-gray-700 text-gray-200"}`}>{v.severity}</span></td>
                    <td className="py-3 pr-4 text-white font-bold">{v.cvss ?? "—"}</td>
                    <td className="py-3 text-gray-400 text-xs">{v.fixed_in ?? "—"}</td>
                  </tr>
                ))}</tbody>
              </table></div>}
          </div>}

          {tab === "malicious" && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><ShieldAlert className="w-4 h-4 text-red-400" /> Malicious Packages</h2>
            {malicious.length === 0 ? <p className="text-gray-500 text-sm">No malicious packages detected.</p>
              : <div className="space-y-3">{malicious.map(m => (
                <div key={m.id} className="bg-red-900/20 border border-red-700/40 rounded-lg p-4">
                  <div className="flex items-start gap-3">
                    <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
                    <div className="flex-1">
                      <p className="text-white font-semibold text-sm font-mono">{m.package_name ?? m.name}</p>
                      <p className="text-gray-400 text-xs mt-1">{m.description ?? m.reason ?? "Detected as malicious"}</p>
                      <div className="flex gap-2 mt-2 flex-wrap">
                        {m.ecosystem && <span className={`px-2 py-0.5 rounded text-xs ${ecoColor[m.ecosystem] ?? "bg-gray-700 text-gray-300"}`}>{m.ecosystem}</span>}
                        {m.detected_at && <span className="text-gray-500 text-xs">Detected: {m.detected_at}</span>}
                      </div>
                    </div>
                  </div>
                </div>
              ))}</div>}
          </div>}
        </>}
    </div>
  );
}
