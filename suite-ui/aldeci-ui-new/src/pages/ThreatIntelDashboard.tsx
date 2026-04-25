/**
 * Threat Intelligence Dashboard - Live API
 * Route: /threat-intel
 * API: GET /api/v1/feeds/status, /api/v1/threat-intel/active-threats, /api/v1/threat-intel/cves/recent
 */
import { useState, useEffect } from "react";
import { Activity, RefreshCw, Search, Copy } from "lucide-react";
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

const healthColor: Record<string, string> = {
  healthy: "bg-green-500/20 text-green-400",
  degraded: "bg-amber-500/20 text-amber-400",
  down: "bg-red-500/20 text-red-400",
  inactive: "bg-gray-500/20 text-gray-400",
};

export default function ThreatIntelDashboard() {
  const [feeds, setFeeds] = useState<any[]>([]);
  const [actors, setActors] = useState<any[]>([]);
  const [cves, setCves] = useState<any[]>([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [f, a, c] = await Promise.allSettled([
        apiFetch<any>("/api/v1/feeds/status"),
        apiFetch<any>("/api/v1/threat-intel/active-threats"),
        apiFetch<any>("/api/v1/threat-intel/cves/recent"),
      ]);
      if (f.status === "fulfilled") { const v = f.value as any; setFeeds(Array.isArray(v) ? v : (v.feeds ?? v.items ?? [])); }
      if (a.status === "fulfilled") { const v = a.value as any; setActors(Array.isArray(v) ? v : (v.actors ?? v.threats ?? v.items ?? [])); }
      if (c.status === "fulfilled") { const v = c.value as any; setCves(Array.isArray(v) ? v : (v.cves ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filteredCves = search ? cves.filter(c => JSON.stringify(c).toLowerCase().includes(search.toLowerCase())) : cves;
  const healthy = feeds.filter(f => f.status === "healthy" || f.active).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Activity className="w-6 h-6 text-purple-400" /> Threat Intelligence</h1>
          <p className="text-gray-400 text-sm mt-1">Feed health, active threats, recent CVEs</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : feeds.length === 0 && actors.length === 0 && cves.length === 0 ? <EmptyState icon={Activity} title="No threat intel" description="Configure feeds and threat actor sources to start ingesting." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Active Feeds</p><p className="text-3xl font-bold text-green-400 mt-1">{healthy}/{feeds.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Active Threats</p><p className="text-3xl font-bold text-orange-400 mt-1">{actors.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Recent CVEs</p><p className="text-3xl font-bold text-red-400 mt-1">{cves.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Critical CVEs</p><p className="text-3xl font-bold text-red-500 mt-1">{cves.filter(c => (c.severity ?? c.cvss_severity) === "CRITICAL" || c.cvss >= 9).length}</p></div>
          </div>

          {feeds.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Feed Health</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">{feeds.map(f => (
              <div key={f.id ?? f.name} className="bg-gray-700/30 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-white font-medium text-sm">{f.name ?? f.feed_name}</p>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${healthColor[f.status ?? (f.active ? "healthy" : "inactive")] ?? healthColor.inactive}`}>{f.status ?? (f.active ? "active" : "inactive")}</span>
                </div>
                <div className="text-xs text-gray-400 space-y-1">
                  {f.last_updated && <p>Last update: {f.last_updated}</p>}
                  {f.records_count !== undefined && <p>{f.records_count} records</p>}
                  {f.source && <p>Source: {f.source}</p>}
                </div>
              </div>
            ))}</div>
          </div>}

          {actors.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Active Threat Actors</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">{actors.slice(0, 12).map(a => (
              <div key={a.id ?? a.actor_name} className="bg-gray-700/30 rounded-lg p-4">
                <p className="text-white font-semibold text-sm">{a.actor_name ?? a.name}</p>
                {a.actor_type && <p className="text-gray-400 text-xs mt-1">{a.actor_type}</p>}
                {a.motivation && <p className="text-gray-500 text-xs mt-1">Motivation: {a.motivation}</p>}
              </div>
            ))}</div>
          </div>}

          {cves.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold">Recent CVEs</h2>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search CVEs..." className="bg-gray-900 border border-gray-700 rounded-lg pl-9 pr-4 py-1.5 text-sm w-56" />
              </div>
            </div>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">CVE</th><th className="text-left pb-2 pr-4">Severity</th><th className="text-left pb-2 pr-4">CVSS</th><th className="text-left pb-2 pr-4">Description</th><th className="text-left pb-2">Published</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{filteredCves.slice(0, 50).map(c => (
                <tr key={c.cve_id ?? c.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 font-mono text-cyan-300 text-xs flex items-center gap-2">{c.cve_id ?? c.cve} <button onClick={() => navigator.clipboard?.writeText(c.cve_id ?? c.cve)} className="text-gray-500 hover:text-gray-300"><Copy className="w-3 h-3" /></button></td>
                  <td className="py-3 pr-4 text-gray-300 text-xs uppercase">{c.severity ?? "—"}</td>
                  <td className="py-3 pr-4 text-white font-bold">{c.cvss ?? c.cvss_score ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs max-w-md truncate">{c.description ?? "—"}</td>
                  <td className="py-3 text-gray-400 text-xs">{c.published ?? c.published_date ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
