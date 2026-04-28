// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Threat Landscape Dashboard - Live API
 * Route: /threat-landscape
 * API: GET /api/v1/threat-landscape/{actors,emerging,assessments}
 */
import { useState, useEffect } from "react";
import { Globe, RefreshCw } from "lucide-react";
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

const actorTypeColor: Record<string, string> = {
  nation_state: "bg-red-700 text-red-100",
  criminal: "bg-orange-700 text-orange-100",
  hacktivist: "bg-purple-700 text-purple-100",
  insider: "bg-amber-700 text-amber-100",
  unknown: "bg-gray-600 text-gray-200",
};
const sophColor: Record<string, string> = {
  very_high: "bg-red-900 text-red-300 border border-red-700",
  high: "bg-orange-900 text-orange-300 border border-orange-700",
  medium: "bg-amber-900 text-amber-300 border border-amber-700",
  low: "bg-gray-700 text-gray-300 border border-gray-600",
};
const sevBadge: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-green-700 text-green-100",
};

export default function ThreatLandscapeDashboard() {
  const [actors, setActors] = useState<any[]>([]);
  const [threats, setThreats] = useState<any[]>([]);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [filterActive, setFilterActive] = useState<"all" | "active" | "inactive">("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, t, as] = await Promise.allSettled([
        apiFetch<any>("/api/v1/threat-landscape/actors"),
        apiFetch<any>("/api/v1/threat-landscape/emerging"),
        apiFetch<any>("/api/v1/threat-landscape/assessments"),
      ]);
      if (a.status === "fulfilled") { const v = a.value as any; setActors(Array.isArray(v) ? v : (v.actors ?? v.items ?? [])); }
      if (t.status === "fulfilled") { const v = t.value as any; setThreats(Array.isArray(v) ? v : (v.threats ?? v.items ?? [])); }
      if (as.status === "fulfilled") { const v = as.value as any; setAssessments(Array.isArray(v) ? v : (v.assessments ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filteredActors = actors.filter(a => filterActive === "all" || (filterActive === "active" ? a.active : !a.active));
  const activeActors = actors.filter(a => a.active).length;
  const activeThreats = threats.filter(t => !t.resolved).length;
  const bySev = (s: string) => threats.filter(t => t.severity === s && !t.resolved).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Globe className="w-6 h-6 text-cyan-400" /> Threat Landscape</h1>
          <p className="text-gray-400 mt-1">Threat actors, emerging threats, sector risk assessments</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : actors.length === 0 && threats.length === 0 ? <EmptyState icon={Globe} title="No threat data" description="Threat actors and emerging threats will appear here." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[
              { label: "Active Actors", value: activeActors, color: "text-red-400" },
              { label: "Active Threats", value: activeThreats, color: "text-orange-400" },
              { label: "Critical", value: bySev("critical"), color: "text-red-400" },
              { label: "High", value: bySev("high"), color: "text-orange-400" },
              { label: "Medium", value: bySev("medium"), color: "text-amber-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>

          {actors.length > 0 && <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Threat Actors</h2>
              <div className="flex gap-2 bg-gray-800 rounded-lg p-1">{(["all", "active", "inactive"] as const).map(f => (
                <button key={f} onClick={() => setFilterActive(f)} className={`px-3 py-1 rounded text-xs font-medium capitalize ${filterActive === f ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>{f}</button>
              ))}</div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">{filteredActors.map(a => (
              <div key={a.id} className="bg-gray-800 rounded-lg p-5 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="text-white font-semibold">{a.actor_name}</p>
                    <p className="text-gray-400 text-xs mt-0.5">Last active: {a.last_active ?? "—"}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1.5">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${actorTypeColor[a.actor_type] ?? actorTypeColor.unknown}`}>{(a.actor_type ?? "").replace("_", " ")}</span>
                    <span className={`flex items-center gap-1 text-xs font-medium ${a.active ? "text-green-400" : "text-gray-500"}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${a.active ? "bg-green-400" : "bg-gray-500"}`} />
                      {a.active ? "Active" : "Inactive"}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2"><span className="text-gray-500 text-xs">Sophistication:</span><span className={`px-2 py-0.5 rounded text-xs font-medium ${sophColor[a.sophistication] ?? sophColor.low}`}>{a.sophistication ?? "—"}</span></div>
                {a.motivation && <p className="text-gray-400 text-xs"><span className="text-gray-500">Motivation:</span> {a.motivation}</p>}
                {Array.isArray(a.target_sectors) && a.target_sectors.length > 0 && <div>
                  <p className="text-gray-500 text-xs mb-1">Target Sectors</p>
                  <div className="flex flex-wrap gap-1">{a.target_sectors.map((s: string) => <span key={s} className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{s}</span>)}</div>
                </div>}
                {Array.isArray(a.known_ttps) && a.known_ttps.length > 0 && <div>
                  <p className="text-gray-500 text-xs mb-1">Known TTPs</p>
                  <div className="flex flex-wrap gap-1">{a.known_ttps.map((t: string) => <span key={t} className="bg-gray-900 text-gray-400 px-2 py-0.5 rounded text-xs border border-gray-700">{t}</span>)}</div>
                </div>}
              </div>
            ))}</div>
          </div>}

          {threats.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Emerging Threats</h2>
            <div className="space-y-3">{threats.map(t => (
              <div key={t.id} className={`p-4 rounded-lg border ${t.resolved ? "opacity-50 border-gray-700 bg-gray-700/20" : "border-gray-700 bg-gray-700/30"}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold ${sevBadge[t.severity] ?? sevBadge.low}`}>{t.severity}</span>
                      <span className="bg-gray-600 text-gray-200 px-2 py-0.5 rounded text-xs">{t.threat_category}</span>
                      {t.resolved && <span className="bg-green-900 text-green-300 px-2 py-0.5 rounded text-xs">Resolved</span>}
                    </div>
                    <p className="text-white text-sm font-medium">{t.title}</p>
                    {t.description && <p className="text-gray-400 text-xs mt-1">{t.description}</p>}
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-500">
                      <span>First observed: {t.first_observed}</span>
                      {t.mitigations_count !== undefined && <span>{t.mitigations_count} mitigation{t.mitigations_count !== 1 ? "s" : ""}</span>}
                    </div>
                  </div>
                </div>
              </div>
            ))}</div>
          </div>}

          {assessments.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Assessment History</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Date</th><th className="text-left pb-2 pr-4">Sector</th><th className="text-left pb-2 pr-4">Overall Risk</th><th className="text-left pb-2 pr-4">Active Actors</th><th className="text-left pb-2 pr-4">Emerging Threats</th><th className="text-left pb-2">Analyst</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{assessments.map(a => (
                <tr key={a.id} className="hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 text-gray-300">{a.date}</td>
                  <td className="py-2.5 pr-4 text-gray-200">{a.sector}</td>
                  <td className="py-2.5 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-bold ${sevBadge[a.overall_risk] ?? sevBadge.low}`}>{a.overall_risk}</span></td>
                  <td className="py-2.5 pr-4 text-gray-300">{a.threat_actors_active}</td>
                  <td className="py-2.5 pr-4 text-gray-300">{a.emerging_threats}</td>
                  <td className="py-2.5 text-gray-400">{a.analyst}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
