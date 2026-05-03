// FOLDED into UpgradePathsHub (dep-map tab) 2026-05-02 — preserve for git history
// Route: /dependency-mapping (now redirects to /remediate/upgrade?tab=dep-map)
// API: GET /api/v1/dependency-mapping/services, /critical-paths, POST /services/{id}/blast-radius
// Mock arrays replaced with live API on 2026-05-02 to satisfy NO MOCKS rule.
import { useState, useEffect } from "react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Network } from "lucide-react";

interface ServiceRow {
  id: string;
  service_name: string;
  service_type: string;
  criticality: string;
  environment: string;
  data_classification: string;
  owner: string;
  dependency_count: number;
  dependent_count: number;
  status: string;
}
interface DependencyRow {
  id: string;
  from_service?: string;
  to_service?: string;
  source_service_id?: string;
  target_service_id?: string;
  dep_type?: string;
  dependency_type?: string;
  criticality: string;
  protocol?: string;
  port?: number;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    ...init,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const criticalityBadge = (c: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-600", low: "bg-green-600" };
  return <span className={`${map[c] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{c}</span>;
};
const envBadge = (e: string) => {
  const map: Record<string, string> = { production: "bg-red-800", staging: "bg-yellow-800", development: "bg-green-800" };
  return <span className={`${map[e] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{e}</span>;
};
const classificationBadge = (c: string) => {
  const map: Record<string, string> = { PCI: "bg-red-700", PII: "bg-orange-700", confidential: "bg-yellow-700", internal: "bg-gray-600" };
  return <span className={`${map[c] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{c}</span>;
};
const statusBadge = (s: string) => {
  const map: Record<string, string> = { healthy: "bg-green-600", degraded: "bg-yellow-600", down: "bg-red-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s}</span>;
};

export default function DependencyMappingDashboard() {
  const [services, setServices] = useState<ServiceRow[]>([]);
  const [criticalPaths, setCriticalPaths] = useState<ServiceRow[]>([]);
  const [activeTab, setActiveTab] = useState<"services" | "blast" | "critical">("services");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterService, setFilterService] = useState<string>("");
  const [analysisType, setAnalysisType] = useState<"downstream" | "upstream">("downstream");
  const [blastResult, setBlastResult] = useState<null | { affected: string[]; affectedCount: number; criticalCount: number }>(null);
  const [blasting, setBlasting] = useState(false);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [svcs, crit] = await Promise.all([
        apiFetch<ServiceRow[]>("/api/v1/dependency-mapping/services"),
        apiFetch<ServiceRow[]>("/api/v1/dependency-mapping/critical-paths"),
      ]);
      const safeSvcs = Array.isArray(svcs) ? svcs : [];
      setServices(safeSvcs);
      setCriticalPaths(Array.isArray(crit) ? crit : []);
      if (!filterService && safeSvcs.length > 0) setFilterService(safeSvcs[0].id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const runBlastAnalysis = async () => {
    if (!filterService) return;
    setBlasting(true); setBlastResult(null);
    try {
      const r: any = await apiFetch<any>(
        `/api/v1/dependency-mapping/services/${encodeURIComponent(filterService)}/blast-radius`,
        { method: "POST", body: JSON.stringify({ analysis_type: analysisType }) },
      );
      const affectedIds: string[] = Array.isArray(r?.affected) ? r.affected
        : Array.isArray(r?.affected_services) ? r.affected_services
        : Array.isArray(r?.services) ? r.services
        : [];
      const affectedSvcs = services.filter(s => affectedIds.includes(s.id));
      setBlastResult({
        affected: affectedSvcs.map(s => s.service_name),
        affectedCount: r?.affected_count ?? affectedSvcs.length,
        criticalCount: r?.critical_count ?? affectedSvcs.filter(s => s.criticality === "critical").length,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBlasting(false);
    }
  };

  const totalServices = services.length;
  const highBlast = services.filter(s => (s.dependent_count ?? 0) >= 5).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Service Dependency Mapping</h1>
          <p className="text-gray-400 text-sm mt-1">Dependency graph, blast radius analysis, and critical service paths</p>
        </div>

        {loading ? (
          <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" /></div>
        ) : error ? (
          <ErrorState message={error} onRetry={load} />
        ) : services.length === 0 ? (
          <EmptyState icon={Network} title="No services registered" description="No services have been registered for this org yet." />
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
              <div className="bg-gray-800 rounded-lg p-6">
                <p className="text-gray-400 text-sm">Total Services</p>
                <p className="text-3xl font-bold mt-1 text-blue-400">{totalServices}</p>
              </div>
              <div className="bg-gray-800 rounded-lg p-6">
                <p className="text-gray-400 text-sm">Critical Paths</p>
                <p className="text-3xl font-bold mt-1 text-purple-400">{criticalPaths.length}</p>
              </div>
              <div className="bg-gray-800 rounded-lg p-6">
                <p className="text-gray-400 text-sm">High Blast Radius</p>
                <p className={`text-3xl font-bold mt-1 ${highBlast > 0 ? "text-orange-400" : "text-green-400"}`}>{highBlast}</p>
                <p className="text-xs text-gray-500 mt-1">≥ 5 dependents</p>
              </div>
            </div>

            <div className="flex gap-2 mb-4 border-b border-gray-700">
              {(["services", "blast", "critical"] as const).map(t => (
                <button key={t} onClick={() => setActiveTab(t)} className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
                  {t === "blast" ? "Blast Radius" : t === "critical" ? "Critical Paths" : "Services"}
                </button>
              ))}
            </div>

            {activeTab === "services" && (
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <div className="flex justify-between items-center p-4 border-b border-gray-700">
                  <h2 className="font-semibold">Service Registry</h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-900 text-gray-400">
                      <tr>{["Service", "Type", "Criticality", "Environment", "Data Class", "Owner", "Deps Out", "Deps In", "Status"].map(h => <th key={h} className="text-left px-4 py-2 whitespace-nowrap">{h}</th>)}</tr>
                    </thead>
                    <tbody className="divide-y divide-gray-700">
                      {services.map(s => (
                        <tr key={s.id} className="hover:bg-gray-750">
                          <td className="px-4 py-3 font-mono text-sm font-medium">{s.service_name}</td>
                          <td className="px-4 py-3"><span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded">{s.service_type ?? "—"}</span></td>
                          <td className="px-4 py-3">{criticalityBadge(s.criticality ?? "")}</td>
                          <td className="px-4 py-3">{envBadge(s.environment ?? "")}</td>
                          <td className="px-4 py-3">{classificationBadge(s.data_classification ?? "")}</td>
                          <td className="px-4 py-3 text-gray-400 text-xs">{s.owner ?? "—"}</td>
                          <td className="px-4 py-3"><span className="bg-blue-800 text-blue-200 text-xs px-2 py-0.5 rounded-full">{s.dependency_count ?? 0} out</span></td>
                          <td className="px-4 py-3"><span className={`${(s.dependent_count ?? 0) >= 5 ? "bg-orange-700" : "bg-gray-700"} text-white text-xs px-2 py-0.5 rounded-full`}>{s.dependent_count ?? 0} in</span></td>
                          <td className="px-4 py-3">{statusBadge(s.status ?? "")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === "blast" && (
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <div className="p-4 border-b border-gray-700">
                  <h2 className="font-semibold mb-3">Blast Radius Analyzer</h2>
                  <div className="flex items-center gap-3 flex-wrap">
                    <select className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm" value={filterService} onChange={e => { setFilterService(e.target.value); setBlastResult(null); }}>
                      {services.map(s => <option key={s.id} value={s.id}>{s.service_name}</option>)}
                    </select>
                    <div className="flex gap-1 bg-gray-900 rounded p-0.5">
                      {(["downstream", "upstream"] as const).map(t => (
                        <button key={t} onClick={() => { setAnalysisType(t); setBlastResult(null); }} className={`px-3 py-1 text-sm rounded transition-colors ${analysisType === t ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>
                          {t}
                        </button>
                      ))}
                    </div>
                    <button onClick={runBlastAnalysis} disabled={blasting} className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-700 text-white text-sm px-4 py-1.5 rounded font-medium">{blasting ? "Running…" : "Run Analysis"}</button>
                  </div>
                </div>
                {blastResult ? (
                  <div className="p-6">
                    <div className="grid grid-cols-2 gap-4 mb-6">
                      <div className="bg-gray-900 rounded-lg p-4 text-center">
                        <p className="text-gray-400 text-sm">Affected Services</p>
                        <p className="text-4xl font-bold text-orange-400 mt-1">{blastResult.affectedCount}</p>
                      </div>
                      <div className="bg-gray-900 rounded-lg p-4 text-center">
                        <p className="text-gray-400 text-sm">Critical Services Impacted</p>
                        <p className={`text-4xl font-bold mt-1 ${blastResult.criticalCount > 0 ? "text-red-400" : "text-green-400"}`}>{blastResult.criticalCount}</p>
                      </div>
                    </div>
                    <h3 className="text-sm font-semibold text-gray-300 mb-3">Affected Services:</h3>
                    {blastResult.affected.length === 0 ? (
                      <p className="text-green-400">No affected services — this service has no {analysisType} dependencies.</p>
                    ) : (
                      <div className="flex flex-wrap gap-2">
                        {blastResult.affected.map(name => {
                          const svc = services.find(s => s.service_name === name);
                          return (
                            <div key={name} className="bg-gray-900 rounded px-3 py-2 flex items-center gap-2">
                              <span className="font-mono text-sm">{name}</span>
                              {svc && criticalityBadge(svc.criticality)}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="p-8 text-center text-gray-500">Select a service and analysis type, then click Run Analysis.</div>
                )}
              </div>
            )}

            {activeTab === "critical" && (
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <div className="p-4 border-b border-gray-700">
                  <h2 className="font-semibold">Critical Service Paths — Most-depended-upon services</h2>
                </div>
                <div className="divide-y divide-gray-700">
                  {criticalPaths.length === 0 ? (
                    <div className="p-8 text-center text-gray-500">No critical paths flagged for this org.</div>
                  ) : (
                    criticalPaths.map((s, i) => (
                      <div key={s.id} className="p-4 flex items-center gap-4">
                        <div className="text-2xl font-bold text-gray-600 w-8 text-center">#{i + 1}</div>
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-mono font-bold">{s.service_name}</span>
                            {criticalityBadge(s.criticality ?? "")}
                            {classificationBadge(s.data_classification ?? "")}
                            {statusBadge(s.status ?? "")}
                          </div>
                          <div className="flex items-center gap-4 text-xs text-gray-400">
                            <span>Owner: {s.owner ?? "—"}</span>
                            <span className="bg-indigo-800 text-indigo-200 px-2 py-0.5 rounded">{s.service_type ?? "—"}</span>
                          </div>
                        </div>
                        <div className="text-right">
                          <p className="text-xs text-gray-400 mb-1">Dependents</p>
                          <span className={`text-2xl font-bold ${(s.dependent_count ?? 0) >= 8 ? "text-red-400" : (s.dependent_count ?? 0) >= 5 ? "text-orange-400" : "text-yellow-400"}`}>{s.dependent_count ?? 0}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
