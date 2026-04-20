import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

const services = [
  { id: "svc-001", service_name: "payment-api", service_type: "api", criticality: "critical", environment: "production", data_classification: "PCI", owner: "alice.chen", dependency_count: 4, dependent_count: 8, status: "healthy" },
  { id: "svc-002", service_name: "auth-service", service_type: "api", criticality: "critical", environment: "production", data_classification: "confidential", owner: "bob.martinez", dependency_count: 2, dependent_count: 12, status: "healthy" },
  { id: "svc-003", service_name: "user-db", service_type: "database", criticality: "critical", environment: "production", data_classification: "PII", owner: "carol.patel", dependency_count: 1, dependent_count: 6, status: "degraded" },
  { id: "svc-004", service_name: "notification-svc", service_type: "service", criticality: "medium", environment: "production", data_classification: "internal", owner: "dan.kim", dependency_count: 3, dependent_count: 2, status: "healthy" },
  { id: "svc-005", service_name: "analytics-pipeline", service_type: "pipeline", criticality: "low", environment: "production", data_classification: "internal", owner: "eva.singh", dependency_count: 5, dependent_count: 1, status: "healthy" },
  { id: "svc-006", service_name: "audit-log-svc", service_type: "service", criticality: "high", environment: "production", data_classification: "confidential", owner: "bob.martinez", dependency_count: 2, dependent_count: 5, status: "healthy" },
  { id: "svc-007", service_name: "email-gateway", service_type: "gateway", criticality: "medium", environment: "production", data_classification: "internal", owner: "dan.kim", dependency_count: 1, dependent_count: 4, status: "healthy" },
];

const dependencies = [
  { id: "dep-001", from_service: "svc-001", to_service: "svc-002", dep_type: "auth", criticality: "critical", protocol: "HTTPS", port: 443 },
  { id: "dep-002", from_service: "svc-001", to_service: "svc-003", dep_type: "data", criticality: "critical", protocol: "PostgreSQL", port: 5432 },
  { id: "dep-003", from_service: "svc-001", to_service: "svc-006", dep_type: "audit", criticality: "high", protocol: "gRPC", port: 50051 },
  { id: "dep-004", from_service: "svc-001", to_service: "svc-004", dep_type: "notification", criticality: "medium", protocol: "AMQP", port: 5672 },
  { id: "dep-005", from_service: "svc-002", to_service: "svc-003", dep_type: "data", criticality: "critical", protocol: "PostgreSQL", port: 5432 },
  { id: "dep-006", from_service: "svc-002", to_service: "svc-006", dep_type: "audit", criticality: "high", protocol: "gRPC", port: 50051 },
  { id: "dep-007", from_service: "svc-004", to_service: "svc-007", dep_type: "email", criticality: "medium", protocol: "SMTP", port: 587 },
  { id: "dep-008", from_service: "svc-004", to_service: "svc-003", dep_type: "data", criticality: "medium", protocol: "PostgreSQL", port: 5432 },
  { id: "dep-009", from_service: "svc-005", to_service: "svc-003", dep_type: "data", criticality: "low", protocol: "PostgreSQL", port: 5432 },
  { id: "dep-010", from_service: "svc-006", to_service: "svc-003", dep_type: "data", criticality: "high", protocol: "PostgreSQL", port: 5432 },
];

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
  const [activeTab, setActiveTab] = useState<"services" | "graph" | "blast" | "critical">("services");
  const [filterService, setFilterService] = useState("svc-001");
  const [analysisType, setAnalysisType] = useState<"downstream" | "upstream">("downstream");

  useEffect(() => {
    apiFetch(`/api/v1/dependency-mapping/services?org_id=${ORG_ID}`).catch(() => {});
  }, []);
  const [blastResult, setBlastResult] = useState<null | { affected: string[]; affectedCount: number; criticalCount: number }>(null);
  const [showAddService, setShowAddService] = useState(false);
  const [showAddDep, setShowAddDep] = useState(false);
  const [newService, setNewService] = useState({ service_name: "", service_type: "api", criticality: "medium", environment: "production", data_classification: "internal", owner: "" });
  const [newDep, setNewDep] = useState({ from_service: "svc-001", to_service: "svc-002", dep_type: "data", criticality: "medium", protocol: "HTTPS", port: 443 });

  const totalServices = services.length;
  const totalDeps = dependencies.length;
  const highBlast = services.filter(s => s.dependent_count >= 5).length;

  // Graph view: outgoing + incoming for selected service
  const outgoing = dependencies.filter(d => d.from_service === filterService);
  const incoming = dependencies.filter(d => d.to_service === filterService);

  // Blast radius BFS (simple 2-hop downstream/upstream)
  const runBlastAnalysis = () => {
    const visited = new Set<string>();
    const queue = [filterService];
    visited.add(filterService);
    while (queue.length) {
      const curr = queue.shift()!;
      const next = analysisType === "downstream"
        ? dependencies.filter(d => d.from_service === curr).map(d => d.to_service)
        : dependencies.filter(d => d.to_service === curr).map(d => d.from_service);
      next.forEach(n => { if (!visited.has(n)) { visited.add(n); queue.push(n); } });
    }
    visited.delete(filterService);
    const affected = [...visited];
    const affectedSvcs = services.filter(s => affected.includes(s.id));
    setBlastResult({
      affected: affectedSvcs.map(s => s.service_name),
      affectedCount: affectedSvcs.length,
      criticalCount: affectedSvcs.filter(s => s.criticality === "critical").length,
    });
  };

  // Critical paths: most-depended-upon critical services
  const criticalPaths = [...services]
    .filter(s => s.criticality === "critical" || s.criticality === "high")
    .sort((a, b) => b.dependent_count - a.dependent_count);

  const svcName = (id: string) => services.find(s => s.id === id)?.service_name ?? id;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Service Dependency Mapping</h1>
          <p className="text-gray-400 text-sm mt-1">Dependency graph, blast radius analysis, and critical service paths</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Total Services</p>
            <p className="text-3xl font-bold mt-1 text-blue-400">{totalServices}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Total Dependencies</p>
            <p className="text-3xl font-bold mt-1 text-purple-400">{totalDeps}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">High Blast Radius</p>
            <p className={`text-3xl font-bold mt-1 ${highBlast > 0 ? "text-orange-400" : "text-green-400"}`}>{highBlast}</p>
            <p className="text-xs text-gray-500 mt-1">&ge;5 dependents</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(["services", "graph", "blast", "critical"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
              {t === "graph" ? "Dependency Graph" : t === "blast" ? "Blast Radius" : t === "critical" ? "Critical Paths" : t}
            </button>
          ))}
        </div>

        {/* Services Table */}
        {activeTab === "services" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <h2 className="font-semibold">Service Registry</h2>
              <div className="flex gap-2">
                <button onClick={() => setShowAddService(!showAddService)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Service</button>
                <button onClick={() => setShowAddDep(!showAddDep)} className="bg-purple-600 hover:bg-purple-700 text-white text-sm px-3 py-1 rounded">+ Add Dependency</button>
              </div>
            </div>
            {showAddService && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-3 gap-3">
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Service name" value={newService.service_name} onChange={e => setNewService({ ...newService, service_name: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newService.service_type} onChange={e => setNewService({ ...newService, service_type: e.target.value })}>
                  {["api","service","database","gateway","pipeline","cache","queue"].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newService.criticality} onChange={e => setNewService({ ...newService, criticality: e.target.value })}>
                  {["critical","high","medium","low"].map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newService.environment} onChange={e => setNewService({ ...newService, environment: e.target.value })}>
                  {["production","staging","development"].map(e => <option key={e} value={e}>{e}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newService.data_classification} onChange={e => setNewService({ ...newService, data_classification: e.target.value })}>
                  {["PCI","PII","confidential","internal","public"].map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Owner" value={newService.owner} onChange={e => setNewService({ ...newService, owner: e.target.value })} />
                <div className="col-span-3 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddService(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddService(false)}>Cancel</button>
                </div>
              </div>
            )}
            {showAddDep && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-3 gap-3">
                <div>
                  <label className="text-xs text-gray-400 block mb-1">From Service</label>
                  <select className="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newDep.from_service} onChange={e => setNewDep({ ...newDep, from_service: e.target.value })}>
                    {services.map(s => <option key={s.id} value={s.id}>{s.service_name}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1">To Service</label>
                  <select className="w-full bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newDep.to_service} onChange={e => setNewDep({ ...newDep, to_service: e.target.value })}>
                    {services.map(s => <option key={s.id} value={s.id}>{s.service_name}</option>)}
                  </select>
                </div>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm self-end" value={newDep.dep_type} onChange={e => setNewDep({ ...newDep, dep_type: e.target.value })}>
                  {["data","auth","audit","notification","email","cache","queue"].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newDep.criticality} onChange={e => setNewDep({ ...newDep, criticality: e.target.value })}>
                  {["critical","high","medium","low"].map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Protocol" value={newDep.protocol} onChange={e => setNewDep({ ...newDep, protocol: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" type="number" placeholder="Port" value={newDep.port} onChange={e => setNewDep({ ...newDep, port: +e.target.value })} />
                <div className="col-span-3 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddDep(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddDep(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Service", "Type", "Criticality", "Environment", "Data Class", "Owner", "Deps Out", "Deps In", "Status"].map(h => <th key={h} className="text-left px-4 py-2 whitespace-nowrap">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {services.map(s => (
                    <tr key={s.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-mono text-sm font-medium">{s.service_name}</td>
                      <td className="px-4 py-3"><span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded">{s.service_type}</span></td>
                      <td className="px-4 py-3">{criticalityBadge(s.criticality)}</td>
                      <td className="px-4 py-3">{envBadge(s.environment)}</td>
                      <td className="px-4 py-3">{classificationBadge(s.data_classification)}</td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{s.owner}</td>
                      <td className="px-4 py-3"><span className="bg-blue-800 text-blue-200 text-xs px-2 py-0.5 rounded-full">{s.dependency_count} out</span></td>
                      <td className="px-4 py-3"><span className={`${s.dependent_count >= 5 ? "bg-orange-700" : "bg-gray-700"} text-white text-xs px-2 py-0.5 rounded-full`}>{s.dependent_count} in</span></td>
                      <td className="px-4 py-3">{statusBadge(s.status)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Dependency Graph */}
        {activeTab === "graph" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 p-4 border-b border-gray-700">
              <h2 className="font-semibold">Dependency Graph</h2>
              <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterService} onChange={e => setFilterService(e.target.value)}>
                {services.map(s => <option key={s.id} value={s.id}>{s.service_name}</option>)}
              </select>
            </div>
            <div className="p-6">
              <div className="text-center mb-6">
                <div className="inline-block bg-blue-700 text-white font-bold px-6 py-3 rounded-lg shadow-lg">
                  {svcName(filterService)}
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                    <span className="text-blue-400">→</span> Outgoing Dependencies ({outgoing.length})
                  </h3>
                  {outgoing.length === 0 ? <p className="text-gray-500 text-sm">No outgoing dependencies.</p> : (
                    <div className="space-y-2">
                      {outgoing.map(d => (
                        <div key={d.id} className="bg-gray-900 rounded p-3 flex items-center justify-between">
                          <div>
                            <span className="font-mono text-sm text-teal-300">{svcName(d.to_service)}</span>
                            <div className="flex gap-1 mt-1">
                              {criticalityBadge(d.criticality)}
                              <span className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded">{d.dep_type}</span>
                            </div>
                          </div>
                          <div className="text-right text-xs text-gray-400">
                            <div>{d.protocol}</div>
                            <div>:{d.port}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                    <span className="text-orange-400">←</span> Incoming Dependencies ({incoming.length})
                  </h3>
                  {incoming.length === 0 ? <p className="text-gray-500 text-sm">No incoming dependencies.</p> : (
                    <div className="space-y-2">
                      {incoming.map(d => (
                        <div key={d.id} className="bg-gray-900 rounded p-3 flex items-center justify-between">
                          <div>
                            <span className="font-mono text-sm text-orange-300">{svcName(d.from_service)}</span>
                            <div className="flex gap-1 mt-1">
                              {criticalityBadge(d.criticality)}
                              <span className="bg-gray-700 text-gray-300 text-xs px-2 py-0.5 rounded">{d.dep_type}</span>
                            </div>
                          </div>
                          <div className="text-right text-xs text-gray-400">
                            <div>{d.protocol}</div>
                            <div>:{d.port}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Blast Radius */}
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
                    <button key={t} onClick={() => { setAnalysisType(t); setBlastResult(null); }}
                      className={`px-3 py-1 text-sm rounded transition-colors ${analysisType === t ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>
                      {t}
                    </button>
                  ))}
                </div>
                <button onClick={runBlastAnalysis} className="bg-orange-600 hover:bg-orange-700 text-white text-sm px-4 py-1.5 rounded font-medium">Run Analysis</button>
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

        {/* Critical Paths */}
        {activeTab === "critical" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h2 className="font-semibold">Critical Service Paths — Most-depended-upon services</h2>
            </div>
            <div className="divide-y divide-gray-700">
              {criticalPaths.map((s, i) => (
                <div key={s.id} className="p-4 flex items-center gap-4">
                  <div className="text-2xl font-bold text-gray-600 w-8 text-center">#{i + 1}</div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono font-bold">{s.service_name}</span>
                      {criticalityBadge(s.criticality)}
                      {classificationBadge(s.data_classification)}
                      {statusBadge(s.status)}
                    </div>
                    <div className="flex items-center gap-4 text-xs text-gray-400">
                      <span>Owner: {s.owner}</span>
                      <span className="bg-indigo-800 text-indigo-200 px-2 py-0.5 rounded">{s.service_type}</span>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-400 mb-1">Dependents</p>
                    <span className={`text-2xl font-bold ${s.dependent_count >= 8 ? "text-red-400" : s.dependent_count >= 5 ? "text-orange-400" : "text-yellow-400"}`}>{s.dependent_count}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
