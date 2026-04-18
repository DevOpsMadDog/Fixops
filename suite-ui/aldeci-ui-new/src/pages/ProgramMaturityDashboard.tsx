import { useState, useEffect } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

const domains = [
  { id: "d-001", domain_name: "Identity & Access Management", domain_type: "identity", current_level: 3, target_level: 4, score: 68, last_assessed: "2026-04-10" },
  { id: "d-002", domain_name: "Vulnerability Management", domain_type: "vuln_mgmt", current_level: 4, target_level: 5, score: 82, last_assessed: "2026-04-08" },
  { id: "d-003", domain_name: "Incident Response", domain_type: "ir", current_level: 2, target_level: 4, score: 45, last_assessed: "2026-04-12" },
  { id: "d-004", domain_name: "Security Awareness", domain_type: "awareness", current_level: 3, target_level: 3, score: 72, last_assessed: "2026-04-05" },
  { id: "d-005", domain_name: "Data Protection", domain_type: "data", current_level: 2, target_level: 4, score: 40, last_assessed: "2026-04-11" },
  { id: "d-006", domain_name: "Network Security", domain_type: "network", current_level: 4, target_level: 4, score: 88, last_assessed: "2026-04-09" },
];

const assessments = [
  { id: "a-001", assessment_name: "Q1 2026 Maturity Assessment", assessor: "External Auditor", status: "completed", overall_level: 3.2, overall_score: 66, domains_assessed: 6, completed_at: "2026-04-01" },
  { id: "a-002", assessment_name: "Q4 2025 Maturity Assessment", assessor: "Internal Team", status: "completed", overall_level: 2.8, overall_score: 58, domains_assessed: 6, completed_at: "2026-01-10" },
  { id: "a-003", assessment_name: "Q2 2026 Maturity Assessment", assessor: "External Auditor", status: "in_progress", overall_level: 0, overall_score: 0, domains_assessed: 3, completed_at: "" },
];

const improvements = [
  { id: "i-001", domain_id: "d-003", improvement_name: "Implement IR playbooks for top 5 scenarios", priority: "critical", target_level: 3, effort_days: 30, status: "in_progress", due_date: "2026-05-01" },
  { id: "i-002", domain_id: "d-005", improvement_name: "Deploy DLP tooling across endpoints", priority: "high", target_level: 3, effort_days: 60, status: "planned", due_date: "2026-06-15" },
  { id: "i-003", domain_id: "d-001", improvement_name: "Implement privileged access workstations", priority: "high", target_level: 4, effort_days: 45, status: "planned", due_date: "2026-05-30" },
  { id: "i-004", domain_id: "d-002", improvement_name: "Achieve full asset coverage in vuln scans", priority: "medium", target_level: 5, effort_days: 20, status: "in_progress", due_date: "2026-04-30" },
  { id: "i-005", domain_id: "d-004", improvement_name: "Launch phishing simulation programme", priority: "medium", target_level: 4, effort_days: 15, status: "completed", due_date: "2026-04-15" },
  { id: "i-006", domain_id: "d-003", improvement_name: "Red team exercise for IR validation", priority: "low", target_level: 4, effort_days: 90, status: "planned", due_date: "2026-08-01" },
];

const levelColor = (l: number) => l <= 2 ? "bg-red-500" : l === 3 ? "bg-yellow-500" : "bg-green-500";
const statusBadge = (s: string) => {
  const map: Record<string, string> = { planned: "bg-gray-600", in_progress: "bg-blue-600", completed: "bg-green-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s.replace("_", " ")}</span>;
};
const priorityBadge = (p: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-600", low: "bg-gray-600" };
  return <span className={`${map[p] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{p}</span>;
};

export default function ProgramMaturityDashboard() {
  const [activeTab, setActiveTab] = useState<"domains" | "assessments" | "roadmap">("domains");
  const [error, setError] = useState<string | null>(null);
  const [filterDomain, setFilterDomain] = useState("all");
  const [showAddDomain, setShowAddDomain] = useState(false);

  useEffect(() => {
    apiFetch(`/api/v1/program-maturity/domains?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); });
  }, []);
  const [showAddImprovement, setShowAddImprovement] = useState(false);
  const [newDomain, setNewDomain] = useState({ domain_name: "", domain_type: "identity", current_level: 1, target_level: 3 });
  const [newImprovement, setNewImprovement] = useState({ domain_id: "d-001", improvement_name: "", priority: "medium", target_level: 3, effort_days: 30, due_date: "" 
    setLoading(false);});
  const [loading, setLoading] = useState(true);

  const avgCurrentLevel = (domains.reduce((a, d) => a + d.current_level, 0) / domains.length).toFixed(1);
  const avgScore = Math.round(domains.reduce((a, d) => a + d.score, 0) / domains.length);
  const domainsAtTarget = domains.filter(d => d.current_level >= d.target_level).length;
  const pendingImprovements = improvements.filter(i => i.status !== "completed").length;

  const filteredImprovements = filterDomain === "all" ? improvements : improvements.filter(i => i.domain_id === filterDomain);
  const today = "2026-04-16";

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Security Program Maturity</h1>
          <p className="text-gray-400 text-sm mt-1">CMMI-style maturity levels, domain assessments, and improvement roadmap</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Avg Current Level</p>
            <p className="text-3xl font-bold mt-1 text-blue-400">{avgCurrentLevel}<span className="text-lg text-gray-500">/5</span></p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm mb-2">Avg Score</p>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-gray-700 rounded-full h-3">
                <div className="h-3 rounded-full bg-blue-500" style={{ width: `${avgScore}%` }} />
              </div>
              <span className="text-blue-400 font-bold">{avgScore}</span>
            </div>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Domains at Target</p>
            <p className="text-3xl font-bold mt-1 text-green-400">{domainsAtTarget}<span className="text-lg text-gray-500">/{domains.length}</span></p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Pending Improvements</p>
            <p className="text-3xl font-bold mt-1 text-orange-400">{pendingImprovements}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(["domains", "assessments", "roadmap"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
              {t}
            </button>
          ))}
        </div>

        {/* Domains Grid */}
        {activeTab === "domains" && (
          <>
            <div className="flex justify-between items-center mb-4">
              <h2 className="font-semibold">Maturity Domains</h2>
              <button onClick={() => setShowAddDomain(!showAddDomain)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Domain</button>
            </div>
            {showAddDomain && (
              <div className="bg-gray-800 rounded-lg p-4 mb-4 grid grid-cols-2 gap-3">
                <input className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Domain name" value={newDomain.domain_name} onChange={e => setNewDomain({ ...newDomain, domain_name: e.target.value })} />
                <select className="bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newDomain.domain_type} onChange={e => setNewDomain({ ...newDomain, domain_type: e.target.value })}>
                  {["identity", "vuln_mgmt", "ir", "awareness", "data", "network"].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <div className="flex gap-2">
                  <label className="text-xs text-gray-400 self-center">Current:</label>
                  <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1.5 text-sm flex-1" value={newDomain.current_level} onChange={e => setNewDomain({ ...newDomain, current_level: +e.target.value })}>
                    {[1,2,3,4,5].map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                  <label className="text-xs text-gray-400 self-center">Target:</label>
                  <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1.5 text-sm flex-1" value={newDomain.target_level} onChange={e => setNewDomain({ ...newDomain, target_level: +e.target.value })}>
                    {[1,2,3,4,5].map(n => <option key={n} value={n}>{n}</option>)}
                  </select>
                </div>
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddDomain(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddDomain(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {domains.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                domains.map(d => {
                const gap = d.current_level - d.target_level;
                return (
                  <div key={d.id} className="bg-gray-800 rounded-lg p-5">
                    <div className="flex justify-between items-start mb-3">
                      <div>
                        <h3 className="font-semibold text-sm">{d.domain_name}</h3>
                        <span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded mt-1 inline-block">{d.domain_type.replace("_", " ")}</span>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded ${gap < 0 ? "bg-red-700 text-red-100" : "bg-green-700 text-green-100"}`}>
                        {gap === 0 ? "At Target" : `Gap: ${gap}`}
                      </span>
                    </div>
                    <div className="mb-3">
                      <div className="flex justify-between text-xs text-gray-400 mb-1">
                        <span>Current Level: <strong className="text-white">{d.current_level}/5</strong></span>
                        <span>Target: {d.target_level}/5</span>
                      </div>
                      <div className="flex gap-1">
                        {[1,2,3,4,5].map(lvl => (
                          <div key={lvl} className={`flex-1 h-3 rounded ${lvl <= d.current_level ? levelColor(d.current_level) : "bg-gray-700"} ${lvl === d.target_level ? "ring-2 ring-white ring-opacity-50" : ""}`} />
                        ))}
                      </div>
                    </div>
                    <div className="mb-2">
                      <div className="flex justify-between text-xs text-gray-400 mb-1"><span>Score</span><span>{d.score}/100</span></div>
                      <div className="bg-gray-700 rounded-full h-2">
                        <div className={`h-2 rounded-full ${d.score >= 80 ? "bg-green-500" : d.score >= 60 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${d.score}%` }} />
                      </div>
                    </div>
                    <p className="text-gray-500 text-xs">Last assessed: {d.last_assessed}</p>
                  </div>
                );
              })}
              )}
            </div>
          </>
        )}

        {/* Assessments */}
        {activeTab === "assessments" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700"><h2 className="font-semibold">Assessment History</h2></div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Assessment", "Assessor", "Status", "Overall Level", "Score", "Domains", "Completed"].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {assessments.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    assessments.map(a => (
                    <tr key={a.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-medium">{a.assessment_name}</td>
                      <td className="px-4 py-3 text-gray-300">{a.assessor}</td>
                      <td className="px-4 py-3">{statusBadge(a.status)}</td>
                      <td className="px-4 py-3 text-blue-400 font-bold">{a.overall_level > 0 ? `${a.overall_level}/5` : "—"}</td>
                      <td className="px-4 py-3 min-w-[140px]">
                        {a.overall_score > 0 ? (
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-gray-700 rounded-full h-2">
                              <div className="h-2 rounded-full bg-blue-500" style={{ width: `${a.overall_score}%` }} />
                            </div>
                            <span className="text-xs text-gray-400 w-8">{a.overall_score}</span>
                          </div>
                        ) : <span className="text-gray-500">—</span>}
                      </td>
                      <td className="px-4 py-3"><span className="bg-gray-700 text-white text-xs px-2 py-0.5 rounded-full">{a.domains_assessed}</span></td>
                      <td className="px-4 py-3 text-gray-400">{a.completed_at || "—"}</td>
                    </tr>
                  ))}
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Roadmap */}
        {activeTab === "roadmap" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <h2 className="font-semibold">Improvement Roadmap</h2>
                <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterDomain} onChange={e => setFilterDomain(e.target.value)}>
                  <option value="all">All Domains</option>
                  {domains.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    domains.map(d => <option key={d.id} value={d.id}>{d.domain_name}</option>)}
                </select>
              </div>
              <button onClick={() => setShowAddImprovement(!showAddImprovement)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Improvement</button>
                  )}
            </div>
            {showAddImprovement && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newImprovement.domain_id} onChange={e => setNewImprovement({ ...newImprovement, domain_id: e.target.value })}>
                  {domains.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    domains.map(d => <option key={d.id} value={d.id}>{d.domain_name}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newImprovement.priority} onChange={e => setNewImprovement({ ...newImprovement, priority: e.target.value })}>
                  )}
                  {["critical","high","medium","low"].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Improvement name" value={newImprovement.improvement_name} onChange={e => setNewImprovement({ ...newImprovement, improvement_name: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" type="date" value={newImprovement.due_date} onChange={e => setNewImprovement({ ...newImprovement, due_date: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" type="number" placeholder="Effort (days)" value={newImprovement.effort_days} onChange={e => setNewImprovement({ ...newImprovement, effort_days: +e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddImprovement(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddImprovement(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="divide-y divide-gray-700">
              {filteredImprovements.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                filteredImprovements.map(i => {
                const domain = domains.find(d => d.id === i.domain_id);
                const overdue = i.status !== "completed" && i.due_date < today;
                return (
                  <div key={i.id} className="p-4 flex items-center gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        {priorityBadge(i.priority)}
                        <span className="text-sm font-medium">{i.improvement_name}</span>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-400">
                        <span>{domain?.domain_name}</span>
                        <span>Target Level: <strong className="text-white">{i.target_level}</strong></span>
                        <span className="bg-gray-700 px-2 py-0.5 rounded">{i.effort_days}d effort</span>
                        <span className={overdue ? "text-red-400 font-medium" : ""}>Due: {i.due_date}{overdue ? " OVERDUE" : ""}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {statusBadge(i.status)}
                      {i.status !== "completed" && <button className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Complete</button>}
                    </div>
                  </div>
                );
              })}
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
