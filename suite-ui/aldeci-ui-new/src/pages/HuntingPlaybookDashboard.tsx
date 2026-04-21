import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/hunting-playbooks";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


const playbooks = [
  { id: "pb-001", playbook_name: "Lateral Movement Detection", hunt_type: "proactive", threat_category: "APT", mitre_technique: "T1021", success_rate: 78, execution_count: 24, avg_duration_mins: 45 },
  { id: "pb-002", playbook_name: "Credential Stuffing Hunt", hunt_type: "reactive", threat_category: "Identity", mitre_technique: "T1110", success_rate: 62, execution_count: 18, avg_duration_mins: 30 },
  { id: "pb-003", playbook_name: "DNS Tunneling Detection", hunt_type: "proactive", threat_category: "C2", mitre_technique: "T1071.004", success_rate: 85, execution_count: 12, avg_duration_mins: 60 },
  { id: "pb-004", playbook_name: "Living-off-the-Land Binaries", hunt_type: "hypothesis", threat_category: "Endpoint", mitre_technique: "T1218", success_rate: 55, execution_count: 9, avg_duration_mins: 90 },
  { id: "pb-005", playbook_name: "Ransomware Precursor Hunt", hunt_type: "proactive", threat_category: "Ransomware", mitre_technique: "T1486", success_rate: 90, execution_count: 6, avg_duration_mins: 120 },
];

const executions = [
  { id: "ex-001", playbook_id: "pb-001", analyst: "Alice Chen", start_time: "2026-04-16 08:00", end_time: "2026-04-16 08:47", duration_mins: 47, outcome: "finding", findings_count: 3, iocs_discovered: ["10.10.5.22", "mimikatz.exe"] },
  { id: "ex-002", playbook_id: "pb-002", analyst: "Bob Martinez", start_time: "2026-04-16 09:15", end_time: "2026-04-16 09:44", duration_mins: 29, outcome: "no_finding", findings_count: 0, iocs_discovered: [] },
  { id: "ex-003", playbook_id: "pb-003", analyst: "Carol Patel", start_time: "2026-04-15 14:00", end_time: "2026-04-15 15:03", duration_mins: 63, outcome: "partial", findings_count: 1, iocs_discovered: ["dns.malicious-c2.net"] },
  { id: "ex-004", playbook_id: "pb-001", analyst: "Dan Kim", start_time: "2026-04-15 10:00", end_time: "2026-04-15 10:41", duration_mins: 41, outcome: "inconclusive", findings_count: 0, iocs_discovered: [] },
  { id: "ex-005", playbook_id: "pb-005", analyst: "Eva Singh", start_time: "2026-04-14 16:00", end_time: "2026-04-14 18:05", duration_mins: 125, outcome: "finding", findings_count: 5, iocs_discovered: ["cobalt-strike-beacon", "192.168.1.99", "psexec.exe"] },
];

const hypotheses = [
  { id: "h-001", playbook_id: "pb-001", hypothesis_text: "Attacker has compromised a workstation and is using SMB for lateral movement", confidence: "high", validated: true, evidence: "SMB traffic anomaly detected on SIEM, 3 hosts with unusual connections" },
  { id: "h-002", playbook_id: "pb-002", hypothesis_text: "Credential stuffing campaign targeting VPN portal using leaked credential lists", confidence: "medium", validated: false, evidence: "Elevated failed auth from 5 IPs in Eastern Europe" },
  { id: "h-003", playbook_id: "pb-003", hypothesis_text: "C2 beacon using DNS TXT records for data exfiltration", confidence: "low", validated: false, evidence: "Unusual DNS query volume from finance workstation" },
  { id: "h-004", playbook_id: "pb-005", hypothesis_text: "Threat actor pre-positioned with living-off-the-land tools before ransomware deployment", confidence: "high", validated: true, evidence: "PowerShell execution from svchost.exe observed on 2 servers" },
];

const outcomeBadge = (o: string) => {
  const map: Record<string, string> = { finding: "bg-green-600", partial: "bg-yellow-600", no_finding: "bg-gray-600", inconclusive: "bg-orange-600" };
  return <span className={`${map[o] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{o.replace("_", " ")}</span>;
};

const confBadge = (c: string) => {
  const map: Record<string, string> = { high: "bg-green-600", medium: "bg-yellow-600", low: "bg-red-600" };
  return <span className={`${map[c] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{c}</span>;
};

export default function HuntingPlaybookDashboard() {
  const [activeTab, setActiveTab] = useState<"playbooks" | "executions" | "hypotheses">("playbooks");
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    return fetch(`${_API_BASE}/playbooks?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status}`)))
      .then(d => {
        void d;
      })
      .catch((err) => {
        setFetchError(err instanceof Error ? err.message : "Failed to load playbook data");
      });
  };

  useEffect(() => {
    loadData().finally(() => setLoading(false));
  }, []);

  const [filterPlaybook, setFilterPlaybook] = useState("all");
  const [showAddPlaybook, setShowAddPlaybook] = useState(false);
  const [showStartExec, setShowStartExec] = useState(false);
  const [showAddHypothesis, setShowAddHypothesis] = useState(false);
  const [newPlaybook, setNewPlaybook] = useState({ playbook_name: "", hunt_type: "proactive", threat_category: "", mitre_technique: "" });
  const [newExec, setNewExec] = useState({ playbook_id: "pb-001", analyst: "" });
  const [newHyp, setNewHyp] = useState({ playbook_id: "pb-001", hypothesis_text: "", confidence: "medium" });

  const totalPlaybooks = playbooks.length;
  const totalExecutions = executions.length;
  const overallSuccessRate = Math.round(playbooks.reduce((a, p) => a + p.success_rate, 0) / playbooks.length);
  const activeHunts = 2;

  const filteredExecs = filterPlaybook === "all" ? executions : executions.filter(e => e.playbook_id === filterPlaybook);
  const filteredHyps = filterPlaybook === "all" ? hypotheses : hypotheses.filter(h => h.playbook_id === filterPlaybook);


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Threat Hunting Playbooks</h1>
          <p className="text-gray-400 text-sm mt-1">Hunt execution history, playbook library, and hypothesis tracking</p>
        </div>

        {/* Fetch Error Banner */}
        {fetchError && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between mb-6">
            <span className="text-sm">Failed to load live data: {fetchError}</span>
            <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {[
            { label: "Total Playbooks", value: totalPlaybooks, color: "text-blue-400" },
            { label: "Total Executions", value: totalExecutions, color: "text-purple-400" },
            { label: "Overall Success Rate", value: `${overallSuccessRate}%`, color: "text-green-400" },
            { label: "Active Hunts", value: activeHunts, color: "text-yellow-400" },
          ].map(c => (
            <div key={c.label} className="bg-gray-800 rounded-lg p-6">
              <p className="text-gray-400 text-sm">{c.label}</p>
              <p className={`text-3xl font-bold mt-1 ${c.color}`}>{c.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(["playbooks", "executions", "hypotheses"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
              {t}
            </button>
          ))}
        </div>

        {/* Playbooks */}
        {activeTab === "playbooks" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <h2 className="font-semibold">Playbook Library</h2>
              <button onClick={() => setShowAddPlaybook(!showAddPlaybook)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Playbook</button>
            </div>
            {showAddPlaybook && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Playbook name" value={newPlaybook.playbook_name} onChange={e => setNewPlaybook({ ...newPlaybook, playbook_name: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newPlaybook.hunt_type} onChange={e => setNewPlaybook({ ...newPlaybook, hunt_type: e.target.value })}>
                  <option value="proactive">Proactive</option><option value="reactive">Reactive</option><option value="hypothesis">Hypothesis</option>
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Threat category" value={newPlaybook.threat_category} onChange={e => setNewPlaybook({ ...newPlaybook, threat_category: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="MITRE technique (e.g. T1021)" value={newPlaybook.mitre_technique} onChange={e => setNewPlaybook({ ...newPlaybook, mitre_technique: e.target.value })} />
                <div className="flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddPlaybook(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddPlaybook(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Playbook Name", "Hunt Type", "Threat Category", "MITRE", "Success Rate", "Executions", "Avg Duration", "Action"].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {playbooks.map(p => (
                    <tr key={p.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-medium">{p.playbook_name}</td>
                      <td className="px-4 py-3"><span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded">{p.hunt_type}</span></td>
                      <td className="px-4 py-3"><span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{p.threat_category}</span></td>
                      <td className="px-4 py-3"><span className="font-mono text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{p.mitre_technique}</span></td>
                      <td className="px-4 py-3 min-w-[140px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-2">
                            <div className={`h-2 rounded-full ${p.success_rate >= 70 ? "bg-green-500" : p.success_rate >= 40 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${p.success_rate}%` }} />
                          </div>
                          <span className="text-xs text-gray-400 w-8">{p.success_rate}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3"><span className="bg-gray-700 text-white text-xs px-2 py-0.5 rounded-full">{p.execution_count}</span></td>
                      <td className="px-4 py-3 text-gray-300">{p.avg_duration_mins}m</td>
                      <td className="px-4 py-3">
                        <button onClick={() => { setShowStartExec(true); setNewExec({ ...newExec, playbook_id: p.id }); setActiveTab("executions"); }} className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Execute</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Executions */}
        {activeTab === "executions" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <h2 className="font-semibold">Execution History</h2>
                <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterPlaybook} onChange={e => setFilterPlaybook(e.target.value)}>
                  <option value="all">All Playbooks</option>
                  {playbooks.map(p => <option key={p.id} value={p.id}>{p.playbook_name}</option>)}
                </select>
              </div>
              <button onClick={() => setShowStartExec(!showStartExec)} className="bg-green-600 hover:bg-green-700 text-white text-sm px-3 py-1 rounded">+ Start Execution</button>
            </div>
            {showStartExec && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newExec.playbook_id} onChange={e => setNewExec({ ...newExec, playbook_id: e.target.value })}>
                  {playbooks.map(p => <option key={p.id} value={p.id}>{p.playbook_name}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Analyst name" value={newExec.analyst} onChange={e => setNewExec({ ...newExec, analyst: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowStartExec(false)}>Start Hunt</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowStartExec(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="divide-y divide-gray-700">
              {filteredExecs.map(e => (
                <div key={e.id} className="p-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-sm">{playbooks.find(p => p.id === e.playbook_id)?.playbook_name}</span>
                        {outcomeBadge(e.outcome)}
                        {e.findings_count > 0 && <span className="bg-red-700 text-white text-xs px-2 py-0.5 rounded-full">{e.findings_count} findings</span>}
                      </div>
                      <div className="text-xs text-gray-400">Analyst: {e.analyst} | {e.start_time} → {e.end_time} | {e.duration_mins}m</div>
                      {e.iocs_discovered.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {e.iocs_discovered.map(ioc => <span key={ioc} className="bg-red-900 text-red-300 text-xs px-2 py-0.5 rounded font-mono">{ioc}</span>)}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Hypotheses */}
        {activeTab === "hypotheses" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <h2 className="font-semibold">Hunt Hypotheses</h2>
                <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterPlaybook} onChange={e => setFilterPlaybook(e.target.value)}>
                  <option value="all">All Playbooks</option>
                  {playbooks.map(p => <option key={p.id} value={p.id}>{p.playbook_name}</option>)}
                </select>
              </div>
              <button onClick={() => setShowAddHypothesis(!showAddHypothesis)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Hypothesis</button>
            </div>
            {showAddHypothesis && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newHyp.playbook_id} onChange={e => setNewHyp({ ...newHyp, playbook_id: e.target.value })}>
                  {playbooks.map(p => <option key={p.id} value={p.id}>{p.playbook_name}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newHyp.confidence} onChange={e => setNewHyp({ ...newHyp, confidence: e.target.value })}>
                  <option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                </select>
                <textarea className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2 h-20 resize-none" placeholder="Hypothesis text" value={newHyp.hypothesis_text} onChange={e => setNewHyp({ ...newHyp, hypothesis_text: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddHypothesis(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddHypothesis(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="divide-y divide-gray-700">
              {filteredHyps.map(h => (
                <div key={h.id} className="p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        {confBadge(h.confidence)}
                        {h.validated
                          ? <span className="text-green-400 text-xs font-medium">✓ Validated</span>
                          : <span className="text-orange-400 text-xs font-medium">⏳ Pending</span>}
                      </div>
                      <p className="text-sm font-medium">{h.hypothesis_text}</p>
                      <p className="text-gray-400 text-xs mt-1">Evidence: {h.evidence}</p>
                    </div>
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
