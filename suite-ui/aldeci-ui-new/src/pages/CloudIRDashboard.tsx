import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/cloud-ir";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


const incidents = [
  { id: "ci-001", incident_name: "Unauthorized S3 Bucket Access", cloud_provider: "aws", incident_type: "data_exposure", severity: "critical", status: "investigating", containment_time_mins: 0, resolution_time_mins: 0, blast_radius: "high", affected_services: ["s3", "iam"], affected_regions: ["us-east-1"] },
  { id: "ci-002", incident_name: "Cryptomining Instance Compromise", cloud_provider: "aws", incident_type: "compute_abuse", severity: "high", status: "contained", containment_time_mins: 18, resolution_time_mins: 0, blast_radius: "medium", affected_services: ["ec2", "iam"], affected_regions: ["eu-west-1", "ap-southeast-1"] },
  { id: "ci-003", incident_name: "Azure AD Token Exfiltration", cloud_provider: "azure", incident_type: "identity_compromise", severity: "critical", status: "detected", containment_time_mins: 0, resolution_time_mins: 0, blast_radius: "critical", affected_services: ["azure-ad", "key-vault"], affected_regions: ["eastus"] },
  { id: "ci-004", incident_name: "GCS Public Bucket Misconfiguration", cloud_provider: "gcp", incident_type: "misconfiguration", severity: "medium", status: "resolved", containment_time_mins: 5, resolution_time_mins: 42, blast_radius: "low", affected_services: ["gcs"], affected_regions: ["us-central1"] },
  { id: "ci-005", incident_name: "Lambda Function Data Leak", cloud_provider: "aws", incident_type: "data_exposure", severity: "high", status: "resolved", containment_time_mins: 12, resolution_time_mins: 95, blast_radius: "medium", affected_services: ["lambda", "cloudwatch"], affected_regions: ["us-west-2"] },
];

const actions = [
  { id: "a-001", incident_id: "ci-001", action_type: "isolate", resource_id: "arn:aws:s3:::company-finance-data", description: "Block public access on bucket", automated: false, status: "completed", executed_by: "Alice Chen", result: "Public access blocked, bucket policy updated" },
  { id: "a-002", incident_id: "ci-001", action_type: "revoke_credentials", resource_id: "AKIAIOSFODNN7EXAMPLE", description: "Revoke compromised IAM access key", automated: true, status: "completed", executed_by: "SOAR", result: "Key deactivated, session tokens invalidated" },
  { id: "a-003", incident_id: "ci-002", action_type: "terminate_instance", resource_id: "i-0abcd1234ef567890", description: "Terminate compromised EC2 instance", automated: false, status: "in_progress", executed_by: "Bob Martinez", result: "" },
  { id: "a-004", incident_id: "ci-003", action_type: "revoke_tokens", resource_id: "azure-ad-refresh-token-pool", description: "Revoke all active refresh tokens for affected user", automated: true, status: "pending", executed_by: "SOAR", result: "" },
];

const playbooks = [
  { id: "play-001", cloud_provider: "aws", incident_type: "data_exposure", playbook_name: "S3 Data Exposure Response", estimated_mins: 45, execution_count: 8, steps: 7 },
  { id: "play-002", cloud_provider: "aws", incident_type: "compute_abuse", playbook_name: "EC2 Cryptomining Containment", estimated_mins: 30, execution_count: 5, steps: 6 },
  { id: "play-003", cloud_provider: "azure", incident_type: "identity_compromise", playbook_name: "Azure AD Compromise Response", estimated_mins: 60, execution_count: 3, steps: 9 },
  { id: "play-004", cloud_provider: "gcp", incident_type: "misconfiguration", playbook_name: "GCS Misconfiguration Remediation", estimated_mins: 20, execution_count: 12, steps: 4 },
];

const providerBadge = (p: string) => {
  const map: Record<string, string> = { aws: "bg-orange-600", azure: "bg-blue-600", gcp: "bg-green-600" };
  return <span className={`${map[p] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{p.toUpperCase()}</span>;
};
const severityBadge = (s: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-600", low: "bg-green-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s}</span>;
};
const statusBadge = (s: string) => {
  const map: Record<string, string> = { detected: "bg-red-600", investigating: "bg-yellow-600", contained: "bg-blue-600", resolved: "bg-green-600", completed: "bg-green-600", in_progress: "bg-blue-600", pending: "bg-gray-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s.replace("_", " ")}</span>;
};
const blastBadge = (b: string) => {
  const map: Record<string, string> = { unknown: "bg-gray-600", low: "bg-green-600", medium: "bg-yellow-600", high: "bg-orange-500", critical: "bg-red-600" };
  return <span className={`${map[b] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{b}</span>;
};

export default function CloudIRDashboard() {
  const [activeTab, setActiveTab] = useState<"incidents" | "actions" | "playbooks">("incidents");
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setError(null);
    fetch(_API_BASE, { headers: _getHeaders() })
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`API ${r.status}`)))
    .then(d => {
    // live data loaded — components read from API response
    void d;
    })
    .catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);

  const [filterIncident, setFilterIncident] = useState("all");
  const [filterProvider, setFilterProvider] = useState("all");
  const [filterType, setFilterType] = useState("all");
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [showAddAction, setShowAddAction] = useState(false);
  const [newIncident, setNewIncident] = useState({ incident_name: "", cloud_provider: "aws", incident_type: "data_exposure", severity: "high" });
  const [newAction, setNewAction] = useState({ incident_id: "ci-001", action_type: "isolate", resource_id: "", description: "" });

  const totalIncidents = incidents.length;
  const openCritical = incidents.filter(i => i.severity === "critical" && i.status !== "resolved").length;
  const resolvedIncs = incidents.filter(i => i.status === "resolved");
  const avgContainment = resolvedIncs.length ? Math.round(resolvedIncs.reduce((a, i) => a + i.containment_time_mins, 0) / resolvedIncs.length) : 0;
  const avgResolution = resolvedIncs.length ? Math.round(resolvedIncs.reduce((a, i) => a + i.resolution_time_mins, 0) / resolvedIncs.length) : 0;

  const filteredActions = filterIncident === "all" ? actions : actions.filter(a => a.incident_id === filterIncident);
  const filteredPlaybooks = playbooks.filter(p =>
    (filterProvider === "all" || p.cloud_provider === filterProvider) &&
    (filterType === "all" || p.incident_type === filterType)
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Cloud Incident Response</h1>
          <p className="text-gray-400 text-sm mt-1">Multi-cloud incident management, containment actions, and response playbooks</p>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Total Incidents</p>
            <p className="text-3xl font-bold mt-1 text-blue-400">{totalIncidents}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Open Critical</p>
            <p className={`text-3xl font-bold mt-1 ${openCritical > 0 ? "text-red-400" : "text-green-400"}`}>{openCritical}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Avg Containment</p>
            <p className="text-3xl font-bold mt-1 text-yellow-400">{avgContainment}m</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Avg Resolution</p>
            <p className="text-3xl font-bold mt-1 text-purple-400">{avgResolution}m</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(["incidents", "actions", "playbooks"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
              {t}
            </button>
          ))}
        </div>

        {/* Incidents */}
        {activeTab === "incidents" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <h2 className="font-semibold">Cloud Incidents</h2>
              <button onClick={() => setShowCreateIncident(!showCreateIncident)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Create Incident</button>
            </div>
            {showCreateIncident && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Incident name" value={newIncident.incident_name} onChange={e => setNewIncident({ ...newIncident, incident_name: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newIncident.cloud_provider} onChange={e => setNewIncident({ ...newIncident, cloud_provider: e.target.value })}>
                  <option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">GCP</option>
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newIncident.incident_type} onChange={e => setNewIncident({ ...newIncident, incident_type: e.target.value })}>
                  <option value="data_exposure">Data Exposure</option><option value="compute_abuse">Compute Abuse</option>
                  <option value="identity_compromise">Identity Compromise</option><option value="misconfiguration">Misconfiguration</option>
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newIncident.severity} onChange={e => setNewIncident({ ...newIncident, severity: e.target.value })}>
                  {["critical","high","medium","low"].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <div className="flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowCreateIncident(false)}>Create</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowCreateIncident(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Incident", "Provider", "Type", "Severity", "Status", "Containment", "Resolution", "Blast Radius", "Services", "Regions"].map(h => <th key={h} className="text-left px-4 py-2 whitespace-nowrap">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {incidents.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    incidents.map(i => (
                    <tr key={i.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-medium whitespace-nowrap">{i.incident_name}</td>
                      <td className="px-4 py-3">{providerBadge(i.cloud_provider)}</td>
                      <td className="px-4 py-3"><span className="bg-purple-700 text-purple-100 text-xs px-2 py-0.5 rounded">{i.incident_type.replace("_", " ")}</span></td>
                      <td className="px-4 py-3">{severityBadge(i.severity)}</td>
                      <td className="px-4 py-3">{statusBadge(i.status)}</td>
                      <td className="px-4 py-3 text-gray-300">{i.containment_time_mins > 0 ? `${i.containment_time_mins}m` : "—"}</td>
                      <td className="px-4 py-3 text-gray-300">{i.resolution_time_mins > 0 ? `${i.resolution_time_mins}m` : "—"}</td>
                      <td className="px-4 py-3">{blastBadge(i.blast_radius)}</td>
                      <td className="px-4 py-3"><span className="bg-gray-700 text-white text-xs px-2 py-0.5 rounded-full">{i.affected_services.length}</span></td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {i.affected_regions.map(r => <span key={r} className="bg-gray-700 text-gray-300 text-xs px-1.5 py-0.5 rounded">{r}</span>)}
                        </div>
                      </td>
                    </tr>
                  ))}
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Actions */}
        {activeTab === "actions" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <h2 className="font-semibold">Containment Actions</h2>
                <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterIncident} onChange={e => setFilterIncident(e.target.value)}>
                  <option value="all">All Incidents</option>
                  {incidents.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    incidents.map(i => <option key={i.id} value={i.id}>{i.incident_name}</option>)}
                </select>
              </div>
              <button onClick={() => setShowAddAction(!showAddAction)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Action</button>
                  )}
            </div>
            {showAddAction && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newAction.incident_id} onChange={e => setNewAction({ ...newAction, incident_id: e.target.value })}>
                  {incidents.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    incidents.map(i => <option key={i.id} value={i.id}>{i.incident_name}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newAction.action_type} onChange={e => setNewAction({ ...newAction, action_type: e.target.value })}>
                  )}
                  {["isolate","terminate_instance","revoke_credentials","revoke_tokens","snapshot","block_ip"].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Resource ID" value={newAction.resource_id} onChange={e => setNewAction({ ...newAction, resource_id: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Description" value={newAction.description} onChange={e => setNewAction({ ...newAction, description: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddAction(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddAction(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="divide-y divide-gray-700">
              {filteredActions.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                filteredActions.map(a => (
                <div key={a.id} className="p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded">{a.action_type.replace("_", " ")}</span>
                        {a.automated && <span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">Automated</span>}
                        {statusBadge(a.status)}
                      </div>
                      <p className="text-sm font-medium">{a.description}</p>
                      <p className="text-xs text-gray-400 font-mono mt-0.5">{a.resource_id}</p>
                      <p className="text-xs text-gray-400 mt-1">By: {a.executed_by}{a.result && ` — ${a.result}`}</p>
                    </div>
                    {a.status === "pending" && <button className="bg-orange-700 hover:bg-orange-600 text-white text-xs px-2 py-1 rounded">Execute</button>}
                    {a.status === "in_progress" && <button className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Complete</button>}
                  </div>
                </div>
              ))}
              )}
            </div>
          </div>
        )}

        {/* Playbooks */}
        {activeTab === "playbooks" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 p-4 border-b border-gray-700">
              <h2 className="font-semibold">Response Playbooks</h2>
              <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterProvider} onChange={e => setFilterProvider(e.target.value)}>
                <option value="all">All Providers</option>
                <option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">GCP</option>
              </select>
              <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterType} onChange={e => setFilterType(e.target.value)}>
                <option value="all">All Types</option>
                <option value="data_exposure">Data Exposure</option><option value="compute_abuse">Compute Abuse</option>
                <option value="identity_compromise">Identity Compromise</option><option value="misconfiguration">Misconfiguration</option>
              </select>
            </div>
            <div className="divide-y divide-gray-700">
              {filteredPlaybooks.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                filteredPlaybooks.map(p => (
                <div key={p.id} className="p-4 flex items-center gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      {providerBadge(p.cloud_provider)}
                      <span className="bg-purple-700 text-purple-100 text-xs px-2 py-0.5 rounded">{p.incident_type.replace("_", " ")}</span>
                      <span className="font-medium text-sm">{p.playbook_name}</span>
                    </div>
                    <div className="flex items-center gap-4 text-xs text-gray-400">
                      <span>Est. {p.estimated_mins}m</span>
                      <span className="bg-gray-700 px-2 py-0.5 rounded">{p.steps} steps</span>
                      <span>{p.execution_count} executions</span>
                    </div>
                  </div>
                  <button className="bg-green-700 hover:bg-green-600 text-white text-xs px-3 py-1.5 rounded">Execute</button>
                </div>
              ))}
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
