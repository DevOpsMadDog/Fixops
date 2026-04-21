import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/identity-lifecycle";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });


const accounts = [
  { id: "acc-001", username: "alice.chen", display_name: "Alice Chen", account_type: "employee", department: "Engineering", manager: "david.kim", status: "active", last_active: "2026-04-16", provisioned_at: "2024-01-15" },
  { id: "acc-002", username: "bob.martinez", display_name: "Bob Martinez", account_type: "employee", department: "Security", manager: "carol.patel", status: "active", last_active: "2026-04-15", provisioned_at: "2023-06-01" },
  { id: "acc-003", username: "svc-payment-api", display_name: "Payment API Service", account_type: "service", department: "Platform", manager: "alice.chen", status: "active", last_active: "2026-04-16", provisioned_at: "2023-09-10" },
  { id: "acc-004", username: "contractor.james", display_name: "James Wilson", account_type: "contractor", department: "IT", manager: "bob.martinez", status: "active", last_active: "2025-12-01", provisioned_at: "2025-09-01" },
  { id: "acc-005", username: "vendor.oracle", display_name: "Oracle Support", account_type: "vendor", department: "External", manager: "carol.patel", status: "suspended", last_active: "2026-01-10", provisioned_at: "2024-03-20" },
  { id: "acc-006", username: "ex.employee.trent", display_name: "Trent Hollis", account_type: "employee", department: "Finance", manager: "david.kim", status: "deprovisioned", last_active: "2025-10-01", provisioned_at: "2022-04-01" },
  { id: "acc-007", username: "svc-legacy-batch", display_name: "Legacy Batch Job", account_type: "service", department: "Platform", manager: "", status: "active", last_active: "2025-06-15", provisioned_at: "2020-01-01" },
];

const entitlements = [
  { id: "ent-001", account_id: "acc-001", system_name: "GitHub", role: "maintainer", access_level: "write", granted_by: "david.kim", expires_at: "", status: "active" },
  { id: "ent-002", account_id: "acc-001", system_name: "AWS", role: "developer", access_level: "write", granted_by: "alice.chen", expires_at: "2026-06-30", status: "active" },
  { id: "ent-003", account_id: "acc-002", system_name: "Splunk", role: "analyst", access_level: "read", granted_by: "carol.patel", expires_at: "", status: "active" },
  { id: "ent-004", account_id: "acc-002", system_name: "AWS", role: "security-admin", access_level: "admin", granted_by: "carol.patel", expires_at: "2026-04-20", status: "active" },
  { id: "ent-005", account_id: "acc-003", system_name: "Database", role: "service-account", access_level: "write", granted_by: "alice.chen", expires_at: "", status: "active" },
  { id: "ent-006", account_id: "acc-004", system_name: "Jira", role: "contributor", access_level: "write", granted_by: "bob.martinez", expires_at: "2026-05-01", status: "active" },
  { id: "ent-007", account_id: "acc-005", system_name: "Oracle DB", role: "dba", access_level: "admin", granted_by: "carol.patel", expires_at: "2026-02-01", status: "active" },
];

const events = [
  { id: "ev-001", account_id: "acc-001", event_type: "provisioned", performed_by: "hr-system", event_time: "2024-01-15 09:00" },
  { id: "ev-002", account_id: "acc-005", event_type: "suspended", performed_by: "carol.patel", event_time: "2026-01-15 14:30" },
  { id: "ev-003", account_id: "acc-006", event_type: "deprovisioned", performed_by: "hr-system", event_time: "2025-10-05 17:00" },
  { id: "ev-004", account_id: "acc-002", event_type: "access_granted", performed_by: "carol.patel", event_time: "2026-04-10 11:00" },
  { id: "ev-005", account_id: "acc-004", event_type: "access_revoked", performed_by: "bob.martinez", event_time: "2026-03-01 09:30" },
];

const typeBadge = (t: string) => {
  const map: Record<string, string> = { employee: "bg-blue-600", contractor: "bg-orange-600", service: "bg-purple-600", vendor: "bg-gray-600" };
  return <span className={`${map[t] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{t}</span>;
};
const statusBadge = (s: string) => {
  const map: Record<string, string> = { active: "bg-green-600", suspended: "bg-yellow-600", deprovisioned: "bg-red-600", revoked: "bg-red-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s}</span>;
};
const accessBadge = (a: string) => {
  const map: Record<string, string> = { read: "bg-blue-700", write: "bg-orange-700", admin: "bg-red-700" };
  return <span className={`${map[a] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{a}</span>;
};
const eventBadge = (e: string) => {
  const map: Record<string, string> = { provisioned: "bg-green-700", suspended: "bg-yellow-700", deprovisioned: "bg-red-700", access_granted: "bg-blue-700", access_revoked: "bg-orange-700" };
  return <span className={`${map[e] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{e.replace("_", " ")}</span>;
};

function daysSince(dateStr: string): number {
  const d = new Date(dateStr);
  const now = new Date("2026-04-16");
  return Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
}

export default function IdentityLifecycleDashboard() {
  const [activeTab, setActiveTab] = useState<"accounts" | "entitlements" | "orphans" | "events">("accounts");
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    return fetch(`${_API_BASE}/accounts?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`${r.status}`)))
      .then(d => {
        void d;
      })
      .catch((err) => {
        setFetchError(err instanceof Error ? err.message : "Failed to load identity lifecycle data");
      });
  };

  useEffect(() => {
    loadData().finally(() => setLoading(false));
  }, []);

  const [filterAccount, setFilterAccount] = useState("all");
  const [showAddAccount, setShowAddAccount] = useState(false);
  const [showGrantAccess, setShowGrantAccess] = useState(false);
  const [newAccount, setNewAccount] = useState({ username: "", display_name: "", account_type: "employee", department: "", manager: "" });
  const [newEntitlement, setNewEntitlement] = useState({ account_id: "acc-001", system_name: "", role: "", access_level: "read" });

  const totalAccounts = accounts.length;
  const activeAccounts = accounts.filter(a => a.status === "active").length;
  const orphans = accounts.filter(a => a.status === "active" && daysSince(a.last_active) > 90).length;
  const totalEntitlements = entitlements.length;

  const filteredEntitlements = filterAccount === "all" ? entitlements : entitlements.filter(e => e.account_id === filterAccount);
  const filteredEvents = filterAccount === "all" ? events : events.filter(e => e.account_id === filterAccount);
  const orphanAccounts = accounts
    .filter(a => a.status === "active" && daysSince(a.last_active) > 90)
    .sort((a, b) => daysSince(b.last_active) - daysSince(a.last_active));

  const today = "2026-04-16";

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Identity Lifecycle Management</h1>
          <p className="text-gray-400 text-sm mt-1">Account provisioning, entitlements, orphan detection, and audit trail</p>
        </div>

        {/* Fetch Error Banner */}
        {fetchError && (
          <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between mb-6">
            <span className="text-sm">Failed to load live data: {fetchError}</span>
            <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Total Accounts</p>
            <p className="text-3xl font-bold mt-1 text-blue-400">{totalAccounts}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Active</p>
            <p className="text-3xl font-bold mt-1 text-green-400">{activeAccounts}</p>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Orphan Accounts</p>
            <p className={`text-3xl font-bold mt-1 ${orphans > 0 ? "text-red-400" : "text-green-400"}`}>{orphans}</p>
            {orphans > 0 && <p className="text-xs text-red-400 mt-1">No activity &gt;90 days</p>}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">Total Entitlements</p>
            <p className="text-3xl font-bold mt-1 text-purple-400">{totalEntitlements}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(["accounts", "entitlements", "orphans", "events"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
              {t === "orphans" ? "Orphan Accounts" : t}
            </button>
          ))}
        </div>

        {/* Accounts */}
        {activeTab === "accounts" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <h2 className="font-semibold">Account Directory</h2>
              <button onClick={() => setShowAddAccount(!showAddAccount)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Account</button>
            </div>
            {showAddAccount && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Username" value={newAccount.username} onChange={e => setNewAccount({ ...newAccount, username: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Display name" value={newAccount.display_name} onChange={e => setNewAccount({ ...newAccount, display_name: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newAccount.account_type} onChange={e => setNewAccount({ ...newAccount, account_type: e.target.value })}>
                  <option value="employee">Employee</option><option value="contractor">Contractor</option><option value="service">Service</option><option value="vendor">Vendor</option>
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Department" value={newAccount.department} onChange={e => setNewAccount({ ...newAccount, department: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Manager username" value={newAccount.manager} onChange={e => setNewAccount({ ...newAccount, manager: e.target.value })} />
                <div className="flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddAccount(false)}>Save</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddAccount(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Username", "Display Name", "Type", "Department", "Manager", "Status", "Last Active", "Actions"].map(h => <th key={h} className="text-left px-4 py-2 whitespace-nowrap">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {accounts.map(a => {
                    const age = daysSince(a.last_active);
                    const isOrphan = a.status === "active" && age > 90;
                    return (
                      <tr key={a.id} className={`hover:bg-gray-750 ${isOrphan ? "bg-red-950/20" : ""}`}>
                        <td className="px-4 py-3 font-mono text-xs text-gray-300">{a.username}</td>
                        <td className="px-4 py-3 font-medium">{a.display_name}</td>
                        <td className="px-4 py-3">{typeBadge(a.account_type)}</td>
                        <td className="px-4 py-3 text-gray-400">{a.department}</td>
                        <td className="px-4 py-3 text-gray-400 text-xs font-mono">{a.manager || <span className="text-yellow-500">unassigned</span>}</td>
                        <td className="px-4 py-3">{statusBadge(a.status)}</td>
                        <td className="px-4 py-3">
                          <span className={isOrphan ? "text-red-400 font-medium" : "text-gray-400"}>
                            {a.last_active} {isOrphan && `(${age}d)`}
                          </span>
                          {isOrphan && <span className="ml-1 text-red-400 text-xs">⚠ Orphan</span>}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            {a.status === "active" && <button className="bg-yellow-700 hover:bg-yellow-600 text-white text-xs px-2 py-1 rounded">Suspend</button>}
                            {a.status === "suspended" && <button className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Reactivate</button>}
                            {a.status !== "deprovisioned" && <button className="bg-red-700 hover:bg-red-600 text-white text-xs px-2 py-1 rounded">Deprovision</button>}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Entitlements */}
        {activeTab === "entitlements" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <h2 className="font-semibold">Access Entitlements</h2>
                <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterAccount} onChange={e => setFilterAccount(e.target.value)}>
                  <option value="all">All Accounts</option>
                  {accounts.map(a => <option key={a.id} value={a.id}>{a.display_name}</option>)}
                </select>
              </div>
              <button onClick={() => setShowGrantAccess(!showGrantAccess)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Grant Access</button>
            </div>
            {showGrantAccess && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newEntitlement.account_id} onChange={e => setNewEntitlement({ ...newEntitlement, account_id: e.target.value })}>
                  {accounts.map(a => <option key={a.id} value={a.id}>{a.display_name}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="System name" value={newEntitlement.system_name} onChange={e => setNewEntitlement({ ...newEntitlement, system_name: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Role" value={newEntitlement.role} onChange={e => setNewEntitlement({ ...newEntitlement, role: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newEntitlement.access_level} onChange={e => setNewEntitlement({ ...newEntitlement, access_level: e.target.value })}>
                  <option value="read">Read</option><option value="write">Write</option><option value="admin">Admin</option>
                </select>
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowGrantAccess(false)}>Grant</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowGrantAccess(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Account", "System", "Role", "Access Level", "Granted By", "Expires", "Status", "Action"].map(h => <th key={h} className="text-left px-4 py-2 whitespace-nowrap">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredEntitlements.map(e => {
                    const acc = accounts.find(a => a.id === e.account_id);
                    const expiring = e.expires_at && e.expires_at <= today;
                    return (
                      <tr key={e.id} className="hover:bg-gray-750">
                        <td className="px-4 py-3 text-gray-300 text-xs font-mono">{acc?.username}</td>
                        <td className="px-4 py-3"><span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{e.system_name}</span></td>
                        <td className="px-4 py-3 text-gray-300">{e.role}</td>
                        <td className="px-4 py-3">{accessBadge(e.access_level)}</td>
                        <td className="px-4 py-3 text-gray-400 text-xs">{e.granted_by}</td>
                        <td className="px-4 py-3">
                          {e.expires_at
                            ? <span className={expiring ? "text-red-400 font-medium" : "text-gray-400"}>{e.expires_at}{expiring ? " ⚠" : ""}</span>
                            : <span className="text-gray-500">Never</span>}
                        </td>
                        <td className="px-4 py-3">{statusBadge(e.status)}</td>
                        <td className="px-4 py-3"><button className="bg-red-800 hover:bg-red-700 text-white text-xs px-2 py-1 rounded">Revoke</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Orphans */}
        {activeTab === "orphans" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h2 className="font-semibold text-red-400">Orphan Accounts — Active with no activity &gt;90 days</h2>
            </div>
            {orphanAccounts.length === 0 ? (
              <div className="p-8 text-center text-green-400">No orphan accounts detected.</div>
            ) : (
              <div className="divide-y divide-gray-700">
                {orphanAccounts.map(a => (
                  <div key={a.id} className="p-4 flex items-center gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-sm text-gray-300">{a.username}</span>
                        {typeBadge(a.account_type)}
                        <span className="bg-red-700 text-white text-xs px-2 py-0.5 rounded">{daysSince(a.last_active)}d inactive</span>
                      </div>
                      <p className="text-gray-400 text-xs">{a.display_name} — {a.department} — Manager: {a.manager || "unassigned"}</p>
                      <p className="text-gray-500 text-xs">Last active: {a.last_active}</p>
                    </div>
                    <div className="flex gap-2">
                      <button className="bg-yellow-700 hover:bg-yellow-600 text-white text-xs px-2 py-1 rounded">Suspend</button>
                      <button className="bg-red-700 hover:bg-red-600 text-white text-xs px-2 py-1 rounded">Deprovision</button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Events */}
        {activeTab === "events" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 p-4 border-b border-gray-700">
              <h2 className="font-semibold">Audit Trail</h2>
              <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterAccount} onChange={e => setFilterAccount(e.target.value)}>
                <option value="all">All Accounts</option>
                {accounts.map(a => <option key={a.id} value={a.id}>{a.display_name}</option>)}
              </select>
            </div>
            <div className="divide-y divide-gray-700">
              {filteredEvents.map(ev => {
                const acc = accounts.find(a => a.id === ev.account_id);

                if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                return (
                  <div key={ev.id} className="p-4 flex items-center gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        {eventBadge(ev.event_type)}
                        <span className="font-mono text-xs text-gray-300">{acc?.username}</span>
                      </div>
                      <p className="text-xs text-gray-400">Performed by: {ev.performed_by} — {ev.event_time}</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
