import { useState, useEffect, useCallback } from "react";
import { getStoredOrgId } from "@/lib/api";
const _API_BASE = "/api/v1/identity-lifecycle";
const _getHeaders = () => ({
  "X-API-Key": localStorage.getItem("aldeci.authToken") || "",
  "Content-Type": "application/json",
});

// NO-MOCKS (CLAUDE.md): accounts / entitlements / events / orphans below are
// all loaded from the live /api/v1/identity-lifecycle API on mount — there is
// no hardcoded fixture data and no frozen "today".

const typeBadge = (t: string) => {
  const map: Record<string, string> = { employee: "bg-blue-600", contractor: "bg-orange-600", service: "bg-purple-600", system: "bg-purple-700", bot: "bg-indigo-600", vendor: "bg-gray-600", temp: "bg-teal-700" };
  return <span className={`${map[t] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{t}</span>;
};
const statusBadge = (s: string) => {
  const map: Record<string, string> = { active: "bg-green-600", suspended: "bg-yellow-600", deprovisioned: "bg-red-600", revoked: "bg-red-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s}</span>;
};
const accessBadge = (a: string) => {
  const map: Record<string, string> = { read: "bg-blue-700", write: "bg-orange-700", admin: "bg-red-700", owner: "bg-red-800" };
  return <span className={`${map[a] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{a}</span>;
};
const eventBadge = (e: string) => {
  const map: Record<string, string> = { provisioned: "bg-green-700", suspended: "bg-yellow-700", deprovisioned: "bg-red-700", access_granted: "bg-blue-700", access_revoked: "bg-orange-700", reactivated: "bg-green-600" };
  return <span className={`${map[e] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{(e || "").replace("_", " ")}</span>;
};

function daysSince(dateStr: string): number {
  if (!dateStr) return 0;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return 0;
  return Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
}

const EmptyState = ({ title, hint }: { title: string; hint: string }) => (
  <div className="p-12 text-center">
    <p className="text-gray-300 font-medium">{title}</p>
    <p className="text-gray-500 text-sm mt-1">{hint}</p>
  </div>
);

const ORG_ID = (getStoredOrgId() ?? "default");
export default function IdentityLifecycleDashboard() {
  const [activeTab, setActiveTab] = useState<"accounts" | "entitlements" | "orphans" | "events">("accounts");
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [accounts, setAccounts] = useState<any[]>([]);
  const [entitlements, setEntitlements] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [orphans, setOrphans] = useState<any[]>([]);
  const [summary, setSummary] = useState<any | null>(null);

  const [filterAccount, setFilterAccount] = useState("all");
  const [showAddAccount, setShowAddAccount] = useState(false);
  const [showGrantAccess, setShowGrantAccess] = useState(false);
  const [newAccount, setNewAccount] = useState({ username: "", display_name: "", email: "", account_type: "employee", department: "", manager: "" });
  const [newEntitlement, setNewEntitlement] = useState({ account_id: "", system_name: "", role: "", access_level: "read", granted_by: "" });

  const loadData = useCallback(async () => {
    setFetchError(null);
    try {
      const [accRes, orphRes, sumRes] = await Promise.all([
        fetch(`${_API_BASE}/accounts?org_id=${ORG_ID}`, { headers: _getHeaders() }),
        fetch(`${_API_BASE}/orphans?org_id=${ORG_ID}`, { headers: _getHeaders() }),
        fetch(`${_API_BASE}/summary?org_id=${ORG_ID}`, { headers: _getHeaders() }),
      ]);
      const accList = accRes.ok ? await accRes.json() : [];
      setAccounts(Array.isArray(accList) ? accList : []);
      if (orphRes.ok) { const o = await orphRes.json(); setOrphans(Array.isArray(o) ? o : []); }
      if (sumRes.ok) setSummary(await sumRes.json());

      // Per-account detail carries active_entitlements + events; fan out + flatten.
      const details = await Promise.all(
        (Array.isArray(accList) ? accList : []).map((a: any) =>
          fetch(`${_API_BASE}/accounts/${a.id}?org_id=${ORG_ID}`, { headers: _getHeaders() })
            .then((d) => (d.ok ? d.json() : null))
            .catch(() => null)
        )
      );
      const allEnts: any[] = [];
      const allEvents: any[] = [];
      details.filter(Boolean).forEach((d: any) => {
        (d.active_entitlements || []).forEach((e: any) => allEnts.push({ ...e, account_id: e.account_id || d.id }));
        (d.events || []).forEach((ev: any) => allEvents.push({ ...ev, account_id: ev.account_id || d.id }));
      });
      allEvents.sort((a, b) => String(b.event_time || "").localeCompare(String(a.event_time || "")));
      setEntitlements(allEnts);
      setEvents(allEvents);
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : "Failed to load identity lifecycle data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const postAction = async (url: string, body?: any) => {
    try {
      const res = await fetch(url, { method: "POST", headers: _getHeaders(), body: body ? JSON.stringify(body) : JSON.stringify({}) });
      if (!res.ok) throw new Error(`Request failed (${res.status})`);
      await loadData();
      return true;
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : "Action failed");
      return false;
    }
  };

  const saveAccount = async () => {
    if (!newAccount.username) { setFetchError("Username is required"); return; }
    setSaving(true);
    const ok = await postAction(`${_API_BASE}/accounts?org_id=${ORG_ID}`, newAccount);
    if (ok) { setShowAddAccount(false); setNewAccount({ username: "", display_name: "", email: "", account_type: "employee", department: "", manager: "" }); }
    setSaving(false);
  };

  const grantAccess = async () => {
    if (!newEntitlement.account_id || !newEntitlement.system_name || !newEntitlement.role) { setFetchError("Select an account and provide system + role"); return; }
    setSaving(true);
    const { account_id, ...body } = newEntitlement;
    const ok = await postAction(`${_API_BASE}/accounts/${account_id}/access?org_id=${ORG_ID}`, body);
    if (ok) { setShowGrantAccess(false); setNewEntitlement({ account_id: "", system_name: "", role: "", access_level: "read", granted_by: "" }); }
    setSaving(false);
  };

  const totalAccounts = summary?.total_accounts ?? accounts.length;
  const activeAccounts = summary?.active_accounts ?? accounts.filter(a => a.status === "active").length;
  const orphanCount = summary?.orphan_count ?? orphans.length;
  const totalEntitlements = summary?.total_entitlements ?? entitlements.length;

  const filteredEntitlements = filterAccount === "all" ? entitlements : entitlements.filter(e => e.account_id === filterAccount);
  const filteredEvents = filterAccount === "all" ? events : events.filter(e => e.account_id === filterAccount);
  const orphanAccounts = (orphans.length ? orphans : accounts.filter(a => a.status === "active" && daysSince(a.last_active) > 90))
    .slice()
    .sort((a, b) => daysSince(b.last_active) - daysSince(a.last_active));

  const today = new Date().toISOString().slice(0, 10);

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

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
            <p className={`text-3xl font-bold mt-1 ${orphanCount > 0 ? "text-red-400" : "text-green-400"}`}>{orphanCount}</p>
            {orphanCount > 0 && <p className="text-xs text-red-400 mt-1">No activity &gt;90 days</p>}
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
                  <option value="employee">Employee</option><option value="contractor">Contractor</option><option value="service">Service</option><option value="system">System</option><option value="bot">Bot</option><option value="vendor">Vendor</option><option value="temp">Temp</option>
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Department" value={newAccount.department} onChange={e => setNewAccount({ ...newAccount, department: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Manager username" value={newAccount.manager} onChange={e => setNewAccount({ ...newAccount, manager: e.target.value })} />
                <div className="flex gap-2">
                  <button disabled={saving} className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded" onClick={saveAccount}>{saving ? "Saving…" : "Save"}</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddAccount(false)}>Cancel</button>
                </div>
              </div>
            )}
            {accounts.length === 0 ? (
              <EmptyState title="No accounts yet" hint="Provision your first identity account to begin tracking entitlements and the audit trail." />
            ) : (
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
                            {a.status === "active" && <button onClick={() => postAction(`${_API_BASE}/accounts/${a.id}/suspend?org_id=${ORG_ID}`)} className="bg-yellow-700 hover:bg-yellow-600 text-white text-xs px-2 py-1 rounded">Suspend</button>}
                            {a.status === "suspended" && <button onClick={() => postAction(`${_API_BASE}/accounts/${a.id}/reactivate?org_id=${ORG_ID}`)} className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Reactivate</button>}
                            {a.status !== "deprovisioned" && <button onClick={() => postAction(`${_API_BASE}/accounts/${a.id}/deprovision?org_id=${ORG_ID}`)} className="bg-red-700 hover:bg-red-600 text-white text-xs px-2 py-1 rounded">Deprovision</button>}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            )}
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
                  <option value="">Select account…</option>
                  {accounts.map(a => <option key={a.id} value={a.id}>{a.display_name}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="System name" value={newEntitlement.system_name} onChange={e => setNewEntitlement({ ...newEntitlement, system_name: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Role" value={newEntitlement.role} onChange={e => setNewEntitlement({ ...newEntitlement, role: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newEntitlement.access_level} onChange={e => setNewEntitlement({ ...newEntitlement, access_level: e.target.value })}>
                  <option value="read">Read</option><option value="write">Write</option><option value="admin">Admin</option><option value="owner">Owner</option>
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Granted by" value={newEntitlement.granted_by} onChange={e => setNewEntitlement({ ...newEntitlement, granted_by: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button disabled={saving} className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded" onClick={grantAccess}>{saving ? "Granting…" : "Grant"}</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowGrantAccess(false)}>Cancel</button>
                </div>
              </div>
            )}
            {filteredEntitlements.length === 0 ? (
              <EmptyState title="No entitlements" hint="Grant system access to an account and it will appear here." />
            ) : (
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
                        <td className="px-4 py-3 text-gray-300 text-xs font-mono">{acc?.username || e.account_id}</td>
                        <td className="px-4 py-3"><span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{e.system_name}</span></td>
                        <td className="px-4 py-3 text-gray-300">{e.role}</td>
                        <td className="px-4 py-3">{accessBadge(e.access_level)}</td>
                        <td className="px-4 py-3 text-gray-400 text-xs">{e.granted_by || "—"}</td>
                        <td className="px-4 py-3">
                          {e.expires_at
                            ? <span className={expiring ? "text-red-400 font-medium" : "text-gray-400"}>{e.expires_at}{expiring ? " ⚠" : ""}</span>
                            : <span className="text-gray-500">Never</span>}
                        </td>
                        <td className="px-4 py-3">{statusBadge(e.status)}</td>
                        <td className="px-4 py-3"><button onClick={() => postAction(`${_API_BASE}/entitlements/${e.id}/revoke?org_id=${ORG_ID}`)} className="bg-red-800 hover:bg-red-700 text-white text-xs px-2 py-1 rounded">Revoke</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            )}
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
                      <button onClick={() => postAction(`${_API_BASE}/accounts/${a.id}/suspend?org_id=${ORG_ID}`)} className="bg-yellow-700 hover:bg-yellow-600 text-white text-xs px-2 py-1 rounded">Suspend</button>
                      <button onClick={() => postAction(`${_API_BASE}/accounts/${a.id}/deprovision?org_id=${ORG_ID}`)} className="bg-red-700 hover:bg-red-600 text-white text-xs px-2 py-1 rounded">Deprovision</button>
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
            {filteredEvents.length === 0 ? (
              <EmptyState title="No audit events" hint="Provisioning, suspension, grant and revoke actions are recorded here." />
            ) : (
            <div className="divide-y divide-gray-700">
              {filteredEvents.map(ev => {
                const acc = accounts.find(a => a.id === ev.account_id);
                return (
                  <div key={ev.id} className="p-4 flex items-center gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        {eventBadge(ev.event_type)}
                        <span className="font-mono text-xs text-gray-300">{acc?.username || ev.account_id}</span>
                      </div>
                      <p className="text-xs text-gray-400">Performed by: {ev.performed_by || "system"} — {ev.event_time}</p>
                    </div>
                  </div>
                );
              })}
            </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
