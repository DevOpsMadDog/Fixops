/**
 * AdminUsersPage
 * Route: /admin/users
 * API:   GET/POST/PUT/DELETE /api/v1/orgs/{org_id}/users[/{uid}]
 *
 * Features:
 *  - User list with role badge + last_login + status
 *  - Invite user form (email + role dropdown)
 *  - Role change dropdown per row
 *  - Remove button per row with confirmation
 */

import { useState, useEffect, useCallback } from "react";
import {
  Users,
  UserPlus,
  Trash2,
  RefreshCw,
  ShieldCheck,
  Eye,
  Code2,
  Shield,
  Download,
} from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

type OrgUser = {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: string;
  status: string;
  last_login: string | null;
  created_at: string;
};

type ApiResponse = {
  org_id: string;
  items: OrgUser[];
  total: number;
};

// ── Constants ─────────────────────────────────────────────────────────────────

const ORG_ID = "default";
const BASE = "/api/v1/orgs";

const ROLES = [
  { value: "admin", label: "Admin", icon: ShieldCheck, color: "text-red-400 bg-red-900/30" },
  { value: "security_analyst", label: "Analyst", icon: Shield, color: "text-amber-400 bg-amber-900/30" },
  { value: "developer", label: "Developer", icon: Code2, color: "text-blue-400 bg-blue-900/30" },
  { value: "viewer", label: "Viewer", icon: Eye, color: "text-slate-400 bg-slate-700/50" },
];

function roleMeta(role: string) {
  return ROLES.find((r) => r.value === role) ?? ROLES[3];
}

function RoleBadge({ role }: { role: string }) {
  const meta = roleMeta(role);
  const Icon = meta.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${meta.color}`}>
      <Icon className="w-3 h-3" />
      {meta.label}
    </span>
  );
}

function formatDate(iso: string | null) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function fetchOrgUsers(orgId: string): Promise<ApiResponse> {
  const r = await fetch(`${BASE}/${orgId}/users`);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

async function inviteUser(
  orgId: string,
  email: string,
  role: string,
  firstName: string,
  lastName: string
): Promise<OrgUser> {
  const r = await fetch(`${BASE}/${orgId}/users`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, role, first_name: firstName, last_name: lastName }),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(err.detail ?? r.statusText);
  }
  return r.json();
}

async function updateRole(orgId: string, uid: string, role: string): Promise<OrgUser> {
  const r = await fetch(`${BASE}/${orgId}/users/${uid}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(err.detail ?? r.statusText);
  }
  return r.json();
}

async function removeUser(orgId: string, uid: string): Promise<void> {
  const r = await fetch(`${BASE}/${orgId}/users/${uid}`, { method: "DELETE" });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText }));
    throw new Error(err.detail ?? r.statusText);
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────

type Toast = { id: number; msg: string; kind: "ok" | "err" };

function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const add = useCallback((msg: string, kind: "ok" | "err") => {
    const id = Date.now();
    setToasts((t) => [...t, { id, msg, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4000);
  }, []);
  return { toasts, add };
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AdminUsersPage() {
  const [users, setUsers] = useState<OrgUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { toasts, add: toast } = useToast();

  // Invite form state
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteFirst, setInviteFirst] = useState("");
  const [inviteLast, setInviteLast] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");
  const [inviting, setInviting] = useState(false);

  // Per-row role update in progress
  const [updatingRole, setUpdatingRole] = useState<string | null>(null);
  const [removingId, setRemovingId] = useState<string | null>(null);

  // Export state
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchOrgUsers(ORG_ID);
      setUsers(data.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load users");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setInviting(true);
    try {
      const u = await inviteUser(ORG_ID, inviteEmail.trim(), inviteRole, inviteFirst || "Invited", inviteLast || "User");
      setUsers((prev) => [u, ...prev]);
      setInviteEmail("");
      setInviteFirst("");
      setInviteLast("");
      setInviteRole("viewer");
      setShowInvite(false);
      toast("User invited successfully", "ok");
    } catch (e) {
      toast(e instanceof Error ? e.message : "Invite failed", "err");
    } finally {
      setInviting(false);
    }
  };

  const handleRoleChange = async (uid: string, role: string) => {
    setUpdatingRole(uid);
    try {
      const updated = await updateRole(ORG_ID, uid, role);
      setUsers((prev) => prev.map((u) => (u.id === uid ? { ...u, role: updated.role } : u)));
      toast("Role updated", "ok");
    } catch (e) {
      toast(e instanceof Error ? e.message : "Role update failed", "err");
    } finally {
      setUpdatingRole(null);
    }
  };

  const handleRemove = async (uid: string, email: string) => {
    if (!window.confirm(`Remove ${email} from this org?`)) return;
    setRemovingId(uid);
    try {
      await removeUser(ORG_ID, uid);
      setUsers((prev) => prev.filter((u) => u.id !== uid));
      toast("User removed", "ok");
    } catch (e) {
      toast(e instanceof Error ? e.message : "Remove failed", "err");
    } finally {
      setRemovingId(null);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      toast("Generating ZIP...", "ok");
      const r = await fetch(`/api/v1/orgs/${ORG_ID}/export`, { method: "POST" });
      if (!r.ok) {
        const err = await r.json().catch(() => ({ detail: r.statusText }));
        throw new Error(err.detail ?? r.statusText);
      }
      const data = await r.json();
      window.location.href = data.download_url;
      toast("Export started", "ok");
    } catch (e) {
      toast(e instanceof Error ? e.message : "Export failed", "err");
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-50 p-6">
      {/* Toast stack */}
      <div className="fixed top-4 right-4 z-50 flex flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`px-4 py-2 rounded shadow-lg text-sm font-medium transition-all ${
              t.kind === "ok" ? "bg-green-600 text-white" : "bg-red-600 text-white"
            }`}
          >
            {t.msg}
          </div>
        ))}
      </div>

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-indigo-600/20">
            <Users className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">Org Users</h1>
            <p className="text-sm text-slate-400">
              Manage team members, roles, and access for this organisation.
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-700 hover:bg-slate-600 text-sm transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-700 hover:bg-slate-600 text-sm transition-colors disabled:opacity-50"
            title="Export org data as ZIP (GDPR)"
          >
            <Download className="w-3.5 h-3.5" />
            Export Data
          </button>
          <button
            onClick={() => setShowInvite((v) => !v)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500 text-sm font-medium transition-colors"
          >
            <UserPlus className="w-3.5 h-3.5" />
            Invite User
          </button>
        </div>
      </div>

      {/* Invite form */}
      {showInvite && (
        <form
          onSubmit={handleInvite}
          className="mb-6 p-4 rounded-xl bg-slate-800 border border-slate-700 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3"
        >
          <input
            type="email"
            required
            placeholder="Email address *"
            value={inviteEmail}
            onChange={(e) => setInviteEmail(e.target.value)}
            className="col-span-1 lg:col-span-2 px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <input
            type="text"
            placeholder="First name"
            value={inviteFirst}
            onChange={(e) => setInviteFirst(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <input
            type="text"
            placeholder="Last name"
            value={inviteLast}
            onChange={(e) => setInviteLast(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-sm placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <div className="flex gap-2">
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value)}
              className="flex-1 px-3 py-2 rounded-lg bg-slate-700 border border-slate-600 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              {ROLES.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
            <button
              type="submit"
              disabled={inviting}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-sm font-medium disabled:opacity-50 transition-colors"
            >
              {inviting ? "Inviting…" : "Send"}
            </button>
          </div>
        </form>
      )}

      {/* Error state */}
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* Table */}
      <div className="rounded-xl border border-slate-700 overflow-hidden bg-slate-800">
        {loading ? (
          <div className="space-y-0">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-14 bg-slate-800 border-b border-slate-700 animate-pulse" />
            ))}
          </div>
        ) : users.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-400">
            <Users className="w-10 h-10 mb-3 opacity-30" />
            <p className="text-sm">No users in this org yet.</p>
            <button
              onClick={() => setShowInvite(true)}
              className="mt-3 text-indigo-400 text-sm hover:underline"
            >
              Invite the first user
            </button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700 text-slate-400 text-xs uppercase tracking-wide">
              <tr>
                <th className="px-4 py-3 text-left">User</th>
                <th className="px-4 py-3 text-left">Role</th>
                <th className="px-4 py-3 text-left hidden md:table-cell">Status</th>
                <th className="px-4 py-3 text-left hidden lg:table-cell">Last Login</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-slate-700/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium text-slate-100">{u.first_name} {u.last_name}</div>
                    <div className="text-xs text-slate-400">{u.email}</div>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={u.role}
                      disabled={updatingRole === u.id}
                      onChange={(e) => handleRoleChange(u.id, e.target.value)}
                      className="bg-transparent border-none cursor-pointer focus:outline-none"
                      aria-label={`Change role for ${u.email}`}
                    >
                      {ROLES.map((r) => (
                        <option key={r.value} value={r.value} className="bg-slate-800">
                          {r.label}
                        </option>
                      ))}
                    </select>
                    <RoleBadge role={u.role} />
                  </td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                      u.status === "active"
                        ? "text-green-400 bg-green-900/30"
                        : "text-slate-400 bg-slate-700/50"
                    }`}>
                      {u.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell text-slate-400 text-xs">
                    {formatDate(u.last_login)}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => handleRemove(u.id, u.email)}
                      disabled={removingId === u.id}
                      aria-label={`Remove ${u.email}`}
                      className="p-1.5 rounded hover:bg-red-900/30 text-slate-400 hover:text-red-400 transition-colors disabled:opacity-50"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Footer count */}
      {!loading && users.length > 0 && (
        <p className="mt-3 text-xs text-slate-500">{users.length} user{users.length !== 1 ? "s" : ""} in org</p>
      )}
    </div>
  );
}
