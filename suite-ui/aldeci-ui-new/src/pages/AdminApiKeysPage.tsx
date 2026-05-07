/**
 * AdminApiKeysPage
 * Route: /admin/api-keys
 * API:   GET    /api/v1/auth/keys
 *        POST   /api/v1/auth/keys   (returns plaintext_key once)
 *        DELETE /api/v1/auth/keys/:id
 *
 * Features:
 *  - Table: name · prefix · role · created · last_used · expires · status · revoke
 *  - Create dialog: name, user_id, role, ttl_days — shows secret once with copy prompt
 *  - Revoke: confirmation inline, immediate optimistic removal
 *  - Skeleton loading, empty state, error state, dark mode
 */

import { useState, useEffect, useCallback } from "react";
import {
  KeyRound,
  Plus,
  Trash2,
  Copy,
  Check,
  RefreshCw,
  X,
  Eye,
  EyeOff,
  ShieldCheck,
  ShieldOff,
  Clock,
} from "lucide-react";
import { apiKeysApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ApiKey {
  id: string;
  key_prefix: string;
  name: string;
  user_id: string;
  role: string;
  scopes: string[];
  is_active: boolean;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
}

interface CreateForm {
  name: string;
  user_id: string;
  role: string;
  ttl_days: string;
}

const ROLES = ["viewer", "analyst", "developer", "admin", "super_admin"];

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(raw: string | null): string {
  if (!raw) return "—";
  try {
    return new Date(raw).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return raw;
  }
}

function normalise(raw: Record<string, unknown>): ApiKey {
  return {
    id: String(raw.id ?? ""),
    key_prefix: String(raw.key_prefix ?? raw.prefix ?? ""),
    name: String(raw.name ?? "Unnamed"),
    user_id: String(raw.user_id ?? ""),
    role: String(raw.role ?? "viewer"),
    scopes: Array.isArray(raw.scopes) ? (raw.scopes as string[]) : [],
    is_active: Boolean(raw.is_active ?? true),
    created_at: String(raw.created_at ?? ""),
    expires_at: raw.expires_at ? String(raw.expires_at) : null,
    last_used_at: raw.last_used_at ? String(raw.last_used_at) : null,
    revoked_at: raw.revoked_at ? String(raw.revoked_at) : null,
  };
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ active }: { active: boolean }) {
  return active ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
      <ShieldCheck className="w-3 h-3" />
      Active
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-500/15 text-red-400 border border-red-500/30">
      <ShieldOff className="w-3 h-3" />
      Revoked
    </span>
  );
}

function RoleBadge({ role }: { role: string }) {
  const colors: Record<string, string> = {
    super_admin: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    admin: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
    developer: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    analyst: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    viewer: "bg-slate-600/40 text-slate-300 border-slate-600/40",
  };
  const cls = colors[role] ?? colors.viewer;
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${cls}`}>
      {role}
    </span>
  );
}

function TableSkeleton() {
  return (
    <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700 animate-pulse">
      <div className="px-5 py-3.5 border-b border-slate-700">
        <div className="h-4 w-32 bg-slate-700 rounded" />
      </div>
      {Array.from({ length: 5 }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-3.5 border-b border-slate-700/50">
          <div className="h-3 w-28 bg-slate-700 rounded" />
          <div className="h-3 w-20 bg-slate-700 rounded" />
          <div className="h-3 w-16 bg-slate-700 rounded" />
          <div className="h-3 w-36 bg-slate-700 rounded" />
          <div className="h-3 w-36 bg-slate-700 rounded" />
          <div className="h-3 w-24 bg-slate-700 rounded" />
          <div className="h-3 w-14 bg-slate-700 rounded" />
        </div>
      ))}
    </div>
  );
}

// ── Copy button ───────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handle = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <button
      onClick={handle}
      className="inline-flex items-center gap-1 px-2 py-1 bg-slate-700 hover:bg-slate-600 rounded text-xs transition-colors"
    >
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// ── Create dialog ─────────────────────────────────────────────────────────────

interface CreateDialogProps {
  onClose: () => void;
  onCreated: (key: ApiKey) => void;
}

function CreateDialog({ onClose, onCreated }: CreateDialogProps) {
  const [form, setForm] = useState<CreateForm>({
    name: "",
    user_id: "",
    role: "viewer",
    ttl_days: "",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [showSecret, setShowSecret] = useState(true);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim() || !form.user_id.trim()) {
      setError("Name and User ID are required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const res = await apiKeysApi.create({
        name: form.name.trim(),
        user_id: form.user_id.trim(),
        role: form.role,
        scopes: [],
        ttl_days: form.ttl_days ? parseInt(form.ttl_days, 10) : null,
      });
      const data = res.data as Record<string, unknown>;
      const plaintext = String(data.plaintext_key ?? "");
      setSecret(plaintext);
      onCreated(normalise(data));
    } catch (err) {
      setError((err as Error).message ?? "Failed to create key");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-6 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <KeyRound className="w-5 h-5 text-indigo-400" />
            {secret ? "Key created" : "Create API Key"}
          </h2>
          <button
            onClick={onClose}
            className="p-1 hover:bg-slate-700 rounded-lg transition-colors text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {secret ? (
          /* ── Secret reveal panel ── */
          <div className="space-y-4">
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-amber-300 text-xs">
              This key is shown <strong>once</strong>. Copy it now — it cannot be retrieved later.
            </div>
            <div className="bg-slate-800 rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">Secret key</span>
                <button
                  onClick={() => setShowSecret((v) => !v)}
                  className="text-slate-400 hover:text-white transition-colors"
                >
                  {showSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <div className="font-mono text-sm text-emerald-300 break-all">
                {showSecret ? secret : "•".repeat(Math.min(secret.length, 48))}
              </div>
              <CopyButton text={secret} />
            </div>
            <button
              onClick={onClose}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition-colors"
            >
              Done
            </button>
          </div>
        ) : (
          /* ── Create form ── */
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-300 text-xs">
                {error}
              </div>
            )}

            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-300">Key name *</label>
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="e.g. ci-pipeline-prod"
                className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              />
            </div>

            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-300">User ID *</label>
              <input
                type="text"
                value={form.user_id}
                onChange={(e) => setForm((f) => ({ ...f, user_id: e.target.value }))}
                placeholder="UUID of the owning user"
                className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">Role</label>
                <select
                  value={form.role}
                  onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>{r}</option>
                  ))}
                </select>
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-medium text-slate-300">TTL (days)</label>
                <input
                  type="number"
                  min={1}
                  max={3650}
                  value={form.ttl_days}
                  onChange={(e) => setForm((f) => ({ ...f, ttl_days: e.target.value }))}
                  placeholder="No expiry"
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                />
              </div>
            </div>

            <div className="flex gap-3 pt-1">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg text-sm font-medium transition-colors"
              >
                {saving ? "Creating…" : "Create Key"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ── Revoke confirm cell ───────────────────────────────────────────────────────

interface RevokeCellProps {
  keyId: string;
  isActive: boolean;
  onRevoked: (keyId: string) => void;
}

function RevokeCell({ keyId, isActive, onRevoked }: RevokeCellProps) {
  const [confirming, setConfirming] = useState(false);
  const [revoking, setRevoking] = useState(false);

  if (!isActive) return <span className="text-slate-600 text-xs">—</span>;

  const doRevoke = async () => {
    setRevoking(true);
    try {
      await apiKeysApi.revoke(keyId);
      onRevoked(keyId);
    } catch {
      setRevoking(false);
      setConfirming(false);
    }
  };

  if (confirming) {
    return (
      <div className="flex items-center gap-1">
        <button
          onClick={doRevoke}
          disabled={revoking}
          className="px-2 py-1 text-[10px] font-semibold bg-red-600 hover:bg-red-500 text-white rounded transition-colors disabled:opacity-50"
        >
          {revoking ? "…" : "Confirm"}
        </button>
        <button
          onClick={() => setConfirming(false)}
          className="px-2 py-1 text-[10px] bg-slate-700 hover:bg-slate-600 text-slate-300 rounded transition-colors"
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      className="inline-flex items-center gap-1 px-2 py-1 text-[10px] text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
    >
      <Trash2 className="w-3 h-3" />
      Revoke
    </button>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function AdminApiKeysPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [includeRevoked, setIncludeRevoked] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiKeysApi.list({ include_revoked: includeRevoked });
      const raw = res.data;
      const list: Record<string, unknown>[] = Array.isArray(raw)
        ? (raw as Record<string, unknown>[])
        : ((raw as Record<string, unknown>)?.keys ??
           (raw as Record<string, unknown>)?.items ??
           (raw as Record<string, unknown>)?.data ??
           []) as Record<string, unknown>[];
      setKeys(list.map(normalise));
    } catch (e) {
      setError((e as Error).message ?? "Failed to load API keys");
    } finally {
      setLoading(false);
    }
  }, [includeRevoked]);

  useEffect(() => { load(); }, [load]);

  const handleCreated = (newKey: ApiKey) => {
    setKeys((prev) => [newKey, ...prev]);
  };

  const handleRevoked = (keyId: string) => {
    setKeys((prev) =>
      prev.map((k) =>
        k.id === keyId ? { ...k, is_active: false, revoked_at: new Date().toISOString() } : k
      )
    );
  };

  const activeCount = keys.filter((k) => k.is_active).length;
  const expiringCount = keys.filter((k) => {
    if (!k.expires_at || !k.is_active) return false;
    const diff = new Date(k.expires_at).getTime() - Date.now();
    return diff > 0 && diff < 7 * 24 * 60 * 60 * 1000;
  }).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-5">
      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <KeyRound className="w-6 h-6 text-indigo-400" />
            API Keys
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Managed API keys — GET /api/v1/auth/keys
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 rounded-lg text-sm transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            Create Key
          </button>
        </div>
      </div>

      {/* ── Stats strip ── */}
      {!loading && !error && (
        <div className="flex flex-wrap gap-3">
          <div className="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-400">Active</span>
            <span className="font-semibold text-white">{activeCount}</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm">
            <span className="text-slate-400">Total</span>
            <span className="font-semibold text-white">{keys.length}</span>
          </div>
          {expiringCount > 0 && (
            <div className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 border border-amber-500/30 rounded-lg text-sm text-amber-300">
              <Clock className="w-4 h-4" />
              {expiringCount} expiring within 7 days
            </div>
          )}
          {/* Include revoked toggle */}
          <label className="flex items-center gap-2 px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm cursor-pointer select-none ml-auto">
            <input
              type="checkbox"
              checked={includeRevoked}
              onChange={(e) => setIncludeRevoked(e.target.checked)}
              className="w-3.5 h-3.5 accent-indigo-500"
            />
            <span className="text-slate-300">Show revoked</span>
          </label>
        </div>
      )}

      {/* ── Content ── */}
      {loading ? (
        <TableSkeleton />
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : keys.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No API keys"
          description="Create your first API key to allow programmatic access to the platform."
        />
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/80">
                  {["Name", "Prefix", "Role", "Created", "Last Used", "Expires", "Status", ""].map((h) => (
                    <th
                      key={h}
                      className="px-4 py-3 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {keys.map((k) => (
                  <tr
                    key={k.id}
                    className={`hover:bg-slate-700/30 transition-colors ${!k.is_active ? "opacity-50" : ""}`}
                  >
                    <td className="px-4 py-2.5 text-xs font-medium text-slate-200 max-w-[160px] truncate">
                      {k.name}
                    </td>
                    <td className="px-4 py-2.5">
                      <code className="text-[11px] font-mono text-slate-300 bg-slate-700/50 px-1.5 py-0.5 rounded">
                        {k.key_prefix}…
                      </code>
                    </td>
                    <td className="px-4 py-2.5">
                      <RoleBadge role={k.role} />
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-slate-400 font-mono whitespace-nowrap">
                      {fmtDate(k.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-slate-400 font-mono whitespace-nowrap">
                      {fmtDate(k.last_used_at)}
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-slate-400 font-mono whitespace-nowrap">
                      {k.expires_at ? fmtDate(k.expires_at) : <span className="text-slate-600">No expiry</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge active={k.is_active} />
                    </td>
                    <td className="px-4 py-2.5">
                      <RevokeCell keyId={k.id} isActive={k.is_active} onRevoked={handleRevoked} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Create dialog ── */}
      {showCreate && (
        <CreateDialog
          onClose={() => setShowCreate(false)}
          onCreated={(k) => {
            handleCreated(k);
          }}
        />
      )}
    </div>
  );
}
