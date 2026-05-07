/**
 * WebhooksOutboundPage
 * Route:  /admin/webhooks-out
 * API:    GET    /api/v1/webhooks/outbound          — list subscriptions
 *         POST   /api/v1/webhooks/outbound          — create subscription
 *         POST   /api/v1/webhooks/outbound/:id/test — send test payload
 *         DELETE /api/v1/webhooks/outbound/:id      — revoke subscription
 *
 * Multica #4155
 */

import { useState, useEffect, useCallback } from "react";
import {
  Webhook,
  Plus,
  Trash2,
  FlaskConical,
  RefreshCw,
  X,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
} from "lucide-react";
import api from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

// ── Constants ──────────────────────────────────────────────────────────────────

const TOPICS = [
  { value: "finding.created.critical", label: "finding.created.critical" },
  { value: "incident.opened",          label: "incident.opened"          },
  { value: "council.escalated",        label: "council.escalated"        },
] as const;

type Topic = (typeof TOPICS)[number]["value"];

// ── Types ──────────────────────────────────────────────────────────────────────

interface Subscription {
  id: string;
  url: string;
  topics: Topic[];
  is_active: boolean;
  created_at: string;
  last_triggered_at: string | null;
  failure_count: number;
}

interface CreateForm {
  url: string;
  topics: Topic[];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(raw: string | null): string {
  if (!raw) return "—";
  try {
    return new Date(raw).toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch {
    return raw;
  }
}

function normalise(raw: Record<string, unknown>): Subscription {
  return {
    id:                String(raw.id ?? ""),
    url:               String(raw.url ?? ""),
    topics:            Array.isArray(raw.topics) ? (raw.topics as Topic[]) : [],
    is_active:         raw.is_active !== false,
    created_at:        String(raw.created_at ?? ""),
    last_triggered_at: raw.last_triggered_at ? String(raw.last_triggered_at) : null,
    failure_count:     Number(raw.failure_count ?? 0),
  };
}

function extractList(raw: unknown): Record<string, unknown>[] {
  if (Array.isArray(raw)) return raw as Record<string, unknown>[];
  if (raw && typeof raw === "object") {
    const r = raw as Record<string, unknown>;
    for (const key of ["items", "subscriptions", "data", "results"]) {
      if (Array.isArray(r[key])) return r[key] as Record<string, unknown>[];
    }
  }
  return [];
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatusBadge({ active }: { active: boolean }) {
  return active ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
      <CheckCircle2 className="w-3 h-3" />
      Active
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-slate-600/40 text-slate-400 border border-slate-600/40">
      <XCircle className="w-3 h-3" />
      Inactive
    </span>
  );
}

function TopicPill({ topic }: { topic: string }) {
  const color =
    topic === "finding.created.critical"
      ? "bg-red-500/15 text-red-400 border-red-500/30"
      : topic === "incident.opened"
      ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
      : "bg-indigo-500/15 text-indigo-400 border-indigo-500/30";
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium border ${color} mr-1 mb-0.5`}>
      {topic}
    </span>
  );
}

function TableSkeleton() {
  return (
    <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700 animate-pulse">
      <div className="px-5 py-3.5 border-b border-slate-700">
        <div className="h-4 w-40 bg-slate-700 rounded" />
      </div>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-3.5 border-b border-slate-700/50">
          <div className="h-3 w-56 bg-slate-700 rounded" />
          <div className="h-3 w-40 bg-slate-700 rounded" />
          <div className="h-3 w-16 bg-slate-700 rounded" />
          <div className="h-3 w-32 bg-slate-700 rounded" />
          <div className="h-3 w-20 bg-slate-700 rounded" />
        </div>
      ))}
    </div>
  );
}

// ── Test button ───────────────────────────────────────────────────────────────

function TestButton({ subId }: { subId: string }) {
  const [state, setState] = useState<"idle" | "sending" | "ok" | "err">("idle");

  const fire = async () => {
    setState("sending");
    try {
      await api.post(`/api/v1/webhooks/outbound/${encodeURIComponent(subId)}/test`);
      setState("ok");
    } catch {
      setState("err");
    } finally {
      setTimeout(() => setState("idle"), 3000);
    }
  };

  const cls =
    state === "ok"  ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" :
    state === "err" ? "text-red-400 bg-red-500/10 border-red-500/30" :
                      "text-slate-300 bg-slate-700/50 hover:bg-slate-600/50 border-slate-600/40";

  return (
    <button
      onClick={fire}
      disabled={state === "sending"}
      aria-label="Send test payload"
      className={`inline-flex items-center gap-1 px-2 py-1 text-[10px] font-medium rounded border transition-colors disabled:opacity-50 ${cls}`}
    >
      {state === "sending" ? (
        <Loader2 className="w-3 h-3 animate-spin" />
      ) : (
        <FlaskConical className="w-3 h-3" />
      )}
      {state === "ok" ? "Sent" : state === "err" ? "Failed" : "Test"}
    </button>
  );
}

// ── Revoke button ─────────────────────────────────────────────────────────────

interface RevokeButtonProps {
  subId: string;
  onRevoked: (id: string) => void;
}

function RevokeButton({ subId, onRevoked }: RevokeButtonProps) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const doRevoke = async () => {
    setBusy(true);
    try {
      await api.delete(`/api/v1/webhooks/outbound/${encodeURIComponent(subId)}`);
      onRevoked(subId);
    } catch {
      setBusy(false);
      setConfirming(false);
    }
  };

  if (confirming) {
    return (
      <div className="flex items-center gap-1">
        <button
          onClick={doRevoke}
          disabled={busy}
          className="px-2 py-1 text-[10px] font-semibold bg-red-600 hover:bg-red-500 text-white rounded transition-colors disabled:opacity-50"
        >
          {busy ? "…" : "Confirm"}
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
      aria-label="Revoke subscription"
      className="inline-flex items-center gap-1 px-2 py-1 text-[10px] text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded transition-colors"
    >
      <Trash2 className="w-3 h-3" />
      Revoke
    </button>
  );
}

// ── Create dialog ─────────────────────────────────────────────────────────────

interface CreateDialogProps {
  onClose: () => void;
  onCreated: (sub: Subscription) => void;
}

function CreateDialog({ onClose, onCreated }: CreateDialogProps) {
  const [form, setForm] = useState<CreateForm>({ url: "", topics: [] });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleTopic = (t: Topic) => {
    setForm((f) => ({
      ...f,
      topics: f.topics.includes(t) ? f.topics.filter((x) => x !== t) : [...f.topics, t],
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.url.trim()) { setError("URL is required."); return; }
    try { new URL(form.url.trim()); } catch { setError("URL must be a valid HTTPS URL."); return; }
    if (form.topics.length === 0) { setError("Select at least one topic."); return; }
    setSaving(true);
    setError(null);
    try {
      const res = await api.post("/api/v1/webhooks/outbound", {
        url: form.url.trim(),
        topics: form.topics,
      });
      onCreated(normalise(res.data as Record<string, unknown>));
      onClose();
    } catch (err) {
      setError((err as Error).message ?? "Failed to create subscription.");
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
            <Webhook className="w-5 h-5 text-indigo-400" />
            New Outbound Webhook
          </h2>
          <button
            onClick={onClose}
            aria-label="Close dialog"
            className="p-1 hover:bg-slate-700 rounded-lg transition-colors text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-300 text-xs">
              {error}
            </div>
          )}

          {/* URL */}
          <div className="space-y-1">
            <label className="block text-xs font-medium text-slate-300">
              Endpoint URL <span className="text-red-400">*</span>
            </label>
            <input
              type="url"
              value={form.url}
              onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
              placeholder="https://hooks.example.com/aldeci"
              className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
              autoFocus
            />
          </div>

          {/* Topics multi-select */}
          <div className="space-y-2">
            <label className="block text-xs font-medium text-slate-300">
              Topics <span className="text-red-400">*</span>
            </label>
            <div className="space-y-2">
              {TOPICS.map((t) => {
                const checked = form.topics.includes(t.value);
                return (
                  <label
                    key={t.value}
                    className={`flex items-center gap-3 px-3 py-2 rounded-lg border cursor-pointer transition-colors select-none ${
                      checked
                        ? "bg-indigo-500/10 border-indigo-500/40 text-indigo-300"
                        : "bg-slate-800 border-slate-700 text-slate-300 hover:border-slate-600"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleTopic(t.value)}
                      className="w-3.5 h-3.5 accent-indigo-500"
                    />
                    <span className="text-xs font-mono">{t.label}</span>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Actions */}
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
              {saving ? "Creating…" : "Create Subscription"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function WebhooksOutboundPage() {
  const [subs, setSubs]       = useState<Subscription[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get("/api/v1/webhooks/outbound");
      setSubs(extractList(res.data).map(normalise));
    } catch (e) {
      setError((e as Error).message ?? "Failed to load subscriptions");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreated = (sub: Subscription) => setSubs((p) => [sub, ...p]);
  const handleRevoked = (id: string) => setSubs((p) => p.filter((s) => s.id !== id));

  const activeCount = subs.filter((s) => s.is_active).length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-5">
      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Webhook className="w-6 h-6 text-indigo-400" />
            Outbound Webhooks
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Push real-time events to external endpoints — GET /api/v1/webhooks/outbound
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={load}
            disabled={loading}
            aria-label="Refresh subscriptions"
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
            Add Subscription
          </button>
        </div>
      </div>

      {/* ── Stats strip ── */}
      {!loading && !error && (
        <div className="flex flex-wrap gap-3">
          <div className="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span className="text-slate-400">Active</span>
            <span className="font-semibold text-white">{activeCount}</span>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm">
            <span className="text-slate-400">Total</span>
            <span className="font-semibold text-white">{subs.length}</span>
          </div>
          {subs.some((s) => s.failure_count > 0) && (
            <div className="flex items-center gap-2 px-4 py-2 bg-amber-500/10 border border-amber-500/30 rounded-lg text-sm text-amber-300">
              <Clock className="w-4 h-4" />
              {subs.filter((s) => s.failure_count > 0).length} endpoint(s) with delivery failures
            </div>
          )}
        </div>
      )}

      {/* ── Content ── */}
      {loading ? (
        <TableSkeleton />
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : subs.length === 0 ? (
        <EmptyState
          icon={Webhook}
          title="No outbound webhooks"
          description="Create a subscription to push critical findings, incidents and AI escalations to your endpoints."
        />
      ) : (
        <div className="bg-slate-800 rounded-lg overflow-hidden border border-slate-700">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-800/80">
                  {["Endpoint URL", "Topics", "Status", "Created", "Last Triggered", "Failures", "", ""].map((h, i) => (
                    <th
                      key={i}
                      className="px-4 py-3 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {subs.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-700/30 transition-colors">
                    <td className="px-4 py-2.5 max-w-[240px]">
                      <span
                        className="block truncate text-xs font-mono text-slate-200"
                        title={s.url}
                      >
                        {s.url}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 min-w-[220px]">
                      <div className="flex flex-wrap">
                        {s.topics.map((t) => (
                          <TopicPill key={t} topic={t} />
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusBadge active={s.is_active} />
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-slate-400 font-mono whitespace-nowrap">
                      {fmtDate(s.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-slate-400 font-mono whitespace-nowrap">
                      {fmtDate(s.last_triggered_at)}
                    </td>
                    <td className="px-4 py-2.5 text-[11px] font-mono">
                      {s.failure_count > 0 ? (
                        <span className="text-amber-400">{s.failure_count}</span>
                      ) : (
                        <span className="text-slate-600">0</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <TestButton subId={s.id} />
                    </td>
                    <td className="px-4 py-2.5">
                      <RevokeButton subId={s.id} onRevoked={handleRevoked} />
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
          onCreated={handleCreated}
        />
      )}
    </div>
  );
}
