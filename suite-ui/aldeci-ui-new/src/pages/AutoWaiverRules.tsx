/**
 * Auto Waiver Rules — Live API
 * Multica: 38f1a6bf-99b9-4272-87f0-0e8b77901827
 * API: GET/POST /api/v1/auto-waiver/rule(s) + DELETE /rule/{rule_key}
 *
 * Lists existing auto-waiver rules and lets the operator delete one or
 * publish a new one inline. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { Sparkles, Plus, Trash2, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiCall<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function AutoWaiverRules() {
  const [rules, setRules] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [newMatch, setNewMatch] = useState('{"severity":"low"}');
  const [newReason, setNewReason] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiCall<{ items?: Record<string, unknown>[] } | Record<string, unknown>[]>(
        "/api/v1/auto-waiver/rules",
      );
      setRules(Array.isArray(v) ? v : (v.items as Record<string, unknown>[]) ?? []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const create = async () => {
    setSubmitting(true);
    try {
      let parsedMatch: Record<string, unknown> = {};
      try {
        parsedMatch = JSON.parse(newMatch);
      } catch {
        throw new Error("match clause must be valid JSON");
      }
      await apiCall("/api/v1/auto-waiver/rule", {
        method: "POST",
        body: JSON.stringify({
          rule_key: newKey || `rule-${Date.now()}`,
          match: parsedMatch,
          reason: newReason,
        }),
      });
      setShowCreate(false);
      setNewKey("");
      setNewMatch('{"severity":"low"}');
      setNewReason("");
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const remove = async (key: string) => {
    if (!confirm(`Delete rule "${key}"?`)) return;
    try {
      await apiCall(`/api/v1/auto-waiver/rule/${encodeURIComponent(key)}`, { method: "DELETE" });
      await load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Sparkles className="w-6 h-6 text-indigo-400" /> Auto Waiver Rules
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/auto-waiver</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreate((v) => !v)}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-sm"
          >
            <Plus className="w-4 h-4" /> New rule
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      {showCreate && (
        <div className="bg-gray-800 rounded-lg p-4 space-y-3 max-w-3xl">
          <div className="grid md:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-gray-400 uppercase mb-1">Rule key</label>
              <input
                type="text"
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
                className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 uppercase mb-1">Reason</label>
              <input
                type="text"
                value={newReason}
                onChange={(e) => setNewReason(e.target.value)}
                className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 uppercase mb-1">
              Match clause (JSON)
            </label>
            <textarea
              value={newMatch}
              onChange={(e) => setNewMatch(e.target.value)}
              rows={3}
              className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-xs font-mono"
            />
          </div>
          <button
            onClick={create}
            disabled={submitting}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 rounded text-sm"
          >
            {submitting ? "Creating…" : "Create"}
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : rules.length === 0 ? (
        <EmptyState
          icon={Sparkles}
          title="No auto-waiver rules"
          description="Use the New rule button to create the first one."
        />
      ) : (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Rules ({rules.length})</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                {Object.keys(rules[0] || {})
                  .slice(0, 5)
                  .map((c) => (
                    <th key={c} className="px-4 py-3 text-left text-xs uppercase text-gray-400">
                      {c.replace(/_/g, " ")}
                    </th>
                  ))}
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {rules.map((row, i) => (
                <tr key={(row.rule_key as string) ?? i} className="hover:bg-gray-750">
                  {Object.values(row)
                    .slice(0, 5)
                    .map((cell, j) => (
                      <td
                        key={j}
                        className="px-4 py-3 text-sm text-gray-300 max-w-xs truncate"
                      >
                        {typeof cell === "object" && cell !== null
                          ? JSON.stringify(cell).slice(0, 80)
                          : String(cell ?? "—")}
                      </td>
                    ))}
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => remove(String(row.rule_key ?? row.id))}
                      className="text-red-400 hover:text-red-300"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
