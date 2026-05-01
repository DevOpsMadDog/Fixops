// FOLDED into RulesCatalogHub hero (catalog tab) 2026-05-02 — preserve for git history
/**
 * Unified Rules Catalog — Live API
 * Multica: 3f52e898-a36a-4fde-a788-e637b63014be
 * API: GET /api/v1/rules/unified
 *      POST /api/v1/rules/unified/{rule_key}/enable | /disable
 *
 * Browse + toggle every rule across all sub-engines from a single
 * catalog view. NO MOCKS.
 */

import { useEffect, useMemo, useState } from "react";
import { ListChecks, RefreshCw } from "lucide-react";
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

type Rule = {
  key?: string;
  rule_key?: string;
  name?: string;
  description?: string;
  category?: string;
  severity?: string;
  enabled?: boolean;
  source?: string;
};

export default function UnifiedRulesCatalog() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "enabled" | "disabled">("all");
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiCall<Rule[] | { items?: Rule[] }>("/api/v1/rules/unified");
      setRules(Array.isArray(v) ? v : v.items ?? []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const toggle = async (key: string, currentlyEnabled: boolean) => {
    setBusyKey(key);
    try {
      await apiCall(
        `/api/v1/rules/unified/${encodeURIComponent(key)}/${currentlyEnabled ? "disable" : "enable"}`,
        { method: "POST" },
      );
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusyKey(null);
    }
  };

  const visible = useMemo(() => {
    if (filter === "all") return rules;
    return rules.filter((r) => Boolean(r.enabled) === (filter === "enabled"));
  }, [rules, filter]);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ListChecks className="w-6 h-6 text-indigo-400" /> Unified Rules Catalog
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/rules/unified</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      <div className="flex gap-2">
        {(["all", "enabled", "disabled"] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded text-xs font-medium capitalize ${
              filter === f
                ? "bg-indigo-600 text-white"
                : "bg-gray-800 text-gray-400 hover:text-white"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : visible.length === 0 ? (
        <EmptyState
          icon={ListChecks}
          title="No rules"
          description="Sync via /api/v1/rules/unified/sync to populate the catalog."
        />
      ) : (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Rules ({visible.length})</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Key</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Name</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">
                    Category
                  </th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">
                    Status
                  </th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {visible.slice(0, 200).map((r) => {
                  const key = r.rule_key ?? r.key ?? "";
                  const enabled = Boolean(r.enabled);
                  return (
                    <tr key={key} className="hover:bg-gray-750">
                      <td className="px-4 py-3 text-xs font-mono text-indigo-300 max-w-xs truncate">
                        {key}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-200 max-w-md truncate">
                        {r.name ?? "—"}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400">{r.category ?? "—"}</td>
                      <td className="px-4 py-3 text-sm capitalize text-gray-300">
                        {r.severity ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-medium ${
                            enabled
                              ? "bg-emerald-900/40 text-emerald-300"
                              : "bg-gray-700 text-gray-400"
                          }`}
                        >
                          {enabled ? "enabled" : "disabled"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => toggle(key, enabled)}
                          disabled={busyKey === key || !key}
                          className={`px-3 py-1 rounded text-xs ${
                            enabled
                              ? "bg-gray-700 hover:bg-gray-600 text-gray-200"
                              : "bg-indigo-600 hover:bg-indigo-500 text-white"
                          } disabled:opacity-50`}
                        >
                          {enabled ? "Disable" : "Enable"}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
