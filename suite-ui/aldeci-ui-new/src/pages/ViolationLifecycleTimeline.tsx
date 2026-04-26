/**
 * Violation Lifecycle Timeline — Live API
 * Multica: bc6a193d-8363-412e-98fa-db18a9015fe7
 * API: GET /api/v1/findings/{id}/lifecycle (Wave-B-01)
 *      GET /api/v1/findings (to seed the picker)
 *
 * Walks `previous_violation_id` ancestry of a finding and renders the
 * chain as a vertical timeline with timestamps + actors. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { Activity, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

type Finding = {
  id: string;
  title?: string;
  severity?: string;
  status?: string;
};

type LifecycleEntry = {
  id?: string;
  finding_id?: string;
  status?: string;
  severity?: string;
  detected_at?: string;
  resolved_at?: string;
  actor?: string;
  scan_id?: string;
  previous_violation_id?: string | null;
  note?: string;
} & Record<string, unknown>;

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const sevColor: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
  info: "bg-gray-600 text-gray-200",
};

export default function ViolationLifecycleTimeline() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [findingId, setFindingId] = useState<string>("");
  const [chain, setChain] = useState<LifecycleEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [chainLoading, setChainLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiFetch<{ items?: Finding[]; findings?: Finding[] } | Finding[]>(
        "/api/v1/security-findings/findings",
      );
      const arr = Array.isArray(v) ? v : v.findings ?? v.items ?? [];
      setFindings(arr);
      if (arr[0]) setFindingId(arr[0].id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const loadChain = async (id: string) => {
    if (!id) return;
    setChainLoading(true);
    setError(null);
    try {
      const v = await apiFetch<
        { lifecycle?: LifecycleEntry[]; chain?: LifecycleEntry[] } | LifecycleEntry[]
      >(`/api/v1/findings/${encodeURIComponent(id)}/lifecycle`);
      const arr = Array.isArray(v) ? v : v.lifecycle ?? v.chain ?? [];
      setChain(arr);
    } catch (e) {
      setError((e as Error).message);
      setChain([]);
    } finally {
      setChainLoading(false);
    }
  };

  useEffect(() => {
    loadFindings();
  }, []);
  useEffect(() => {
    if (findingId) loadChain(findingId);
  }, [findingId]);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Activity className="w-6 h-6 text-indigo-400" /> Violation Lifecycle
          </h1>
          <p className="text-gray-400 mt-1">
            Live data — /api/v1/findings/&#123;id&#125;/lifecycle
          </p>
        </div>
        <button
          onClick={() => {
            loadFindings();
            if (findingId) loadChain(findingId);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
        >
          <RefreshCw
            className={`w-4 h-4 ${loading || chainLoading ? "animate-spin" : ""}`}
          />{" "}
          Refresh
        </button>
      </div>

      <div className="bg-gray-800 rounded-lg p-4 grid md:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs text-gray-400 uppercase mb-1">Finding</label>
          <select
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
          >
            {findings.length === 0 && <option value="">— no findings —</option>}
            {findings.map((f) => (
              <option key={f.id} value={f.id}>
                {f.title ?? f.id} {f.severity ? `[${f.severity}]` : ""}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-xs text-gray-400 uppercase mb-1">Or paste finding ID</label>
          <input
            type="text"
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            placeholder="finding UUID…"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm font-mono"
          />
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={() => loadChain(findingId)} />
      ) : !findingId ? (
        <EmptyState
          icon={Activity}
          title="No finding selected"
          description="Pick a finding above to view its violation lifecycle chain."
        />
      ) : chain.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No lifecycle history"
          description="This finding has no previous_violation_id ancestors yet."
        />
      ) : (
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">
            Chain ({chain.length} entr{chain.length === 1 ? "y" : "ies"})
          </h2>
          <ol className="relative border-l border-gray-700 ml-3 space-y-4">
            {chain.map((entry, i) => (
              <li
                key={(entry.id as string) ?? entry.finding_id ?? i}
                className="ml-6"
              >
                <span
                  className={`absolute -left-2 mt-1 w-4 h-4 rounded-full border-2 border-gray-900 ${
                    entry.status === "resolved"
                      ? "bg-emerald-500"
                      : entry.status === "open"
                      ? "bg-red-500"
                      : "bg-indigo-500"
                  }`}
                />
                <div className="bg-gray-700/40 rounded-lg p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    {entry.severity && (
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-bold ${
                          sevColor[entry.severity] ?? sevColor.info
                        }`}
                      >
                        {entry.severity}
                      </span>
                    )}
                    <span className="text-sm font-medium text-gray-100">
                      {entry.status ?? "(unknown)"}
                    </span>
                    {entry.actor && (
                      <span className="text-xs text-gray-400 font-mono">{entry.actor}</span>
                    )}
                  </div>
                  <div className="text-xs text-gray-400 mt-1">
                    detected {entry.detected_at ?? "—"}
                    {entry.resolved_at ? ` → resolved ${entry.resolved_at}` : ""}
                  </div>
                  <div className="text-[10px] text-gray-500 mt-1 font-mono break-all">
                    id: {String(entry.id ?? entry.finding_id ?? "—")} · scan:{" "}
                    {entry.scan_id ?? "—"}
                  </div>
                  {entry.note && (
                    <div className="text-xs text-gray-300 mt-2">{entry.note}</div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
