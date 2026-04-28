// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Stage Policy Matrix — Live API
 * Multica: 932eab7f-3d8c-4ec3-af19-a8743319f89a
 * API: GET /api/v1/policies (list) + GET /api/v1/policies/{id} (matrix detail)
 *
 * Renders a per-policy SDLC stage × severity matrix derived from the
 * policy's `rules` / `stage_thresholds` payload. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { Grid3x3, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const STAGES = ["plan", "code", "build", "test", "deploy", "operate"] as const;
const SEVS = ["critical", "high", "medium", "low"] as const;

type Policy = {
  id: string;
  name?: string;
  rules?: Array<Record<string, unknown>>;
  stage_thresholds?: Record<string, Record<string, string | number>>;
};

export default function StagePolicyMatrix() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [selected, setSelected] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiFetch<{ items?: Policy[] } | Policy[]>("/api/v1/policies");
      const list = Array.isArray(v) ? v : v.items ?? [];
      setPolicies(list);
      setSelected(list[0] ?? null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  // Build cell payload from selected.rules / stage_thresholds
  const cellFor = (stage: string, sev: string): string => {
    if (!selected) return "—";
    const thresholds = selected.stage_thresholds?.[stage];
    if (thresholds && thresholds[sev] !== undefined) return String(thresholds[sev]);
    const matched = (selected.rules ?? []).filter(
      (r) =>
        String((r as Record<string, unknown>).stage ?? "").toLowerCase() === stage &&
        String((r as Record<string, unknown>).severity ?? "").toLowerCase() === sev,
    );
    return matched.length ? `${matched.length} rule${matched.length > 1 ? "s" : ""}` : "—";
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Grid3x3 className="w-6 h-6 text-indigo-400" /> Stage Policy Matrix
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/policies (stage × severity)</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : policies.length === 0 ? (
        <EmptyState
          icon={Grid3x3}
          title="No policies"
          description="Create a policy via /api/v1/policies to see its stage × severity matrix here."
        />
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            {policies.slice(0, 12).map((p) => (
              <button
                key={p.id}
                onClick={() => setSelected(p)}
                className={`px-3 py-1.5 rounded text-xs font-medium ${
                  selected?.id === p.id
                    ? "bg-indigo-600 text-white"
                    : "bg-gray-800 text-gray-400 hover:text-white"
                }`}
              >
                {p.name ?? p.id}
              </button>
            ))}
          </div>

          {selected && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-700">
                <h2 className="text-lg font-semibold text-white">
                  {selected.name ?? selected.id} — Stage × Severity
                </h2>
              </div>
              <div className="overflow-x-auto p-4">
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">
                        Stage
                      </th>
                      {SEVS.map((s) => (
                        <th
                          key={s}
                          className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase"
                        >
                          {s}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700">
                    {STAGES.map((stage) => (
                      <tr key={stage} className="hover:bg-gray-750">
                        <td className="px-4 py-3 text-sm font-medium text-indigo-300 capitalize">
                          {stage}
                        </td>
                        {SEVS.map((sev) => (
                          <td key={sev} className="px-4 py-3 text-sm text-gray-300">
                            {cellFor(stage, sev)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
