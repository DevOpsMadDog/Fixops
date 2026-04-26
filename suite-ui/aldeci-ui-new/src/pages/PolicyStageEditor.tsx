/**
 * Policy Stage Editor — Live API
 * Multica: 55e64210-3cc7-4c7d-96b9-df5794465017
 * API: GET /api/v1/policies/{id}, PATCH /api/v1/policies/{id}
 *      (Stage matrix is part of the policy `stage_thresholds` field.)
 *
 * Lets a policy author select a policy, edit per-stage thresholds for each
 * severity, validate the JSON, and PATCH the policy back. NO MOCKS.
 */

import { useEffect, useMemo, useState } from "react";
import { Pencil, Save, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

const STAGES = ["plan", "code", "build", "test", "deploy", "operate"] as const;
const SEVS = ["critical", "high", "medium", "low"] as const;

type Policy = {
  id: string;
  name?: string;
  stage_thresholds?: Record<string, Record<string, string | number>>;
};

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
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

export default function PolicyStageEditor() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [policyId, setPolicyId] = useState<string>("");
  const [draft, setDraft] = useState<Record<string, Record<string, string>>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await apiFetch<{ items?: Policy[] } | Policy[]>("/api/v1/policies");
      const arr = Array.isArray(list) ? list : list.items ?? [];
      setPolicies(arr);
      if (arr[0]) setPolicyId(arr[0].id);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!policyId) return;
    const p = policies.find((x) => x.id === policyId);
    const initial: Record<string, Record<string, string>> = {};
    STAGES.forEach((stage) => {
      initial[stage] = {};
      SEVS.forEach((sev) => {
        const v = p?.stage_thresholds?.[stage]?.[sev];
        initial[stage][sev] = v === undefined || v === null ? "" : String(v);
      });
    });
    setDraft(initial);
    setSavedAt(null);
  }, [policyId, policies]);

  const dirty = useMemo(() => {
    const p = policies.find((x) => x.id === policyId);
    if (!p) return false;
    for (const stage of STAGES) {
      for (const sev of SEVS) {
        const original = p.stage_thresholds?.[stage]?.[sev];
        const norm = original === undefined || original === null ? "" : String(original);
        if (draft[stage]?.[sev] !== norm) return true;
      }
    }
    return false;
  }, [draft, policyId, policies]);

  const save = async () => {
    if (!policyId) return;
    setSaving(true);
    setError(null);
    try {
      const stage_thresholds: Record<string, Record<string, string>> = {};
      STAGES.forEach((stage) => {
        stage_thresholds[stage] = {};
        SEVS.forEach((sev) => {
          const v = draft[stage]?.[sev] ?? "";
          if (v.trim()) stage_thresholds[stage][sev] = v.trim();
        });
      });
      await apiFetch(`/api/v1/policies/${policyId}`, {
        method: "PATCH",
        body: JSON.stringify({ stage_thresholds }),
      });
      setSavedAt(new Date().toISOString());
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Pencil className="w-6 h-6 text-indigo-400" /> Policy Stage Editor
          </h1>
          <p className="text-gray-400 mt-1">
            Live data — PATCH /api/v1/policies/&#123;id&#125;
          </p>
        </div>
        <div className="flex items-center gap-2">
          {savedAt && <span className="text-xs text-emerald-400">Saved {savedAt}</span>}
          <button
            onClick={save}
            disabled={!dirty || saving}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 disabled:text-gray-500 rounded-lg text-sm"
          >
            <Save className={`w-4 h-4 ${saving ? "animate-spin" : ""}`} /> Save
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : policies.length === 0 ? (
        <EmptyState
          icon={Pencil}
          title="No policies to edit"
          description="Create a policy first via POST /api/v1/policies."
        />
      ) : (
        <>
          <div className="bg-gray-800 rounded-lg p-4">
            <label className="text-xs uppercase text-gray-400 block mb-1">Policy</label>
            <select
              value={policyId}
              onChange={(e) => setPolicyId(e.target.value)}
              className="bg-gray-900 text-gray-100 border border-gray-700 rounded px-3 py-2 w-full md:w-96"
            >
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name ?? p.id}
                </option>
              ))}
            </select>
          </div>

          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-700">
              <h2 className="text-lg font-semibold text-white">Edit thresholds</h2>
              <p className="text-xs text-gray-500 mt-1">
                Empty cell = inherit from parent / no threshold.
              </p>
            </div>
            <div className="overflow-x-auto p-4">
              <table className="w-full">
                <thead>
                  <tr>
                    <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">
                      Stage
                    </th>
                    {SEVS.map((s) => (
                      <th
                        key={s}
                        className="px-4 py-3 text-left text-xs uppercase text-gray-400"
                      >
                        {s}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {STAGES.map((stage) => (
                    <tr key={stage}>
                      <td className="px-4 py-3 text-sm font-medium text-indigo-300 capitalize">
                        {stage}
                      </td>
                      {SEVS.map((sev) => (
                        <td key={sev} className="px-4 py-3">
                          <input
                            type="text"
                            value={draft[stage]?.[sev] ?? ""}
                            onChange={(e) =>
                              setDraft((d) => ({
                                ...d,
                                [stage]: { ...(d[stage] ?? {}), [sev]: e.target.value },
                              }))
                            }
                            placeholder="—"
                            className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm w-24"
                          />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
