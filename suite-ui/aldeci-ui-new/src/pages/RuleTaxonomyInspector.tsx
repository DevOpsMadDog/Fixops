/**
 * Rule Taxonomy Inspector — Live API
 * Multica: 9dcd0ae8-5f2d-4001-b68c-48e6d25fcd57
 * API: GET /api/v1/rules/unified/taxonomy
 *
 * Renders the rule taxonomy as a hierarchy: category → sub-category →
 * rule keys. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { GitBranch, RefreshCw } from "lucide-react";
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

type TaxonomyNode = unknown;

function isNonNullObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function renderNode(label: string, node: TaxonomyNode, depth = 0): React.ReactNode {
  if (Array.isArray(node)) {
    return (
      <details
        open={depth < 1}
        className="ml-4"
        style={{ marginLeft: `${depth * 12}px` }}
      >
        <summary className="cursor-pointer text-sm text-indigo-300">
          {label} <span className="text-gray-500">({node.length})</span>
        </summary>
        <ul className="ml-4 mt-1 space-y-0.5">
          {node.slice(0, 200).map((item, i) => (
            <li key={i} className="text-xs text-gray-400 font-mono truncate">
              {typeof item === "string" ? item : JSON.stringify(item).slice(0, 120)}
            </li>
          ))}
        </ul>
      </details>
    );
  }
  if (isNonNullObject(node)) {
    return (
      <details
        open={depth < 1}
        className="ml-4"
        style={{ marginLeft: `${depth * 12}px` }}
      >
        <summary className="cursor-pointer text-sm font-medium text-gray-200">{label}</summary>
        <div className="ml-4 mt-1 space-y-0.5">
          {Object.entries(node).map(([k, v]) => (
            <div key={k}>{renderNode(k, v, depth + 1)}</div>
          ))}
        </div>
      </details>
    );
  }
  return (
    <div className="text-xs text-gray-400" style={{ marginLeft: `${depth * 12}px` }}>
      <span className="text-gray-500">{label}:</span> {String(node)}
    </div>
  );
}

export default function RuleTaxonomyInspector() {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiFetch<Record<string, unknown>>("/api/v1/rules/unified/taxonomy");
      setData(v);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <GitBranch className="w-6 h-6 text-indigo-400" /> Rule Taxonomy
          </h1>
          <p className="text-gray-400 mt-1">
            Live data — /api/v1/rules/unified/taxonomy
          </p>
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
      ) : !data || Object.keys(data).length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title="No taxonomy yet"
          description="Run /api/v1/rules/unified/sync to populate the taxonomy."
        />
      ) : (
        <div className="bg-gray-800 rounded-lg p-6 space-y-2">
          {Object.entries(data).map(([k, v]) => (
            <div key={k}>{renderNode(k, v)}</div>
          ))}
        </div>
      )}
    </div>
  );
}
