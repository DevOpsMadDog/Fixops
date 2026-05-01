// FOLDED into PolicyLifecycleHub at /comply/policies/lifecycle?tab=inheritance 2026-05-02 — preserve for git history
/**
 * Policy Inheritance View — Live API
 * Multica: 6ad4bf90-5dc1-4b83-ad59-808d92de5b29
 * API: GET /api/v1/organizations + GET /api/v1/policies
 *
 * Renders a parent → child organisation tree and shows which policies
 * apply at each level. Uses the Wave-C `parent_id` field. NO MOCKS.
 */

import { useEffect, useMemo, useState } from "react";
import { Network, RefreshCw, ChevronRight } from "lucide-react";
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

type Org = {
  id: string;
  name?: string;
  parent_id?: string | null;
};

type Policy = {
  id: string;
  name?: string;
  org_id?: string;
  scope?: string;
};

function buildTree(orgs: Org[]): Map<string | null, Org[]> {
  const byParent = new Map<string | null, Org[]>();
  orgs.forEach((o) => {
    const p = o.parent_id ?? null;
    const list = byParent.get(p) ?? [];
    list.push(o);
    byParent.set(p, list);
  });
  return byParent;
}

function renderTree(
  parentId: string | null,
  byParent: Map<string | null, Org[]>,
  policiesByOrg: Map<string, Policy[]>,
  depth = 0,
): React.ReactNode {
  const children = byParent.get(parentId) ?? [];
  if (!children.length) return null;
  return (
    <ul className={depth === 0 ? "space-y-2" : "ml-6 mt-1 space-y-1 border-l border-gray-700 pl-3"}>
      {children.map((c) => {
        const ps = policiesByOrg.get(c.id) ?? [];
        return (
          <li key={c.id}>
            <div className="flex items-start gap-2 py-1.5 px-2 rounded hover:bg-gray-800">
              <ChevronRight className="w-4 h-4 text-gray-500 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-gray-100 truncate">{c.name ?? c.id}</span>
                  <span className="text-xs text-gray-500">{c.id}</span>
                </div>
                {ps.length > 0 && (
                  <div className="text-xs text-indigo-300 mt-0.5">
                    {ps.length} policy{ps.length === 1 ? "" : "ies"}:{" "}
                    {ps.slice(0, 4).map((p) => p.name ?? p.id).join(", ")}
                  </div>
                )}
              </div>
            </div>
            {renderTree(c.id, byParent, policiesByOrg, depth + 1)}
          </li>
        );
      })}
    </ul>
  );
}

export default function PolicyInheritanceView() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [oRes, pRes] = await Promise.allSettled([
        apiFetch<{ items?: Org[] } | Org[]>("/api/v1/organizations"),
        apiFetch<{ items?: Policy[] } | Policy[]>("/api/v1/policies"),
      ]);
      if (oRes.status === "fulfilled") {
        const v = oRes.value;
        setOrgs(Array.isArray(v) ? v : v.items ?? []);
      }
      if (pRes.status === "fulfilled") {
        const v = pRes.value;
        setPolicies(Array.isArray(v) ? v : v.items ?? []);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const policiesByOrg = useMemo(() => {
    const m = new Map<string, Policy[]>();
    policies.forEach((p) => {
      if (!p.org_id) return;
      const list = m.get(p.org_id) ?? [];
      list.push(p);
      m.set(p.org_id, list);
    });
    return m;
  }, [policies]);

  const tree = useMemo(() => buildTree(orgs), [orgs]);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Network className="w-6 h-6 text-indigo-400" /> Policy Inheritance
          </h1>
          <p className="text-gray-400 mt-1">
            Live data — /api/v1/organizations + /api/v1/policies
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
      ) : orgs.length === 0 ? (
        <EmptyState
          icon={Network}
          title="No organisations"
          description="Create an org via POST /api/v1/organizations to see the inheritance tree."
        />
      ) : (
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-3">
            Organisation tree ({orgs.length}) — {policies.length} policies
          </h2>
          {renderTree(null, tree, policiesByOrg)}
        </div>
      )}
    </div>
  );
}
