/**
 * Policy Library Browser — Live API
 * Multica: bd5adbfd-caec-4eb3-8b2d-a810b83638c4
 * API: GET /api/v1/policies + GET /api/v1/policies/stats
 *
 * Browseable catalogue of policy definitions with name search and tag
 * filter chips derived from the live data. NO MOCKS.
 */

import { useEffect, useMemo, useState } from "react";
import { BookOpen, Search, RefreshCw } from "lucide-react";
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

type Policy = {
  id: string;
  name?: string;
  description?: string;
  tags?: string[];
  category?: string;
  owner?: string;
  status?: string;
};

export default function PolicyLibraryBrowser() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [stats, setStats] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [tag, setTag] = useState<string>("");

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [pRes, sRes] = await Promise.allSettled([
        apiFetch<{ items?: Policy[] } | Policy[]>("/api/v1/policies"),
        apiFetch<Record<string, unknown>>("/api/v1/policies/stats"),
      ]);
      if (pRes.status === "fulfilled") {
        const v = pRes.value;
        setPolicies(Array.isArray(v) ? v : v.items ?? []);
      }
      if (sRes.status === "fulfilled") setStats(sRes.value);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const allTags = useMemo(() => {
    const s = new Set<string>();
    policies.forEach((p) => {
      (p.tags ?? []).forEach((t) => s.add(t));
      if (p.category) s.add(p.category);
    });
    return Array.from(s).sort();
  }, [policies]);

  const visible = useMemo(() => {
    return policies.filter((p) => {
      if (q && !(p.name ?? p.id).toLowerCase().includes(q.toLowerCase())) return false;
      if (tag && !(p.tags ?? []).includes(tag) && p.category !== tag) return false;
      return true;
    });
  }, [policies, q, tag]);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <BookOpen className="w-6 h-6 text-indigo-400" /> Policy Library
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/policies</p>
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
      ) : (
        <>
          {stats && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {(Object.entries(stats) as [string, unknown][])
                .filter(([, v]) => typeof v === "number")
                .slice(0, 4)
                .map(([k, v]) => (
                  <div key={k} className="bg-gray-800 rounded-lg p-5">
                    <p className="text-gray-400 text-sm capitalize">{k.replace(/_/g, " ")}</p>
                    <p className="text-3xl font-bold mt-1 text-indigo-400">{String(v)}</p>
                  </div>
                ))}
            </div>
          )}

          <div className="bg-gray-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-gray-500" />
              <input
                type="text"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search policies…"
                className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
              />
            </div>
            {allTags.length > 0 && (
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={() => setTag("")}
                  className={`px-2 py-1 rounded text-xs ${
                    !tag ? "bg-indigo-600 text-white" : "bg-gray-900 text-gray-400"
                  }`}
                >
                  all
                </button>
                {allTags.slice(0, 16).map((t) => (
                  <button
                    key={t}
                    onClick={() => setTag(t)}
                    className={`px-2 py-1 rounded text-xs ${
                      tag === t
                        ? "bg-indigo-600 text-white"
                        : "bg-gray-900 text-gray-400 hover:text-white"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            )}
          </div>

          {visible.length === 0 ? (
            <EmptyState
              icon={BookOpen}
              title="No policies match"
              description="Adjust your search or create a new policy via /api/v1/policies."
            />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {visible.slice(0, 60).map((p) => (
                <div
                  key={p.id}
                  className="bg-gray-800 hover:bg-gray-700 rounded-lg p-4 transition"
                >
                  <h3 className="text-base font-semibold text-white truncate">
                    {p.name ?? p.id}
                  </h3>
                  {p.description && (
                    <p className="text-xs text-gray-400 mt-1 line-clamp-2">
                      {p.description}
                    </p>
                  )}
                  <div className="flex flex-wrap gap-1 mt-3">
                    {(p.tags ?? []).slice(0, 4).map((t) => (
                      <span
                        key={t}
                        className="px-1.5 py-0.5 bg-gray-700 text-gray-300 rounded text-[10px]"
                      >
                        {t}
                      </span>
                    ))}
                    {p.category && (
                      <span className="px-1.5 py-0.5 bg-indigo-900/40 text-indigo-300 rounded text-[10px]">
                        {p.category}
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-gray-500 mt-2 truncate">{p.id}</div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
