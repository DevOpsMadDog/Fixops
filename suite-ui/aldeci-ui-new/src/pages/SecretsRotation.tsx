/**
 * Secrets Rotation - Live API
 * Route: /secrets-rotation
 * API: GET /api/v1/secrets-management/{secrets,expiring,stats}
 */
import { useState, useEffect } from "react";
import { Key, RefreshCw, AlertTriangle, RotateCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...init, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const typeColor: Record<string, string> = {
  api_key: "bg-blue-700 text-blue-100",
  password: "bg-purple-700 text-purple-100",
  certificate: "bg-cyan-700 text-cyan-100",
  ssh_key: "bg-orange-700 text-orange-100",
  token: "bg-green-700 text-green-100",
  database: "bg-pink-700 text-pink-100",
};

export default function SecretsRotation() {
  const [secrets, setSecrets] = useState<any[]>([]);
  const [expiring, setExpiring] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rotating, setRotating] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, e, st] = await Promise.allSettled([
        apiFetch<any>("/api/v1/secrets-management/secrets"),
        apiFetch<any>("/api/v1/secrets-management/expiring"),
        apiFetch<any>("/api/v1/secrets-management/stats"),
      ]);
      if (s.status === "fulfilled") { const v = s.value as any; setSecrets(Array.isArray(v) ? v : (v.secrets ?? v.items ?? [])); }
      if (e.status === "fulfilled") { const v = e.value as any; setExpiring(Array.isArray(v) ? v : (v.expiring ?? v.items ?? [])); }
      if (st.status === "fulfilled") { setStats(st.value); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const rotate = async (id: string) => {
    setRotating(id);
    try {
      await apiFetch<any>(`/api/v1/secrets-management/secrets/${id}/rotate`, { method: "POST", body: JSON.stringify({}) });
      load();
    } catch (er) { setError((er as Error).message); }
    finally { setRotating(null); }
  };

  const types = Array.from(new Set(secrets.map(s => s.secret_type ?? s.type).filter(Boolean)));
  const filtered = filter === "all" ? secrets : secrets.filter(s => (s.secret_type ?? s.type) === filter);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Key className="w-6 h-6 text-yellow-400" /> Secrets Rotation</h1>
          <p className="text-gray-400 text-sm mt-1">Secret lifecycle, rotation tracking, expiry alerts</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-yellow-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : secrets.length === 0 ? <EmptyState icon={Key} title="No secrets registered" description="Add secret metadata to start tracking rotation." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total Secrets", value: stats?.total ?? secrets.length, color: "text-blue-400" },
              { label: "Active", value: stats?.active ?? secrets.filter(s => s.status === "active").length, color: "text-green-400" },
              { label: "Expiring Soon", value: stats?.expiring ?? expiring.length, color: "text-amber-400" },
              { label: "Revoked", value: stats?.revoked ?? secrets.filter(s => s.status === "revoked").length, color: "text-red-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>

          {expiring.length > 0 && <div className="bg-amber-900/30 border border-amber-700 rounded-lg p-4">
            <p className="text-amber-400 font-semibold text-sm mb-2 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> Expiring Soon ({expiring.length})</p>
            <div className="flex flex-wrap gap-2">{expiring.slice(0, 10).map(e => <span key={e.id} className="bg-amber-800/50 text-amber-200 px-2 py-1 rounded text-xs">{e.name ?? e.secret_name}</span>)}</div>
          </div>}

          {types.length > 0 && <div className="flex gap-2 flex-wrap">
            <button onClick={() => setFilter("all")} className={`px-3 py-1.5 rounded text-xs font-medium ${filter === "all" ? "bg-yellow-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>All</button>
            {types.map(t => (
              <button key={t} onClick={() => setFilter(t)} className={`px-3 py-1.5 rounded text-xs font-medium ${filter === t ? "bg-yellow-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>{t}</button>
            ))}
          </div>}

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Secrets</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Type</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2 pr-4">Last Rotated</th><th className="text-left pb-2 pr-4">Expires</th><th className="text-left pb-2">Action</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{filtered.map(s => (
                <tr key={s.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{s.name ?? s.secret_name}</td>
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${typeColor[s.secret_type ?? s.type] ?? "bg-gray-700 text-gray-200"}`}>{s.secret_type ?? s.type}</span></td>
                  <td className="py-3 pr-4 text-gray-300">{s.status}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{s.last_rotated ?? "—"}</td>
                  <td className="py-3 pr-4 text-gray-400 text-xs">{s.expires_at ?? "—"}</td>
                  <td className="py-3"><button onClick={() => rotate(s.id)} disabled={rotating === s.id} className="px-3 py-1 bg-yellow-700 hover:bg-yellow-600 disabled:bg-gray-700 rounded text-xs flex items-center gap-1"><RotateCw className={`w-3 h-3 ${rotating === s.id ? "animate-spin" : ""}`} /> {rotating === s.id ? "Rotating…" : "Rotate"}</button></td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
        </>}
    </div>
  );
}
