// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Quantum Cryptography Dashboard - Live API
 * Route: /quantum-crypto
 * API: GET /api/v1/quantum-crypto/{assets,assessments,migrations,readiness}
 */
import { useState, useEffect } from "react";
import { Atom, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export default function QuantumCryptoDashboard() {
  const [assets, setAssets] = useState<any[]>([]);
  const [migrations, setMigrations] = useState<any[]>([]);
  const [readiness, setReadiness] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, m, r] = await Promise.allSettled([
        apiFetch<any>("/api/v1/quantum-crypto/assets"),
        apiFetch<any>("/api/v1/quantum-crypto/migrations"),
        apiFetch<any>("/api/v1/quantum-crypto/readiness"),
      ]);
      if (a.status === "fulfilled") { const v = a.value as any; setAssets(Array.isArray(v) ? v : (v.assets ?? v.items ?? [])); }
      if (m.status === "fulfilled") { const v = m.value as any; setMigrations(Array.isArray(v) ? v : (v.migrations ?? v.items ?? [])); }
      if (r.status === "fulfilled") { setReadiness(r.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const vulnerable = assets.filter(a => a.quantum_vulnerable).length;
  const migrated = assets.filter(a => a.migrated || a.status === "migrated").length;
  const progressPct = assets.length ? Math.round((migrated / assets.length) * 100) : 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Atom className="w-6 h-6 text-purple-400" /> Quantum Cryptography</h1>
          <p className="text-gray-400 text-sm mt-1">Post-quantum readiness and migration tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : assets.length === 0 ? <EmptyState icon={Atom} title="No crypto assets tracked" description="Inventory your crypto assets to assess quantum readiness." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Total Assets</p><p className="text-3xl font-bold text-blue-400 mt-1">{assets.length}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Quantum Vulnerable</p><p className="text-3xl font-bold text-red-400 mt-1">{vulnerable}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Migrated</p><p className="text-3xl font-bold text-green-400 mt-1">{migrated}</p></div>
            <div className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">Readiness</p><p className="text-3xl font-bold text-purple-400 mt-1">{readiness?.score ?? progressPct}%</p></div>
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Crypto Assets</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Asset</th><th className="text-left pb-2 pr-4">Algorithm</th><th className="text-left pb-2 pr-4">Quantum Safe</th><th className="text-left pb-2 pr-4">Status</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{assets.map(a => (
                <tr key={a.id ?? a.name} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{a.name ?? a.asset_name}</td>
                  <td className="py-3 pr-4 text-gray-300 font-mono text-xs">{a.algorithm ?? "—"}</td>
                  <td className="py-3 pr-4">{a.quantum_vulnerable ? <span className="text-red-400 text-xs">Vulnerable</span> : <span className="text-green-400 text-xs">Safe</span>}</td>
                  <td className="py-3 text-gray-400 text-xs capitalize">{a.status}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
          {migrations.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">Migration Plan</h2>
            <div className="space-y-2">{migrations.slice(0, 20).map((m, i) => (
              <div key={m.id ?? i} className="flex items-center justify-between p-2 bg-gray-700/30 rounded text-sm">
                <span className="text-gray-300">{m.asset_name ?? m.name}: {m.from_algo} → {m.to_algo}</span>
                <span className={`font-medium text-xs ${m.status === "completed" ? "text-green-400" : "text-amber-400"}`}>{m.status}</span>
              </div>
            ))}</div>
          </div>}
        </>}
    </div>
  );
}
