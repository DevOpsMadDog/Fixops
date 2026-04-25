/**
 * Risk Acceptance - Live API
 * Route: /risk-acceptance
 * API: GET /api/v1/risk-acceptance, /pending, /expiring, /stats
 */
import { useState, useEffect } from "react";
import { ShieldCheck, RefreshCw, Clock, Check, X, ArrowRight } from "lucide-react";
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

const statusColor: Record<string, string> = {
  pending: "bg-amber-700 text-amber-100",
  approved: "bg-green-700 text-green-100",
  rejected: "bg-red-700 text-red-100",
  revoked: "bg-gray-600 text-gray-200",
  expired: "bg-purple-700 text-purple-100",
};
const riskColor = (s: number) => s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-amber-400" : "text-green-400";

export default function RiskAcceptance() {
  const [all, setAll] = useState<any[]>([]);
  const [pending, setPending] = useState<any[]>([]);
  const [expiring, setExpiring] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [tab, setTab] = useState<"all" | "pending" | "expiring">("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, p, e, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/risk-acceptance"),
        apiFetch<any>("/api/v1/risk-acceptance/pending"),
        apiFetch<any>("/api/v1/risk-acceptance/expiring"),
        apiFetch<any>("/api/v1/risk-acceptance/stats"),
      ]);
      if (a.status === "fulfilled") { const v = a.value as any; setAll(Array.isArray(v) ? v : (v.items ?? [])); }
      if (p.status === "fulfilled") { const v = p.value as any; setPending(Array.isArray(v) ? v : (v.items ?? [])); }
      if (e.status === "fulfilled") { const v = e.value as any; setExpiring(Array.isArray(v) ? v : (v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const act = async (id: string, kind: "approve" | "reject" | "revoke") => {
    try { await apiFetch<any>(`/api/v1/risk-acceptance/${id}/${kind}`, { method: "POST" }); load(); }
    catch (er) { setError((er as Error).message); }
  };

  const data = tab === "pending" ? pending : tab === "expiring" ? expiring : all;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><ShieldCheck className="w-6 h-6 text-blue-400" /> Risk Acceptance</h1>
          <p className="text-gray-400 text-sm mt-1">Risk acceptance workflow with expiration tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : all.length === 0 && pending.length === 0 ? <EmptyState icon={ShieldCheck} title="No risk acceptances" description="Submit risk acceptance requests to track approvals." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total", value: stats?.total ?? all.length, color: "text-blue-400" },
              { label: "Pending", value: stats?.pending ?? pending.length, color: "text-amber-400" },
              { label: "Approved", value: stats?.approved ?? all.filter(a => a.status === "approved").length, color: "text-green-400" },
              { label: "Expiring Soon", value: stats?.expiring ?? expiring.length, color: "text-purple-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>

          <div className="flex gap-2 bg-gray-800 rounded-lg p-1 w-fit">
            {(["all", "pending", "expiring"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)} className={`px-4 py-2 rounded text-sm font-medium capitalize ${tab === t ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>{t}</button>
            ))}
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4">{tab === "pending" ? "Pending Approvals" : tab === "expiring" ? "Expiring Acceptances" : "All Acceptances"}</h2>
            {data.length === 0 ? <p className="text-gray-500 text-sm">No items.</p>
              : <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Title</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2 pr-4">Risk Score</th><th className="text-left pb-2 pr-4">Expires</th><th className="text-left pb-2 pr-4">Requestor</th><th className="text-left pb-2">Actions</th></tr></thead>
                <tbody className="divide-y divide-gray-700/50">{data.map(r => (
                  <tr key={r.id} className="hover:bg-gray-700/30">
                    <td className="py-3 pr-4 text-gray-200 font-medium">{r.title ?? r.finding ?? "—"}</td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[r.status] ?? "bg-gray-700 text-gray-200"}`}>{r.status}</span></td>
                    <td className={`py-3 pr-4 font-bold ${riskColor(r.risk_score ?? 0)}`}>{r.risk_score ?? "—"}</td>
                    <td className="py-3 pr-4 text-gray-400 text-xs flex items-center gap-1"><Clock className="w-3 h-3" /> {r.expires_at ?? r.expiry_date ?? "—"}</td>
                    <td className="py-3 pr-4 text-gray-300 text-xs">{r.requestor ?? r.requested_by ?? "—"}</td>
                    <td className="py-3">
                      {r.status === "pending" && <div className="flex gap-1">
                        <button onClick={() => act(r.id, "approve")} title="Approve" className="p-1 bg-green-700 hover:bg-green-600 rounded"><Check className="w-3 h-3" /></button>
                        <button onClick={() => act(r.id, "reject")} title="Reject" className="p-1 bg-red-700 hover:bg-red-600 rounded"><X className="w-3 h-3" /></button>
                      </div>}
                      {r.status === "approved" && <button onClick={() => act(r.id, "revoke")} title="Revoke" className="p-1 bg-gray-700 hover:bg-gray-600 rounded text-xs flex items-center gap-1"><ArrowRight className="w-3 h-3" /> Revoke</button>}
                    </td>
                  </tr>
                ))}</tbody>
              </table></div>}
          </div>
        </>}
    </div>
  );
}
