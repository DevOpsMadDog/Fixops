/**
 * Privacy Impact Assessment Dashboard - Live API
 * Route: /privacy-impact
 * API: GET /api/v1/privacy-impact/assessments
 */
import { useState, useEffect } from "react";
import { Shield, FileText, RefreshCw } from "lucide-react";
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

const statusColor: Record<string, string> = {
  draft: "bg-gray-600 text-gray-200",
  in_review: "bg-blue-700 text-blue-100",
  pending_approval: "bg-amber-700 text-amber-100",
  approved: "bg-green-700 text-green-100",
  rejected: "bg-red-700 text-red-100",
};

function riskColor(s: number) { return s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-amber-400" : "text-green-400"; }

export default function PrivacyImpactDashboard() {
  const [pias, setPias] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/privacy-impact/assessments");
      setPias(Array.isArray(v) ? v : (v.assessments ?? v.items ?? []));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const stats = {
    total: pias.length,
    approved: pias.filter(p => p.status === "approved").length,
    pending: pias.filter(p => p.status === "in_review" || p.status === "pending_approval").length,
    highRisk: pias.filter(p => (p.risk_score ?? 0) >= 70).length,
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Shield className="w-6 h-6 text-purple-400" /> Privacy Impact Assessments</h1>
          <p className="text-gray-400 text-sm mt-1">PIA/DPIA workflow and risk tracking</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : pias.length === 0 ? <EmptyState icon={Shield} title="No PIAs yet" description="Create a Privacy Impact Assessment to begin tracking." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total PIAs", value: stats.total, color: "text-blue-400" },
              { label: "Approved", value: stats.approved, color: "text-green-400" },
              { label: "Pending Review", value: stats.pending, color: "text-amber-400" },
              { label: "High Risk", value: stats.highRisk, color: "text-red-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><FileText className="w-4 h-4 text-purple-400" /> Assessment List</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Title</th><th className="text-left pb-2 pr-4">Status</th><th className="text-left pb-2 pr-4">Risk Score</th><th className="text-left pb-2">Created</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{pias.map(p => (
                <tr key={p.id} className="hover:bg-gray-700/30">
                  <td className="py-3 pr-4 text-gray-200 font-medium">{p.title ?? p.name ?? "—"}</td>
                  <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[p.status] || "bg-gray-600 text-gray-200"}`}>{(p.status ?? "—").replace("_", " ")}</span></td>
                  <td className={`py-3 pr-4 font-bold ${riskColor(p.risk_score ?? 0)}`}>{p.risk_score ?? 0}</td>
                  <td className="py-3 text-gray-400 text-xs">{p.created_at ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>
        </>}
    </div>
  );
}
