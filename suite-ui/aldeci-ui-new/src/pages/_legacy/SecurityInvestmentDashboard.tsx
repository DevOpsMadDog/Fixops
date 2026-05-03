// FOLDED 2026-05-02 into FinanceHub.tsx — tab "investment" at /mission-control/finance?tab=investment
// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Security Investment Dashboard - Live API
 * Route: /security-investment (now redirects to /mission-control/finance?tab=investment)
 * API: GET /api/v1/security-investment/{investments,budget,outcomes}
 */
import { useState, useEffect } from "react";
import { DollarSign, TrendingUp, CheckCircle2, Clock, Trophy, RefreshCw } from "lucide-react";
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

function fmt(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

const CAT_COLOR: Record<string, string> = {
  detection: "bg-blue-500/20 text-blue-300",
  prevention: "bg-purple-500/20 text-purple-300",
  response: "bg-red-500/20 text-red-300",
  governance: "bg-teal-500/20 text-teal-300",
  training: "bg-green-500/20 text-green-300",
  infrastructure: "bg-orange-500/20 text-orange-300",
  tooling: "bg-yellow-500/20 text-yellow-300",
};
const STATUS_COLOR: Record<string, string> = {
  active: "bg-green-500/20 text-green-300",
  completed: "bg-gray-600/40 text-gray-400",
  planned: "bg-sky-500/20 text-sky-300",
  on_hold: "bg-yellow-500/20 text-yellow-300",
};
const OUTCOME_LABELS: Record<string, string> = {
  cost_avoided: "Cost Avoided",
  incidents_prevented: "Incidents Prevented",
  compliance_fine_avoided: "Fine Avoided",
  productivity_gain: "Productivity Gain",
  insurance_reduction: "Insurance Savings",
};

export default function SecurityInvestmentDashboard() {
  const [investments, setInvestments] = useState<any[]>([]);
  const [budget, setBudget] = useState<any[]>([]);
  const [outcomes, setOutcomes] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [i, b, o] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-investment/investments"),
        apiFetch<any>("/api/v1/security-investment/budget"),
        apiFetch<any>("/api/v1/security-investment/outcomes"),
      ]);
      if (i.status === "fulfilled") { const v = i.value as any; setInvestments(Array.isArray(v) ? v : (v.investments ?? v.items ?? [])); }
      if (b.status === "fulfilled") { const v = b.value as any; setBudget(Array.isArray(v) ? v : (v.budget ?? v.items ?? [])); }
      if (o.status === "fulfilled") { const v = o.value as any; setOutcomes(Array.isArray(v) ? v : (v.outcomes ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const totalInvested = investments.reduce((s, i) => s + (i.amount ?? 0), 0);
  const avgROI = investments.length ? Math.round(investments.reduce((s, i) => s + (i.roi_score ?? 0), 0) / investments.length) : 0;
  const activeCount = investments.filter(i => i.status === "active").length;
  const completedCount = investments.filter(i => i.status === "completed").length;
  const top5 = [...investments].sort((a, b) => (b.roi_score ?? 0) - (a.roi_score ?? 0)).slice(0, 5);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <DollarSign className="text-emerald-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Security Investment Dashboard</h1>
            <p className="text-gray-400 text-sm">ROI tracking, budget utilization, portfolio analysis</p>
          </div>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : investments.length === 0 ? <EmptyState icon={DollarSign} title="No investments tracked" description="Add security investments to track ROI." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-6 text-center"><div className="text-3xl font-bold text-emerald-400">{fmt(totalInvested)}</div><div className="text-gray-400 text-sm mt-1">Total Invested</div></div>
            <div className="bg-gray-800 rounded-lg p-6 text-center"><div className="text-3xl font-bold text-teal-400">{avgROI}%</div><div className="text-gray-400 text-sm mt-1">Avg ROI Score</div></div>
            <div className="bg-gray-800 rounded-lg p-6 text-center"><div className="text-3xl font-bold text-blue-400">{activeCount}</div><div className="text-gray-400 text-sm mt-1">Active</div></div>
            <div className="bg-gray-800 rounded-lg p-6 text-center"><div className="text-3xl font-bold text-gray-400">{completedCount}</div><div className="text-gray-400 text-sm mt-1">Completed</div></div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><TrendingUp size={18} className="text-emerald-400" /> Investment Portfolio</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-400 border-b border-gray-700"><th className="text-left py-2">Investment</th><th className="text-left py-2">Category</th><th className="text-left py-2">Vendor</th><th className="text-right py-2">Amount</th><th className="text-left py-2 pl-4">Status</th><th className="text-left py-2">ROI</th></tr></thead>
              <tbody>{investments.map(inv => (
                <tr key={inv.id} className="border-b border-gray-700/50">
                  <td className="py-2 font-medium text-gray-200">{inv.investment_name ?? inv.name}</td>
                  <td className="py-2"><span className={`px-2 py-0.5 rounded text-xs ${CAT_COLOR[inv.category] ?? "bg-gray-700 text-gray-300"}`}>{inv.category}</span></td>
                  <td className="py-2 text-gray-400">{inv.vendor ?? "—"}</td>
                  <td className="py-2 text-right text-gray-300 font-mono">{fmt(inv.amount ?? 0)}</td>
                  <td className="py-2 pl-4"><span className={`px-2 py-0.5 rounded text-xs ${STATUS_COLOR[inv.status] ?? "bg-gray-700 text-gray-300"}`}>{inv.status}</span></td>
                  <td className="py-2"><div className="flex items-center gap-2 w-32"><div className="flex-1 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${(inv.roi_score ?? 0) >= 100 ? "bg-green-500" : "bg-orange-500"}`} style={{ width: `${Math.min(100, (inv.roi_score ?? 0) / 2)}%` }} /></div><span className={`text-xs font-bold ${(inv.roi_score ?? 0) >= 100 ? "text-green-400" : "text-orange-400"}`}>{inv.roi_score ?? 0}%</span></div></td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {budget.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4">Budget Utilization</h2>
              <div className="space-y-4">{budget.map(b => {
                const allocated = b.allocated ?? 0, spent = b.spent ?? 0;
                const pct = allocated ? Math.round((spent / allocated) * 100) : 0;
                const over = spent > allocated;
                return (
                  <div key={b.category}>
                    <div className="flex justify-between text-xs mb-1"><span className={`font-medium ${over ? "text-red-400" : "text-gray-300"}`}>{b.category}</span><span className={over ? "text-red-400 font-medium" : "text-gray-400"}>{fmt(spent)} / {fmt(allocated)} {over ? "OVER" : ""}</span></div>
                    <div className="bg-gray-700 rounded-full h-3"><div className={`h-3 rounded-full ${over ? "bg-red-500" : "bg-emerald-500"}`} style={{ width: `${Math.min(100, pct)}%` }} /></div>
                    <div className="text-right text-xs text-gray-500 mt-0.5">{pct}% utilized</div>
                  </div>
                );
              })}</div>
            </div>}
            <div className="space-y-4">
              {outcomes.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><CheckCircle2 size={18} className="text-emerald-400" /> ROI Outcomes</h2>
                <div className="space-y-3">{outcomes.map(o => (
                  <div key={o.id} className="flex items-center justify-between gap-2 text-sm border-b border-gray-700/50 pb-2 last:border-0">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="px-2 py-0.5 rounded text-xs shrink-0 bg-emerald-500/20 text-emerald-300">{OUTCOME_LABELS[o.outcome_type] ?? o.outcome_type}</span>
                      <span className="text-gray-300 truncate">{o.investment_name}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-emerald-400 font-mono font-medium">{o.outcome_type === "incidents_prevented" ? `${o.quantified_value} inc.` : fmt(o.quantified_value ?? 0)}</span>
                      {o.verified ? <CheckCircle2 size={14} className="text-green-400" /> : <Clock size={14} className="text-gray-500" />}
                    </div>
                  </div>
                ))}</div>
              </div>}
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Trophy size={18} className="text-yellow-400" /> Top-5 by ROI</h2>
                <div className="space-y-2">{top5.map((inv, i) => (
                  <div key={inv.id} className="flex items-center gap-3 text-sm">
                    <span className="text-gray-500 w-4">{i + 1}.</span>
                    <span className="flex-1 text-gray-200 truncate">{inv.investment_name ?? inv.name}</span>
                    <span className="text-green-400 font-bold font-mono">{inv.roi_score ?? 0}%</span>
                  </div>
                ))}</div>
              </div>
            </div>
          </div>
        </>}
    </div>
  );
}
