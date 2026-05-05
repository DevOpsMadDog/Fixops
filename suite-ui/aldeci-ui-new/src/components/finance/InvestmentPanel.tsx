/**
 * InvestmentPanel — security investment portfolio + ROI outcomes
 * API: GET /api/v1/security-investment/portfolio + /investments
 * Used by FinanceHub "investment" tab.
 */

import { useEffect, useState } from "react";
import { TrendingUp, AlertTriangle, RefreshCw, CheckCircle2, Clock } from "lucide-react";
import { securityInvestmentApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";

interface Investment {
  investment_id?: string;
  id?: string;
  name?: string;
  category?: string;
  status?: string;
  invested_amount?: number;
  currency?: string;
  risk_reduction_pct?: number;
  roi_pct?: number;
  start_date?: string;
  end_date?: string;
}

interface Portfolio {
  total_investments?: number;
  total_invested?: number;
  total_risk_reduction?: number;
  avg_roi_pct?: number;
  active_count?: number;
  completed_count?: number;
  currency?: string;
  by_category?: Record<string, { invested: number; count: number }>;
}

function fmt$(n: number, currency = "USD") {
  if (n >= 1_000_000) return `${currency === "USD" ? "$" : ""}${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${currency === "USD" ? "$" : ""}${(n / 1_000).toFixed(0)}K`;
  return `${currency === "USD" ? "$" : ""}${n.toFixed(0)}`;
}

const STATUS_PILL: Record<string, string> = {
  active:    "bg-green-700/40 text-green-300",
  completed: "bg-sky-700/40 text-sky-300",
  planned:   "bg-indigo-700/40 text-indigo-300",
  cancelled: "bg-gray-700/40 text-gray-400",
};

function pill(s: string) {
  return STATUS_PILL[s?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

function StatusIcon({ status }: { status: string }) {
  if (status === "active")    return <Clock className="h-3 w-3 text-green-400" />;
  if (status === "completed") return <CheckCircle2 className="h-3 w-3 text-sky-400" />;
  return null;
}

export function InvestmentPanel() {
  const [portfolio, setPortfolio]   = useState<Portfolio | null>(null);
  const [investments, setInvestments] = useState<Investment[]>([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [portRes, invRes] = await Promise.allSettled([
        securityInvestmentApi.portfolio(),
        securityInvestmentApi.list(),
      ]);
      if (portRes.status === "fulfilled") setPortfolio(portRes.value.data as Portfolio);
      if (invRes.status === "fulfilled") {
        const d = invRes.value.data;
        setInvestments(Array.isArray(d) ? d : (d?.investments ?? d?.items ?? []));
      }
      if (portRes.status === "rejected" && invRes.status === "rejected") {
        throw new Error("Failed to load investment data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-4 p-4 animate-pulse">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />)}
        </div>
        <div className="h-48 rounded-xl border border-border/40 bg-muted/30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (!portfolio && investments.length === 0) {
    return (
      <EmptyState
        icon={TrendingUp}
        title="No investments recorded"
        description="Create a security investment via POST /api/v1/security-investment/investments."
      />
    );
  }

  const currency = portfolio?.currency ?? "USD";
  const avgRoi   = portfolio?.avg_roi_pct ?? 0;
  const roiColor = avgRoi >= 20 ? "text-green-400" : avgRoi >= 0 ? "text-amber-400" : "text-red-400";

  return (
    <div className="space-y-6">
      {/* Portfolio stats */}
      {portfolio && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Invested",    value: fmt$(portfolio.total_invested ?? 0, currency), color: "text-foreground" },
            { label: "Risk Reduction",    value: `${(portfolio.total_risk_reduction ?? 0).toFixed(1)}%`, color: "text-green-400" },
            { label: "Avg ROI",           value: `${avgRoi.toFixed(1)}%`, color: roiColor },
            { label: "Active / Completed",value: `${portfolio.active_count ?? 0} / ${portfolio.completed_count ?? 0}`, color: "text-sky-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
                <TrendingUp className="h-3.5 w-3.5" />
                {label}
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Category breakdown */}
      {portfolio?.by_category && Object.keys(portfolio.by_category).length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
            Investment by Category
          </h3>
          <div className="space-y-2">
            {Object.entries(portfolio.by_category).map(([cat, data]) => {
              const total = portfolio.total_invested ?? 1;
              const pct   = total > 0 ? ((data.invested / total) * 100) : 0;
              return (
                <div key={cat}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="capitalize text-foreground">{cat}</span>
                    <span className="text-muted-foreground">{fmt$(data.invested, currency)} ({pct.toFixed(0)}%)</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-muted/40 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-indigo-500 transition-all duration-700"
                      style={{ width: `${Math.min(pct, 100)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Investments table */}
      {investments.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border/60">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <TrendingUp className="h-3.5 w-3.5 text-indigo-400" />
              Investments ({investments.length})
            </h3>
            <button
              onClick={load}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 text-xs text-muted-foreground uppercase tracking-wider">
                  <th className="px-4 py-2 text-left font-medium">Name</th>
                  <th className="px-4 py-2 text-left font-medium">Category</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                  <th className="px-4 py-2 text-right font-medium">Invested</th>
                  <th className="px-4 py-2 text-right font-medium">ROI</th>
                  <th className="px-4 py-2 text-right font-medium">Risk Reduction</th>
                </tr>
              </thead>
              <tbody>
                {investments.map((inv, i) => (
                  <tr
                    key={inv.investment_id ?? inv.id ?? i}
                    className="border-b border-border/20 hover:bg-muted/20 transition-colors"
                  >
                    <td className="px-4 py-2.5 font-medium text-foreground flex items-center gap-1.5">
                      <StatusIcon status={inv.status ?? ""} />
                      {inv.name ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground capitalize">{inv.category ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${pill(inv.status ?? "")}`}>
                        {inv.status ?? "unknown"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono">
                      {inv.invested_amount != null ? fmt$(inv.invested_amount, currency) : "—"}
                    </td>
                    <td className={`px-4 py-2.5 text-right font-mono ${(inv.roi_pct ?? 0) >= 0 ? "text-green-400" : "text-red-400"}`}>
                      {inv.roi_pct != null ? `${inv.roi_pct.toFixed(1)}%` : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-sky-400">
                      {inv.risk_reduction_pct != null ? `${inv.risk_reduction_pct.toFixed(1)}%` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
