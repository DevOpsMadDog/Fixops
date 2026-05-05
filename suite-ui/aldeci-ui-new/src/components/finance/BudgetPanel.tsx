/**
 * BudgetPanel — wires GET /api/v1/security-budget/stats + /allocations
 * Shows budget utilisation stats + allocation table.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Wallet, BarChart2, CheckCircle2 } from "lucide-react";
import { securityBudgetApi } from "@/lib/api";

interface BudgetStats {
  total_allocated: number;
  total_spent: number;
  utilization_pct: number;
  pending_approval_count: number;
  by_category: Record<string, { allocated: number; spent: number }>;
}

interface Allocation {
  id: string;
  category: string;
  fiscal_year: number;
  allocated_amount: number;
  currency: string;
  notes?: string;
}

function fmt$(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

export function BudgetPanel() {
  const [stats, setStats] = useState<BudgetStats | null>(null);
  const [allocations, setAllocations] = useState<Allocation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([securityBudgetApi.stats(), securityBudgetApi.allocations()])
      .then(([statsRes, allocRes]) => {
        if (cancelled) return;
        setStats(statsRes.data as BudgetStats);
        const d = allocRes.data;
        const rows: Allocation[] =
          Array.isArray(d?.items) ? d.items :
          Array.isArray(d?.allocations) ? d.allocations :
          Array.isArray(d) ? d : [];
        setAllocations(rows);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load budget data");
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />
          ))}
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

  const noData = !stats && !allocations.length;
  if (noData) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Wallet className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No budget allocations yet</p>
        <p className="text-xs opacity-70">
          Create a budget allocation via POST /api/v1/security-budget/allocations.
        </p>
      </div>
    );
  }

  const utilized = stats?.utilization_pct ?? 0;
  const barColor =
    utilized >= 90 ? "bg-red-500" :
    utilized >= 70 ? "bg-amber-400" :
    "bg-emerald-500";

  return (
    <div className="flex flex-col gap-6">
      {stats && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Allocated" value={fmt$(stats.total_allocated)} icon={Wallet} accent="text-indigo-400" />
          <StatCard label="Total Spent" value={fmt$(stats.total_spent)} icon={BarChart2} accent="text-sky-400" />
          <StatCard label="Utilization" value={`${utilized.toFixed(1)}%`} icon={CheckCircle2} accent={utilized >= 90 ? "text-red-400" : "text-emerald-400"} />
          <StatCard label="Pending Approvals" value={String(stats.pending_approval_count ?? 0)} icon={AlertTriangle} accent="text-amber-400" />
        </div>
      )}

      {stats && (
        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Overall Utilization
          </p>
          <div className="h-3 w-full rounded-full bg-muted/40 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${barColor}`}
              style={{ width: `${Math.min(utilized, 100)}%` }}
            />
          </div>
          <p className="mt-1 text-right text-xs text-muted-foreground">
            {fmt$(stats.total_spent)} / {fmt$(stats.total_allocated)}
          </p>
        </div>
      )}

      {allocations.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <p className="px-4 pt-4 pb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Allocations
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 text-xs text-muted-foreground uppercase tracking-wider">
                  <th className="px-4 py-2 text-left font-medium">Category</th>
                  <th className="px-4 py-2 text-left font-medium">Fiscal Year</th>
                  <th className="px-4 py-2 text-right font-medium">Allocated</th>
                  <th className="px-4 py-2 text-left font-medium">Notes</th>
                </tr>
              </thead>
              <tbody>
                {allocations.map(a => (
                  <tr key={a.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 font-medium capitalize text-foreground">{a.category}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{a.fiscal_year}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-foreground">{fmt$(a.allocated_amount)}</td>
                    <td className="px-4 py-2.5 text-muted-foreground truncate max-w-xs">{a.notes ?? "—"}</td>
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
