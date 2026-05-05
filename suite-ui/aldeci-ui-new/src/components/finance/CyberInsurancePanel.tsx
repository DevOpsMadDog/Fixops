/**
 * CyberInsurancePanel — wires GET /api/v1/cyber-insurance/stats + /policies + /claims
 * Shows insurance portfolio stats, active policies, and claims ledger.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Shield, FileText, DollarSign } from "lucide-react";
import { cyberInsuranceApi } from "@/lib/api";

interface InsuranceStats {
  total_policies: number;
  active_policies: number;
  total_coverage_limit: number;
  total_premium_annual: number;
  total_claims: number;
  open_claims: number;
  total_claimed_amount: number;
  total_settled_amount: number;
}

interface Policy {
  id: string;
  carrier: string;
  policy_number: string;
  coverage_type: string;
  coverage_limit: number;
  premium_annual: number;
  status: string;
  expiry_date?: string;
}

interface Claim {
  id: string;
  policy_id: string;
  incident_type: string;
  incident_date?: string;
  estimated_loss: number;
  status: string;
  settlement_amount?: number;
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

const CLAIM_STATUS_COLOR: Record<string, string> = {
  open: "text-amber-400",
  in_review: "text-sky-400",
  settled: "text-emerald-400",
  denied: "text-red-400",
  closed: "text-muted-foreground",
};

const POLICY_STATUS_COLOR: Record<string, string> = {
  active: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  expired: "bg-red-500/20 text-red-400 border-red-500/30",
  pending: "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

export function CyberInsurancePanel() {
  const [stats, setStats] = useState<InsuranceStats | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      cyberInsuranceApi.stats(),
      cyberInsuranceApi.policies(),
      cyberInsuranceApi.claims(),
    ])
      .then(([statsRes, policiesRes, claimsRes]) => {
        if (cancelled) return;
        setStats(statsRes.data as InsuranceStats);
        const pols: Policy[] =
          Array.isArray(policiesRes.data) ? policiesRes.data :
          Array.isArray(policiesRes.data?.policies) ? policiesRes.data.policies : [];
        setPolicies(pols);
        const cls: Claim[] =
          Array.isArray(claimsRes.data) ? claimsRes.data :
          Array.isArray(claimsRes.data?.claims) ? claimsRes.data.claims : [];
        setClaims(cls);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load insurance data");
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

  if (!stats && policies.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Shield className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No cyber insurance policies found</p>
        <p className="text-xs opacity-70">
          Add a policy via POST /api/v1/cyber-insurance/policies.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {stats && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Active Policies" value={String(stats.active_policies)} icon={Shield} accent="text-emerald-400" />
          <StatCard label="Coverage Limit" value={fmt$(stats.total_coverage_limit)} icon={DollarSign} accent="text-indigo-400" />
          <StatCard label="Annual Premium" value={fmt$(stats.total_premium_annual)} icon={FileText} accent="text-sky-400" />
          <StatCard label="Open Claims" value={String(stats.open_claims)} icon={AlertTriangle} accent={stats.open_claims > 0 ? "text-amber-400" : "text-muted-foreground"} />
        </div>
      )}

      {policies.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <p className="px-4 pt-4 pb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Policies
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 text-xs text-muted-foreground uppercase tracking-wider">
                  <th className="px-4 py-2 text-left font-medium">Carrier</th>
                  <th className="px-4 py-2 text-left font-medium">Policy #</th>
                  <th className="px-4 py-2 text-left font-medium">Type</th>
                  <th className="px-4 py-2 text-right font-medium">Limit</th>
                  <th className="px-4 py-2 text-right font-medium">Premium</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 font-medium text-foreground">{p.carrier || "—"}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">{p.policy_number || "—"}</td>
                    <td className="px-4 py-2.5 capitalize text-muted-foreground">{p.coverage_type}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-foreground">{fmt$(p.coverage_limit)}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-muted-foreground">{fmt$(p.premium_annual)}/yr</td>
                    <td className="px-4 py-2.5">
                      <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase ${POLICY_STATUS_COLOR[p.status] ?? "bg-muted/20 text-muted-foreground border-border/40"}`}>
                        {p.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {claims.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <p className="px-4 pt-4 pb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Claims
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 text-xs text-muted-foreground uppercase tracking-wider">
                  <th className="px-4 py-2 text-left font-medium">Incident Type</th>
                  <th className="px-4 py-2 text-left font-medium">Date</th>
                  <th className="px-4 py-2 text-right font-medium">Est. Loss</th>
                  <th className="px-4 py-2 text-right font-medium">Settlement</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {claims.map(c => (
                  <tr key={c.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 capitalize text-foreground">{c.incident_type || "—"}</td>
                    <td className="px-4 py-2.5 text-muted-foreground text-xs">{c.incident_date ?? "—"}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-foreground">{fmt$(c.estimated_loss)}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-muted-foreground">
                      {c.settlement_amount != null ? fmt$(c.settlement_amount) : "—"}
                    </td>
                    <td className={`px-4 py-2.5 font-semibold capitalize ${CLAIM_STATUS_COLOR[c.status] ?? "text-muted-foreground"}`}>
                      {c.status.replace(/_/g, " ")}
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
