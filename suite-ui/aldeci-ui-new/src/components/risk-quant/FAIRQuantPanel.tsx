/**
 * FAIRQuantPanel — wires /api/v1/risk-quantification/stats + scenarios
 * Used by RiskQuantHub "fair" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, DollarSign, Shield, TrendingDown, Layers } from "lucide-react";
import { riskQuantApi } from "@/lib/api";

interface RiskStats {
  total_scenarios: number;
  total_ale: number;
  average_likelihood: number;
  total_treatments: number;
  total_financial_impact: number;
  scenarios_by_threat_actor?: Record<string, number>;
}

interface Scenario {
  id: string;
  name: string;
  threat_actor: string;
  attack_vector: string;
  likelihood_pct: number;
  minimum_loss: number;
  maximum_loss: number;
  created_at?: string;
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
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

function fmt(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toFixed(0)}`;
}

export function FAIRQuantPanel() {
  const [stats, setStats] = useState<RiskStats | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([riskQuantApi.stats(), riskQuantApi.listScenarios()])
      .then(([statsRes, scenariosRes]) => {
        if (cancelled) return;
        setStats(statsRes.data as RiskStats);
        const raw = scenariosRes.data;
        setScenarios(Array.isArray(raw) ? raw : (raw as { scenarios?: Scenario[] }).scenarios ?? []);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load FAIR data");
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

  if (!stats || (stats.total_scenarios === 0 && scenarios.length === 0)) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <DollarSign className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No FAIR scenarios defined yet</p>
        <p className="text-xs opacity-70">Create a risk scenario to begin financial quantification.</p>
      </div>
    );
  }

  const ACTOR_COLOR: Record<string, string> = {
    cybercriminal: "bg-red-500",
    nation_state: "bg-purple-500",
    insider: "bg-orange-500",
    hacktivist: "bg-yellow-500",
    opportunist: "bg-blue-400",
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Scenarios" value={stats.total_scenarios} icon={Layers} accent="text-indigo-400" />
        <StatCard label="Total ALE" value={fmt(stats.total_ale ?? 0)} icon={DollarSign} accent="text-red-400" />
        <StatCard label="Avg Likelihood" value={`${(stats.average_likelihood ?? 0).toFixed(1)}%`} icon={TrendingDown} accent="text-amber-400" />
        <StatCard label="Treatments" value={stats.total_treatments ?? 0} icon={Shield} accent="text-green-400" />
      </div>

      {stats.scenarios_by_threat_actor && Object.keys(stats.scenarios_by_threat_actor).length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Scenarios by Threat Actor</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.scenarios_by_threat_actor).map(([actor, count]) => (
              <span key={actor} className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold text-white ${ACTOR_COLOR[actor] ?? "bg-slate-500"}`}>
                {actor.replace("_", " ")} <span className="opacity-80">({count})</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
        <div className="border-b border-border/60 px-4 py-3">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">FAIR Scenarios</p>
        </div>
        <div className="divide-y divide-border/40">
          {scenarios.slice(0, 10).map((s) => (
            <div key={s.id} className="flex items-center justify-between px-4 py-3 text-sm hover:bg-muted/20 transition-colors">
              <div className="flex flex-col gap-0.5 min-w-0">
                <span className="font-medium text-foreground truncate">{s.name}</span>
                <span className="text-xs text-muted-foreground">{s.attack_vector} · {s.threat_actor?.replace("_", " ")}</span>
              </div>
              <div className="flex items-center gap-4 shrink-0 ml-4">
                <span className="text-xs text-muted-foreground">{s.likelihood_pct?.toFixed(0)}% likely</span>
                <span className="text-xs font-semibold text-red-400">{fmt(s.maximum_loss ?? 0)} max</span>
              </div>
            </div>
          ))}
          {scenarios.length === 0 && (
            <div className="px-4 py-8 text-center text-xs text-muted-foreground">No scenarios yet</div>
          )}
        </div>
      </div>
    </div>
  );
}
