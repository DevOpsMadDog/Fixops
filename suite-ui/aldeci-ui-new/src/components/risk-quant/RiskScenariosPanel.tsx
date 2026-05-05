/**
 * RiskScenariosPanel — wires /api/v1/risk-scenarios/scenarios + top-risks + stats
 * Used by RiskQuantHub "scenarios" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Workflow, TrendingDown, Shield } from "lucide-react";
import { riskQuantApi } from "@/lib/api";

interface ScenarioStats {
  total_scenarios: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  average_residual_risk: number;
}

interface Scenario {
  id: string;
  scenario_name: string;
  threat_category: string;
  likelihood: number;
  impact: number;
  inherent_risk?: number;
  residual_risk?: number;
  risk_level?: string;
  owner?: string;
}

interface TopRisk {
  id: string;
  scenario_name?: string;
  residual_risk?: number;
  risk_level?: string;
  threat_category?: string;
}

const RISK_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  low: "bg-green-500/15 text-green-400 border-green-500/30",
};

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

export function RiskScenariosPanel() {
  const [stats, setStats] = useState<ScenarioStats | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [topRisks, setTopRisks] = useState<TopRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      riskQuantApi.scenarioStats(),
      riskQuantApi.scenariosList(),
      riskQuantApi.topRisks(),
    ])
      .then(([statsRes, scenariosRes, topRes]) => {
        if (cancelled) return;
        setStats(statsRes.data as ScenarioStats);
        const raw = scenariosRes.data;
        setScenarios(Array.isArray(raw) ? raw : (raw as { scenarios?: Scenario[] }).scenarios ?? []);
        const topRaw = topRes.data;
        setTopRisks(Array.isArray(topRaw) ? topRaw : (topRaw as { scenarios?: TopRisk[] }).scenarios ?? []);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load risk scenarios");
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
        <div className="h-64 rounded-xl border border-border/40 bg-muted/30" />
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
        <Workflow className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No risk scenarios defined</p>
        <p className="text-xs opacity-70">Create scenarios with likelihood and impact to track residual risk over time.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total" value={stats.total_scenarios} icon={Workflow} accent="text-indigo-400" />
        <StatCard label="Critical" value={stats.critical_count ?? 0} icon={AlertTriangle} accent="text-red-400" />
        <StatCard label="High" value={stats.high_count ?? 0} icon={TrendingDown} accent="text-orange-400" />
        <StatCard
          label="Avg Residual"
          value={(stats.average_residual_risk ?? 0).toFixed(2)}
          icon={Shield}
          accent="text-green-400"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Top risks sidebar */}
        {topRisks.length > 0 && (
          <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
            <div className="border-b border-border/60 px-4 py-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Top Risks by Residual</p>
            </div>
            <div className="divide-y divide-border/40">
              {topRisks.slice(0, 8).map((r, i) => (
                <div key={r.id ?? i} className="flex items-center justify-between px-4 py-2.5 hover:bg-muted/20 transition-colors">
                  <div className="flex flex-col gap-0.5 min-w-0">
                    <span className="text-sm font-medium text-foreground truncate">{r.scenario_name ?? `Scenario ${i + 1}`}</span>
                    {r.threat_category && (
                      <span className="text-xs text-muted-foreground">{r.threat_category}</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-2">
                    {r.risk_level && (
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold capitalize ${RISK_COLOR[r.risk_level] ?? "bg-muted text-muted-foreground border-border"}`}>
                        {r.risk_level}
                      </span>
                    )}
                    <span className="text-xs font-bold text-foreground">{(r.residual_risk ?? 0).toFixed(2)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* All scenarios table */}
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="border-b border-border/60 px-4 py-3">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">All Scenarios</p>
          </div>
          <div className="divide-y divide-border/40 max-h-80 overflow-y-auto">
            {scenarios.slice(0, 15).map((s) => {
              const reduction = s.inherent_risk && s.residual_risk
                ? Math.round(((s.inherent_risk - s.residual_risk) / s.inherent_risk) * 100)
                : null;
              return (
                <div key={s.id} className="flex items-center justify-between px-4 py-2.5 hover:bg-muted/20 transition-colors">
                  <div className="flex flex-col gap-0.5 min-w-0">
                    <span className="text-sm font-medium text-foreground truncate">{s.scenario_name}</span>
                    <span className="text-xs text-muted-foreground">{s.threat_category}</span>
                  </div>
                  <div className="flex items-center gap-3 shrink-0 ml-2">
                    {s.risk_level && (
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold capitalize ${RISK_COLOR[s.risk_level] ?? "bg-muted text-muted-foreground border-border"}`}>
                        {s.risk_level}
                      </span>
                    )}
                    {reduction !== null && (
                      <span className="text-xs text-green-400 font-semibold">-{reduction}%</span>
                    )}
                  </div>
                </div>
              );
            })}
            {scenarios.length === 0 && (
              <div className="px-4 py-8 text-center text-xs text-muted-foreground">No scenarios returned</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
