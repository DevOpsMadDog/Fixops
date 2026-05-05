/**
 * ZeroTrustPolicyPanel — wires GET /api/v1/zero-trust-policy/stats,
 * GET /api/v1/zero-trust-policy/compliance, and
 * GET /api/v1/zero-trust-policy/policies.
 * Used by NetworkSegmentationHub "policy" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Lock, ShieldCheck, Activity, BarChart2 } from "lucide-react";
import api from "@/lib/api";

interface ZTPStats {
  total_policies?: number;
  enabled_policies?: number;
  access_events_24h?: number;
  policy_type_breakdown?: Record<string, number>;
  decision_breakdown?: Record<string, number>;
}

interface ZTPCompliance {
  zt_maturity_score?: number;
  pillar_scores?: Record<string, number>;
  recommendations?: string[];
}

interface ZTPolicy {
  id: string;
  name: string;
  policy_type?: string;
  action?: string;
  enabled?: boolean;
  priority?: number;
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

const ACTION_COLOR: Record<string, string> = {
  allow: "bg-emerald-500/20 text-emerald-400",
  deny: "bg-red-500/20 text-red-400",
  mfa_required: "bg-amber-500/20 text-amber-400",
};

const TYPE_COLOR: Record<string, string> = {
  network: "bg-sky-500/20 text-sky-400",
  identity: "bg-purple-500/20 text-purple-400",
  device: "bg-orange-500/20 text-orange-400",
  application: "bg-indigo-500/20 text-indigo-400",
};

export function ZeroTrustPolicyPanel() {
  const [stats, setStats] = useState<ZTPStats | null>(null);
  const [compliance, setCompliance] = useState<ZTPCompliance | null>(null);
  const [policies, setPolicies] = useState<ZTPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<ZTPStats>("/api/v1/zero-trust-policy/stats").catch(() => null),
      api.get<ZTPCompliance>("/api/v1/zero-trust-policy/compliance").catch(() => null),
      api.get<ZTPolicy[] | { policies?: ZTPolicy[]; items?: ZTPolicy[] }>(
        "/api/v1/zero-trust-policy/policies"
      ).catch(() => null),
    ])
      .then(([statsRes, compRes, polRes]) => {
        if (cancelled) return;
        if (statsRes?.data) setStats(statsRes.data);
        if (compRes?.data) setCompliance(compRes.data);

        const raw = polRes?.data;
        const list: ZTPolicy[] = raw
          ? Array.isArray(raw)
            ? (raw as ZTPolicy[])
            : ((raw as { policies?: ZTPolicy[]; items?: ZTPolicy[] }).policies ??
               (raw as { policies?: ZTPolicy[]; items?: ZTPolicy[] }).items ??
               [])
          : [];
        setPolicies(list);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load Zero Trust policy data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

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
        <div className="h-56 rounded-xl border border-border/40 bg-muted/30" />
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
        <Lock className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No Zero Trust policies defined</p>
        <p className="text-xs opacity-70">
          Create policies via POST /api/v1/zero-trust-policy/policies to enforce Zero Trust access.
        </p>
      </div>
    );
  }

  const maturityScore = compliance?.zt_maturity_score ?? 0;
  const maturityColor =
    maturityScore >= 75 ? "text-emerald-400" :
    maturityScore >= 50 ? "text-amber-400" : "text-red-400";

  return (
    <div className="flex flex-col gap-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Policies"
          value={stats?.total_policies ?? policies.length}
          icon={Lock}
          accent="text-indigo-400"
        />
        <StatCard
          label="Enabled"
          value={stats?.enabled_policies ?? "—"}
          icon={ShieldCheck}
          accent="text-emerald-400"
        />
        <StatCard
          label="Events (24h)"
          value={stats?.access_events_24h ?? "—"}
          icon={Activity}
          accent="text-sky-400"
        />
        <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
          <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
            <BarChart2 className="h-4 w-4 text-purple-400" />
            ZT Maturity
          </div>
          <p className={`text-2xl font-bold ${maturityColor}`}>
            {maturityScore > 0 ? `${maturityScore}%` : "—"}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Policies table */}
        {policies.length > 0 && (
          <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
            <div className="px-4 py-3 border-b border-border/50">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Active Policies
              </p>
            </div>
            <div className="divide-y divide-border/30">
              {policies.slice(0, 10).map((p) => (
                <div
                  key={p.id}
                  className="flex items-center justify-between px-4 py-2.5 hover:bg-muted/20 transition-colors"
                >
                  <div className="min-w-0 flex items-center gap-2">
                    <span
                      className={`shrink-0 inline-block h-2 w-2 rounded-full ${
                        p.enabled ? "bg-emerald-400" : "bg-muted-foreground/40"
                      }`}
                    />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-foreground truncate">{p.name}</p>
                      <p className="text-xs text-muted-foreground">Priority {p.priority ?? "—"}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0 ml-2">
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${
                        TYPE_COLOR[p.policy_type ?? ""] ?? "bg-muted/40 text-muted-foreground"
                      }`}
                    >
                      {p.policy_type ?? "—"}
                    </span>
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${
                        ACTION_COLOR[p.action ?? ""] ?? "bg-muted/40 text-muted-foreground"
                      }`}
                    >
                      {p.action ?? "—"}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Compliance / recommendations */}
        {compliance && (
          <div className="flex flex-col gap-4">
            {/* Pillar scores */}
            {compliance.pillar_scores && Object.keys(compliance.pillar_scores).length > 0 && (
              <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-border/50">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    ZT Pillar Scores
                  </p>
                </div>
                <div className="divide-y divide-border/30">
                  {Object.entries(compliance.pillar_scores).map(([pillar, score]) => (
                    <div
                      key={pillar}
                      className="flex items-center justify-between px-4 py-2.5"
                    >
                      <p className="text-sm capitalize text-foreground">{pillar.replace(/_/g, " ")}</p>
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              score >= 75 ? "bg-emerald-400" :
                              score >= 50 ? "bg-amber-400" : "bg-red-400"
                            }`}
                            style={{ width: `${Math.min(100, score)}%` }}
                          />
                        </div>
                        <span className="text-xs font-medium text-muted-foreground w-8 text-right">
                          {score}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {(compliance.recommendations ?? []).length > 0 && (
              <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-border/50">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Recommendations
                  </p>
                </div>
                <ul className="divide-y divide-border/30">
                  {(compliance.recommendations ?? []).slice(0, 5).map((rec, i) => (
                    <li
                      key={i}
                      className="flex items-start gap-2 px-4 py-2.5 text-sm text-muted-foreground"
                    >
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5 text-amber-400" />
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
