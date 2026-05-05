/**
 * PostureMaturityPanel — wires GET /api/v1/posture-maturity/overview
 * and GET /api/v1/posture-maturity/domains → capability domain breakdown.
 * Used by MaturityHub "posture" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BarChart2, ShieldCheck, Target, CalendarClock } from "lucide-react";
import api from "@/lib/api";

interface PostureOverview {
  overall_maturity_level?: number;
  total_domains?: number;
  at_target?: number;
  overdue_reviews?: number;
  last_snapshot?: string;
}

interface DomainEntry {
  id: string;
  domain: string;
  capability?: string;
  maturity_level: number;
  max_level?: number;
  next_review?: string;
}

interface DomainsResponse {
  domains?: DomainEntry[];
  items?: DomainEntry[];
  data?: DomainEntry[];
}

const LEVEL_COLORS: Record<number, string> = {
  1: "bg-red-500",
  2: "bg-orange-500",
  3: "bg-amber-400",
  4: "bg-emerald-500",
  5: "bg-green-600",
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

function LevelBar({ level, max = 5 }: { level: number; max?: number }) {
  const pct = Math.round((level / max) * 100);
  const color = LEVEL_COLORS[Math.min(5, Math.max(1, level))] ?? "bg-slate-400";
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-2 rounded-full bg-muted/40 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs font-semibold text-foreground w-8 text-right">
        {level}/{max}
      </span>
    </div>
  );
}

export function PostureMaturityPanel() {
  const [overview, setOverview] = useState<PostureOverview | null>(null);
  const [domains, setDomains] = useState<DomainEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<PostureOverview>("/api/v1/posture-maturity/overview").catch(() => null),
      api.get<DomainsResponse>("/api/v1/posture-maturity/domains").catch(() => null),
    ])
      .then(([overviewRes, domainsRes]) => {
        if (cancelled) return;
        if (overviewRes?.data) setOverview(overviewRes.data);
        const raw = domainsRes?.data;
        const list = raw
          ? ((raw as DomainsResponse).domains ??
              (raw as DomainsResponse).items ??
              (Array.isArray(raw) ? (raw as DomainEntry[]) : []))
          : [];
        setDomains(list);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load posture maturity data");
        }
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

  if (!overview && domains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <ShieldCheck className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No posture maturity data yet</p>
        <p className="text-xs opacity-70">
          Record an assessment via POST /api/v1/posture-maturity/assessments to populate this view.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Overall Level"
          value={
            typeof overview?.overall_maturity_level === "number"
              ? `L${overview.overall_maturity_level}`
              : "—"
          }
          icon={ShieldCheck}
          accent="text-indigo-400"
        />
        <StatCard
          label="Domains"
          value={overview?.total_domains ?? domains.length}
          icon={BarChart2}
          accent="text-sky-400"
        />
        <StatCard
          label="At Target"
          value={overview?.at_target ?? "—"}
          icon={Target}
          accent="text-emerald-400"
        />
        <StatCard
          label="Overdue Reviews"
          value={overview?.overdue_reviews ?? "—"}
          icon={CalendarClock}
          accent="text-amber-400"
        />
      </div>

      {/* Domain breakdown */}
      {domains.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Domain Maturity Breakdown
            </p>
          </div>
          <div className="divide-y divide-border/30">
            {domains.slice(0, 12).map((d) => (
              <div key={d.id} className="flex items-center gap-4 px-4 py-3 hover:bg-muted/20 transition-colors">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">{d.domain}</p>
                  {d.capability && (
                    <p className="text-xs text-muted-foreground truncate">{d.capability}</p>
                  )}
                </div>
                <div className="w-40">
                  <LevelBar level={d.maturity_level} max={d.max_level ?? 5} />
                </div>
                {d.next_review && (
                  <p className="text-xs text-muted-foreground hidden sm:block w-24 text-right">
                    {new Date(d.next_review).toLocaleDateString()}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
