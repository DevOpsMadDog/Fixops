/**
 * SecurityMaturityPanel — wires GET /api/v1/security-maturity/stats
 * and GET /api/v1/security-maturity/assessments → CMMI domain grid.
 * Used by MaturityHub "security" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BarChart2, CheckCircle2, Clock, TrendingUp } from "lucide-react";
import api from "@/lib/api";

interface MaturityStats {
  total_assessments: number;
  avg_maturity_level: number;
  domains_assessed: number;
  pending_reviews: number;
  framework?: string;
}

interface Assessment {
  id: string;
  name: string;
  framework: string;
  status: string;
  overall_score?: number;
  created_at?: string;
}

interface AssessmentsResponse {
  assessments?: Assessment[];
  items?: Assessment[];
  data?: Assessment[];
}

const LEVEL_COLOR = [
  "bg-red-500",
  "bg-orange-500",
  "bg-amber-400",
  "bg-emerald-500",
  "bg-green-600",
];

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

export function SecurityMaturityPanel() {
  const [stats, setStats] = useState<MaturityStats | null>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<MaturityStats>("/api/v1/security-maturity/stats").catch(() => null),
      api.get<AssessmentsResponse>("/api/v1/security-maturity/assessments").catch(() => null),
    ])
      .then(([statsRes, assessmentsRes]) => {
        if (cancelled) return;
        if (statsRes?.data) setStats(statsRes.data);
        const raw = assessmentsRes?.data;
        const list = raw
          ? ((raw as AssessmentsResponse).assessments ??
              (raw as AssessmentsResponse).items ??
              (Array.isArray(raw) ? (raw as Assessment[]) : []))
          : [];
        setAssessments(list);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load security maturity data");
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

  if (!stats && assessments.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <BarChart2 className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No maturity assessments yet</p>
        <p className="text-xs opacity-70">
          Create an assessment via POST /api/v1/security-maturity/assessments to populate this view.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Assessments"
          value={stats?.total_assessments ?? assessments.length}
          icon={CheckCircle2}
          accent="text-indigo-400"
        />
        <StatCard
          label="Avg. Level"
          value={
            typeof stats?.avg_maturity_level === "number"
              ? stats.avg_maturity_level.toFixed(1)
              : "—"
          }
          icon={TrendingUp}
          accent="text-sky-400"
        />
        <StatCard
          label="Domains"
          value={stats?.domains_assessed ?? "—"}
          icon={BarChart2}
          accent="text-violet-400"
        />
        <StatCard
          label="Pending Reviews"
          value={stats?.pending_reviews ?? "—"}
          icon={Clock}
          accent="text-amber-400"
        />
      </div>

      {/* Assessment table */}
      {assessments.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Recent Assessments
            </p>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/40 text-muted-foreground text-xs uppercase tracking-wider">
                <th className="px-4 py-2 text-left font-medium">Name</th>
                <th className="px-4 py-2 text-left font-medium">Framework</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                <th className="px-4 py-2 text-right font-medium">Score</th>
              </tr>
            </thead>
            <tbody>
              {assessments.slice(0, 10).map((a) => {
                const level = Math.min(5, Math.max(1, Math.round(a.overall_score ?? 1)));
                return (
                  <tr
                    key={a.id}
                    className="border-b border-border/30 last:border-0 hover:bg-muted/20 transition-colors"
                  >
                    <td className="px-4 py-2 font-medium text-foreground">{a.name}</td>
                    <td className="px-4 py-2 text-muted-foreground uppercase text-xs">
                      {a.framework}
                    </td>
                    <td className="px-4 py-2">
                      <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-muted/40 text-muted-foreground capitalize">
                        {a.status}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      {a.overall_score != null ? (
                        <span
                          className={`inline-flex items-center justify-center rounded-full w-8 h-8 text-xs font-bold text-white ${LEVEL_COLOR[level - 1] ?? "bg-slate-500"}`}
                        >
                          L{level}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
