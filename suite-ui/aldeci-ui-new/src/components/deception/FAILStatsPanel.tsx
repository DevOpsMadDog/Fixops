/**
 * FAILStatsPanel — wires GET /api/v1/fail/ → stat-card grid + grade bar.
 * Used by DeceptionHub "engine" tab (first slot).
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BarChart2, CheckCircle2, Flame } from "lucide-react";
import { failApi } from "@/lib/api";

interface GradeDistribution {
  [grade: string]: number;
}

interface FAILStats {
  total_scored: number;
  average_score: number;
  critical_count: number;
  high_count: number;
  grade_distribution: GradeDistribution;
}

const GRADE_ORDER = ["A", "B", "C", "D", "F"];
const GRADE_COLOR: Record<string, string> = {
  A: "bg-green-500",
  B: "bg-emerald-400",
  C: "bg-amber-400",
  D: "bg-orange-500",
  F: "bg-red-600",
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

export function FAILStatsPanel() {
  const [stats, setStats] = useState<FAILStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    failApi
      .stats("default")
      .then((res) => {
        if (!cancelled) {
          const d = res.data as FAILStats;
          setStats(d);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          const msg =
            err instanceof Error ? err.message : "Failed to load FAIL stats";
          setError(msg);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 animate-pulse">
        {[...Array(4)].map((_, i) => (
          <div
            key={i}
            className="h-24 rounded-xl border border-border/40 bg-muted/30"
          />
        ))}
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

  if (!stats || stats.total_scored === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <BarChart2 className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No FAIL drills scored yet</p>
        <p className="text-xs opacity-70">
          Run a drill via the inject endpoint to see graded results here.
        </p>
      </div>
    );
  }

  const maxGradeCount = Math.max(
    ...GRADE_ORDER.map((g) => stats.grade_distribution[g] ?? 0),
    1,
  );

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Total Scored"
          value={stats.total_scored}
          icon={CheckCircle2}
          accent="text-indigo-400"
        />
        <StatCard
          label="Average Score"
          value={
            typeof stats.average_score === "number"
              ? stats.average_score.toFixed(1)
              : stats.average_score
          }
          icon={BarChart2}
          accent="text-sky-400"
        />
        <StatCard
          label="Critical"
          value={stats.critical_count}
          icon={Flame}
          accent="text-red-500"
        />
        <StatCard
          label="High"
          value={stats.high_count}
          icon={AlertTriangle}
          accent="text-orange-400"
        />
      </div>

      {/* Grade distribution */}
      <div className="rounded-xl border border-border/60 bg-card p-4 shadow-sm">
        <p className="mb-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Grade Distribution
        </p>
        <div className="flex items-end gap-3">
          {GRADE_ORDER.map((grade) => {
            const count = stats.grade_distribution[grade] ?? 0;
            const pct = Math.round((count / maxGradeCount) * 100);
            return (
              <div
                key={grade}
                className="flex flex-1 flex-col items-center gap-1"
              >
                <span className="text-xs font-semibold text-foreground">
                  {count}
                </span>
                <div className="w-full rounded-sm bg-muted/40" style={{ height: 80 }}>
                  <div
                    className={`w-full rounded-sm transition-all duration-500 ${GRADE_COLOR[grade] ?? "bg-slate-400"}`}
                    style={{ height: `${pct}%`, marginTop: `${100 - pct}%` }}
                  />
                </div>
                <span className="text-xs font-bold text-muted-foreground">
                  {grade}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
