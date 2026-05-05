/**
 * PostureBenchmarkingPanel — wires GET /api/v1/posture-benchmarking/stats
 * and GET /api/v1/posture-benchmarking/benchmarks → framework benchmark table.
 * Used by PostureMetricsHub "benchmarking" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BarChart2, CheckCircle2, Target, TrendingUp } from "lucide-react";
import api from "@/lib/api";

interface BenchmarkingStats {
  total_benchmarks?: number;
  active_benchmarks?: number;
  avg_score?: number;
  avg_industry_avg?: number;
  avg_percentile?: number;
}

interface Benchmark {
  id: string;
  benchmark_name?: string;
  framework?: string;
  category?: string;
  score?: number;
  industry_avg_score?: number;
  percentile?: number;
  status?: string;
  total_controls?: number;
}

interface BenchmarksResponse {
  benchmarks?: Benchmark[];
  items?: Benchmark[];
  data?: Benchmark[];
  source?: string;
}

const FRAMEWORK_COLORS: Record<string, string> = {
  cis: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  nist: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  soc2: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  pci_dss: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  iso27001: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  hipaa: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  custom: "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

function frameworkBadge(framework?: string): string {
  return FRAMEWORK_COLORS[framework?.toLowerCase() ?? ""] ?? "bg-slate-500/15 text-slate-400 border-slate-500/30";
}

function ScoreBar({ score, industry }: { score: number; industry: number }) {
  const clamp = (v: number) => Math.max(0, Math.min(100, v));
  return (
    <div className="flex flex-col gap-1 w-full">
      <div className="flex items-center gap-2">
        <div className="flex-1 h-2 rounded-full bg-muted/40 overflow-hidden">
          <div
            className="h-full rounded-full bg-indigo-500 transition-all duration-500"
            style={{ width: `${clamp(score)}%` }}
          />
        </div>
        <span className="text-xs font-semibold text-foreground w-8 text-right">{Math.round(score)}</span>
      </div>
      {industry > 0 && (
        <div className="flex items-center gap-2">
          <div className="flex-1 h-1 rounded-full bg-muted/20 overflow-hidden">
            <div
              className="h-full rounded-full bg-amber-400/60 transition-all duration-500"
              style={{ width: `${clamp(industry)}%` }}
            />
          </div>
          <span className="text-xs text-muted-foreground w-8 text-right">{Math.round(industry)}</span>
        </div>
      )}
    </div>
  );
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

export function PostureBenchmarkingPanel() {
  const [stats, setStats] = useState<BenchmarkingStats | null>(null);
  const [benchmarks, setBenchmarks] = useState<Benchmark[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<BenchmarkingStats>("/api/v1/posture-benchmarking/stats").catch(() => null),
      api.get<BenchmarksResponse>("/api/v1/posture-benchmarking/benchmarks").catch(() => null),
    ])
      .then(([statsRes, benchRes]) => {
        if (cancelled) return;
        if (statsRes?.data) setStats(statsRes.data);
        const raw = benchRes?.data;
        const list: Benchmark[] = raw
          ? ((raw as BenchmarksResponse).benchmarks ??
              (raw as BenchmarksResponse).items ??
              (Array.isArray(raw) ? (raw as Benchmark[]) : []))
          : [];
        setBenchmarks(list);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load benchmarking data");
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

  if (!stats && benchmarks.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <BarChart2 className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No benchmarks yet</p>
        <p className="text-xs opacity-70">
          Create a benchmark via POST /api/v1/posture-benchmarking/benchmarks to populate this view.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Benchmarks" value={stats?.total_benchmarks ?? benchmarks.length} icon={BarChart2} accent="text-indigo-400" />
        <StatCard label="Active" value={stats?.active_benchmarks ?? "—"} icon={CheckCircle2} accent="text-emerald-400" />
        <StatCard label="Avg Score" value={typeof stats?.avg_score === "number" ? `${Math.round(stats.avg_score)}%` : "—"} icon={Target} accent="text-sky-400" />
        <StatCard label="Avg Percentile" value={typeof stats?.avg_percentile === "number" ? `P${Math.round(stats.avg_percentile)}` : "—"} icon={TrendingUp} accent="text-amber-400" />
      </div>

      {benchmarks.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50 flex items-center justify-between">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Framework Benchmarks
            </p>
            <span className="text-xs text-muted-foreground">
              <span className="inline-block w-2 h-2 rounded-full bg-indigo-500 mr-1" />Our score
              <span className="inline-block w-2 h-2 rounded-full bg-amber-400/60 ml-3 mr-1" />Industry avg
            </span>
          </div>
          <div className="divide-y divide-border/30">
            {benchmarks.slice(0, 15).map((b) => (
              <div key={b.id} className="grid grid-cols-[1fr_auto_auto_160px] items-center gap-4 px-4 py-3 hover:bg-muted/20 transition-colors">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground truncate">
                    {b.benchmark_name ?? b.id}
                  </p>
                  {b.category && (
                    <p className="text-xs text-muted-foreground capitalize">{b.category}</p>
                  )}
                </div>
                {b.framework && (
                  <span className={`text-xs font-medium px-2 py-0.5 rounded-full border uppercase ${frameworkBadge(b.framework)}`}>
                    {b.framework}
                  </span>
                )}
                {typeof b.percentile === "number" && (
                  <span className="text-xs text-muted-foreground hidden sm:block">P{b.percentile}</span>
                )}
                <ScoreBar score={b.score ?? 0} industry={b.industry_avg_score ?? 0} />
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
