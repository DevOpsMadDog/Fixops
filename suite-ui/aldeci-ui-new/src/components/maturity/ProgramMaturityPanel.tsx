/**
 * ProgramMaturityPanel — wires GET /api/v1/program-maturity/domains
 * and GET /api/v1/program-maturity/summary → governance domain rollup.
 * Used by MaturityHub "program" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Layers, CheckCircle2, Clock, TrendingUp } from "lucide-react";
import api from "@/lib/api";

interface ProgramSummary {
  total_domains?: number;
  avg_maturity?: number;
  completed_assessments?: number;
  pending_improvements?: number;
}

interface ProgramDomain {
  id: string;
  domain_name: string;
  domain_type?: string;
  target_level?: number;
  current_level?: number;
  status?: string;
}

interface DomainsResponse {
  domains?: ProgramDomain[];
  items?: ProgramDomain[];
  data?: ProgramDomain[];
}

const TYPE_BADGE: Record<string, string> = {
  governance: "bg-indigo-500/20 text-indigo-400",
  operations: "bg-sky-500/20 text-sky-400",
  technical: "bg-violet-500/20 text-violet-400",
  compliance: "bg-amber-500/20 text-amber-400",
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

function MaturityBar({ current = 0, target = 3 }: { current?: number; target?: number }) {
  const max = Math.max(target, current, 5);
  return (
    <div className="flex items-center gap-1.5 w-32">
      {[...Array(max)].map((_, i) => (
        <div
          key={i}
          className={`flex-1 h-2 rounded-sm transition-colors ${
            i < current
              ? "bg-indigo-500"
              : i < target
              ? "bg-muted/60 border border-dashed border-indigo-400/40"
              : "bg-muted/30"
          }`}
        />
      ))}
    </div>
  );
}

export function ProgramMaturityPanel() {
  const [summary, setSummary] = useState<ProgramSummary | null>(null);
  const [domains, setDomains] = useState<ProgramDomain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<ProgramSummary>("/api/v1/program-maturity/summary").catch(() => null),
      api.get<DomainsResponse>("/api/v1/program-maturity/domains").catch(() => null),
    ])
      .then(([summaryRes, domainsRes]) => {
        if (cancelled) return;
        if (summaryRes?.data) setSummary(summaryRes.data);
        const raw = domainsRes?.data;
        const list = raw
          ? ((raw as DomainsResponse).domains ??
              (raw as DomainsResponse).items ??
              (Array.isArray(raw) ? (raw as ProgramDomain[]) : []))
          : [];
        setDomains(list);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load program maturity data");
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

  if (!summary && domains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Layers className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No program maturity domains registered</p>
        <p className="text-xs opacity-70">
          Register a domain via POST /api/v1/program-maturity/domains to begin maturity tracking.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Domains"
          value={summary?.total_domains ?? domains.length}
          icon={Layers}
          accent="text-indigo-400"
        />
        <StatCard
          label="Avg. Maturity"
          value={
            typeof summary?.avg_maturity === "number"
              ? summary.avg_maturity.toFixed(1)
              : "—"
          }
          icon={TrendingUp}
          accent="text-sky-400"
        />
        <StatCard
          label="Completed"
          value={summary?.completed_assessments ?? "—"}
          icon={CheckCircle2}
          accent="text-emerald-400"
        />
        <StatCard
          label="Pending Improvements"
          value={summary?.pending_improvements ?? "—"}
          icon={Clock}
          accent="text-amber-400"
        />
      </div>

      {/* Domain table */}
      {domains.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Program Domains
            </p>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/40 text-muted-foreground text-xs uppercase tracking-wider">
                <th className="px-4 py-2 text-left font-medium">Domain</th>
                <th className="px-4 py-2 text-left font-medium">Type</th>
                <th className="px-4 py-2 text-left font-medium">Progress</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {domains.slice(0, 12).map((d) => (
                <tr
                  key={d.id}
                  className="border-b border-border/30 last:border-0 hover:bg-muted/20 transition-colors"
                >
                  <td className="px-4 py-2 font-medium text-foreground">{d.domain_name}</td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                        TYPE_BADGE[d.domain_type ?? ""] ?? "bg-muted/40 text-muted-foreground"
                      }`}
                    >
                      {d.domain_type ?? "—"}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <MaturityBar current={d.current_level} target={d.target_level} />
                  </td>
                  <td className="px-4 py-2">
                    <span className="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-muted/40 text-muted-foreground capitalize">
                      {d.status ?? "active"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
