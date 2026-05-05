/**
 * UnifiedCNAPPPanel — unified tab
 * GET /api/v1/cloud-findings/findings + /summary + /top-resources
 */

import { useEffect, useState } from "react";
import { Workflow, AlertCircle, BarChart2, TrendingUp } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";

interface FindingSummary {
  total?: number;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  open?: number;
  resolved?: number;
  [key: string]: unknown;
}

interface CloudFinding {
  finding_id: string;
  title?: string;
  severity?: string;
  resource_id?: string;
  status?: string;
  framework?: string;
}

interface TopResource {
  resource_id: string;
  finding_count?: number;
  critical_count?: number;
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

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-amber-500",
  low: "bg-blue-400",
};

const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-amber-500",
  low: "text-blue-400",
};

export function UnifiedCNAPPPanel() {
  const [summary, setSummary] = useState<FindingSummary | null>(null);
  const [findings, setFindings] = useState<CloudFinding[]>([]);
  const [topResources, setTopResources] = useState<TopResource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch("/api/v1/cloud-findings/summary?org_id=default").then(r => r.json()).catch(() => ({})),
      fetch("/api/v1/cloud-findings/findings?org_id=default&limit=10").then(r => r.json()).catch(() => ({ items: [] })),
      fetch("/api/v1/cloud-findings/top-resources?org_id=default&limit=5").then(r => r.json()).catch(() => []),
    ]).then(([sumData, findData, topData]) => {
      if (cancelled) return;
      setSummary(sumData as FindingSummary);
      const fRaw = findData as { items?: CloudFinding[] };
      setFindings(fRaw?.items ?? (Array.isArray(findData) ? (findData as CloudFinding[]) : []));
      setTopResources(Array.isArray(topData) ? (topData as TopResource[]) : []);
      setLoading(false);
    }).catch(e => {
      if (!cancelled) { setError(String(e)); setLoading(false); }
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-24 rounded-xl bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={AlertCircle} title="Failed to load CNAPP data" description={error} />;
  }

  const total = summary?.total ?? findings.length;
  const severities: Array<{ key: string; label: string; value: number }> = [
    { key: "critical", label: "Critical", value: (summary?.critical ?? 0) as number },
    { key: "high",     label: "High",     value: (summary?.high     ?? 0) as number },
    { key: "medium",   label: "Medium",   value: (summary?.medium   ?? 0) as number },
    { key: "low",      label: "Low",      value: (summary?.low      ?? 0) as number },
  ];
  const maxSev = Math.max(...severities.map(s => s.value), 1);

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Findings" value={total} icon={Workflow} accent="text-indigo-400" />
        <StatCard label="Open" value={summary?.open ?? "—"} icon={AlertCircle} accent="text-red-500" />
        <StatCard label="Resolved" value={summary?.resolved ?? "—"} icon={BarChart2} accent="text-green-500" />
        <StatCard label="Critical" value={summary?.critical ?? "—"} icon={TrendingUp} accent="text-orange-500" />
      </div>

      {/* Severity bar chart */}
      <div className="rounded-xl border border-border/60 bg-card p-4">
        <h3 className="text-sm font-semibold mb-4">Severity Distribution</h3>
        <div className="flex flex-col gap-3">
          {severities.map(s => (
            <div key={s.key} className="flex items-center gap-3">
              <span className={`text-xs font-medium w-14 ${SEVERITY_TEXT[s.key]}`}>{s.label}</span>
              <div className="flex-1 h-2 bg-muted/40 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${SEVERITY_COLOR[s.key]} transition-all duration-500`}
                  style={{ width: `${(s.value / maxSev) * 100}%` }}
                />
              </div>
              <span className="text-xs text-muted-foreground w-8 text-right">{s.value}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Findings table */}
        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Latest Cloud Findings</h3>
          </div>
          {findings.length === 0 ? (
            <EmptyState icon={Workflow} title="No findings" description="No cross-pillar CNAPP findings yet." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Title</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Severity</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(f => (
                  <tr key={f.finding_id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 font-medium truncate max-w-[180px]">{f.title ?? f.finding_id}</td>
                    <td className={`px-4 py-2 capitalize font-medium ${SEVERITY_TEXT[f.severity?.toLowerCase() ?? ""] ?? "text-foreground"}`}>
                      {f.severity ?? "—"}
                    </td>
                    <td className="px-4 py-2 capitalize text-muted-foreground">{f.status ?? "open"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Top resources */}
        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Top Affected Resources</h3>
          </div>
          {topResources.length === 0 ? (
            <EmptyState icon={BarChart2} title="No resource data" description="No resources with findings yet." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Resource</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Findings</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Critical</th>
                </tr>
              </thead>
              <tbody>
                {topResources.map(r => (
                  <tr key={r.resource_id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 font-medium truncate max-w-[180px]">{r.resource_id}</td>
                    <td className="px-4 py-2 text-muted-foreground">{r.finding_count ?? "—"}</td>
                    <td className="px-4 py-2 text-red-500 font-medium">{r.critical_count ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
