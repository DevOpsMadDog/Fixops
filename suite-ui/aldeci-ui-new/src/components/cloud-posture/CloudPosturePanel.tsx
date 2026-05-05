/**
 * CloudPosturePanel — posture tab
 * GET /api/v1/posture-score/current + /stats + /benchmarks
 * GET /api/v1/cloud-security/accounts + /findings + /stats
 */

import { useEffect, useState } from "react";
import { Cloud, ShieldAlert, AlertCircle, CheckCircle2 } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";

interface PostureStats {
  score?: number;
  total_findings?: number;
  critical?: number;
  high?: number;
  accounts?: number;
  [key: string]: unknown;
}

interface Finding {
  id: string;
  title?: string;
  severity?: string;
  resource?: string;
  status?: string;
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

export function CloudPosturePanel() {
  const [stats, setStats] = useState<PostureStats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch("/api/v1/posture-score/stats?org_id=default").then(r => r.json()).catch(() => ({})),
      fetch("/api/v1/cloud-security/findings?org_id=default&limit=10").then(r => r.json()).catch(() => ({ items: [] })),
    ]).then(([statsData, findingsData]) => {
      if (cancelled) return;
      setStats(statsData as PostureStats);
      const raw = findingsData as { items?: Finding[] };
      setFindings(raw?.items ?? []);
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
    return (
      <EmptyState
        icon={AlertCircle}
        title="Failed to load posture data"
        description={error}
      />
    );
  }

  const score = typeof stats?.score === "number" ? stats.score : null;
  const critCount = stats?.critical ?? 0;
  const highCount = stats?.high ?? 0;
  const totalFindings = stats?.total_findings ?? findings.length;

  const SEVERITY_COLOR: Record<string, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-amber-500",
    low: "text-blue-400",
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Posture Score" value={score !== null ? `${score}` : "—"} icon={Cloud} accent="text-indigo-400" />
        <StatCard label="Total Findings" value={totalFindings} icon={ShieldAlert} accent="text-amber-400" />
        <StatCard label="Critical" value={critCount} icon={AlertCircle} accent="text-red-500" />
        <StatCard label="High" value={highCount} icon={CheckCircle2} accent="text-orange-500" />
      </div>

      {findings.length === 0 ? (
        <EmptyState
          icon={Cloud}
          title="No cloud findings"
          description="No cloud security findings for this org. Connect a cloud account to start scanning."
        />
      ) : (
        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Recent Cloud Findings</h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/40 bg-muted/30">
                <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Title</th>
                <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Severity</th>
                <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Resource</th>
                <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr key={f.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-2 font-medium truncate max-w-xs">{f.title ?? f.id}</td>
                  <td className={`px-4 py-2 capitalize font-medium ${SEVERITY_COLOR[f.severity?.toLowerCase() ?? ""] ?? "text-foreground"}`}>
                    {f.severity ?? "—"}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground truncate max-w-xs">{f.resource ?? "—"}</td>
                  <td className="px-4 py-2 capitalize text-muted-foreground">{f.status ?? "open"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
