/**
 * DigitalForensicsPanel — wires GET /api/v1/digital-forensics/cases + /stats
 * Used by ForensicsHub "digital" tab.
 */

import { useEffect, useState } from "react";
import { ScanSearch, AlertTriangle, Clock, CheckCircle2, FolderOpen } from "lucide-react";
import { digitalForensicsApi } from "@/lib/api";

interface ForensicCase {
  id: string;
  title: string;
  case_type: string;
  priority: string;
  status: string;
  assigned_analyst: string;
  related_incident_id?: string;
  created_at?: string;
  updated_at?: string;
}

interface ForensicsStats {
  total_cases: number;
  open_cases: number;
  closed_cases: number;
  critical_cases?: number;
}

const PRIORITY_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/15",
  high: "text-orange-400 bg-orange-500/15",
  medium: "text-amber-400 bg-amber-500/15",
  low: "text-green-400 bg-green-500/15",
};

const STATUS_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  open: AlertTriangle,
  in_progress: Clock,
  closed: CheckCircle2,
};

function StatBadge({ label, value, accent }: { label: string; value: number | string; accent?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-xl border border-border/60 bg-card p-4 shadow-sm min-w-[110px]">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold ${accent ?? "text-foreground"}`}>{value}</p>
    </div>
  );
}

export function DigitalForensicsPanel() {
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [stats, setStats] = useState<ForensicsStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([digitalForensicsApi.listCases(), digitalForensicsApi.stats()])
      .then(([casesRes, statsRes]) => {
        if (cancelled) return;
        const raw = casesRes.data;
        setCases(Array.isArray(raw) ? raw : (raw?.cases ?? raw?.items ?? []));
        setStats(statsRes.data ?? null);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load forensic cases");
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="space-y-3 pt-2">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-12 animate-pulse rounded-lg bg-muted/40" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
        {error}
      </div>
    );
  }

  const openCount = stats?.open_cases ?? cases.filter(c => c.status === "open" || c.status === "in_progress").length;
  const closedCount = stats?.closed_cases ?? cases.filter(c => c.status === "closed").length;

  return (
    <div className="flex flex-col gap-6 pt-2">
      {/* Stats row */}
      <div className="flex flex-wrap gap-3">
        <StatBadge label="Total Cases" value={stats?.total_cases ?? cases.length} />
        <StatBadge label="Open" value={openCount} accent="text-amber-400" />
        <StatBadge label="Closed" value={closedCount} accent="text-green-400" />
        {(stats?.critical_cases ?? 0) > 0 && (
          <StatBadge label="Critical" value={stats!.critical_cases!} accent="text-red-400" />
        )}
      </div>

      {/* Cases table */}
      {cases.length === 0 ? (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-border/60 py-12 text-center">
          <FolderOpen className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">No forensic cases</p>
          <p className="text-xs text-muted-foreground/60">
            Cases are created automatically when incidents are escalated for forensic analysis.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border/60">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 bg-muted/20">
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Title</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Type</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Priority</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Status</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Analyst</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {cases.map(c => {
                const StatusIcon = STATUS_ICON[c.status] ?? ScanSearch;
                const priorityClass = PRIORITY_COLOR[c.priority] ?? "text-muted-foreground bg-muted/20";
                return (
                  <tr key={c.id} className="hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-3 font-medium text-foreground max-w-[200px] truncate" title={c.title}>
                      {c.title}
                    </td>
                    <td className="px-4 py-3 text-muted-foreground capitalize">
                      {c.case_type.replace(/_/g, " ")}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${priorityClass}`}>
                        {c.priority}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground capitalize">
                        <StatusIcon className="h-3.5 w-3.5" />
                        {c.status.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {c.assigned_analyst || "Unassigned"}
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
