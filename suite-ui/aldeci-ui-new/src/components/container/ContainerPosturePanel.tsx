/**
 * ContainerPosturePanel — Kubernetes cluster posture
 * API: GET /api/v1/container-posture/stats + /clusters + /findings
 */

import { useEffect, useState } from "react";
import { ShieldAlert, RefreshCw, AlertTriangle, CheckCircle2 } from "lucide-react";
import { containerPostureApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface PostureStats {
  total_clusters: number;
  healthy: number;
  at_risk: number;
  critical_findings: number;
  high_findings: number;
  compliance_score?: number;
}

interface Cluster {
  cluster_id: string;
  name?: string;
  environment?: string;
  status?: string;
  finding_count?: number;
  score?: number;
  registered_at?: string;
}

interface PostureFinding {
  finding_id: string;
  cluster_id?: string;
  check_name?: string;
  severity?: string;
  status?: string;
  description?: string;
  detected_at?: string;
}

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
};

function sevClass(s?: string): string {
  return SEV_COLOR[(s ?? "").toLowerCase()] ?? "bg-gray-700 text-gray-300";
}

export function ContainerPosturePanel() {
  const [stats, setStats] = useState<PostureStats | null>(null);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [findings, setFindings] = useState<PostureFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, clsRes, fndRes] = await Promise.allSettled([
        containerPostureApi.stats(),
        containerPostureApi.clusters(),
        containerPostureApi.findings(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as PostureStats);
      if (clsRes.status === "fulfilled") {
        const d = clsRes.value.data;
        setClusters(Array.isArray(d) ? d : (d?.clusters ?? []));
      }
      if (fndRes.status === "fulfilled") {
        const d = fndRes.value.data;
        setFindings(Array.isArray(d) ? d : (d?.findings ?? []));
      }
      if (statsRes.status === "rejected" && clsRes.status === "rejected") {
        throw new Error((statsRes.reason as Error).message ?? "Failed to load posture data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-10 rounded bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  if (!stats && clusters.length === 0) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No clusters registered"
        description="Register a Kubernetes cluster to start posture assessment."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Clusters", value: stats.total_clusters ?? 0, color: "text-foreground" },
            { label: "Healthy", value: stats.healthy ?? 0, color: "text-green-400" },
            { label: "At Risk", value: stats.at_risk ?? 0, color: "text-red-400" },
            { label: "Compliance Score", value: stats.compliance_score != null ? `${stats.compliance_score.toFixed(0)}%` : "—", color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Critical/High banner */}
      {stats && ((stats.critical_findings ?? 0) > 0) && (
        <div className="flex items-center gap-2 rounded-md border border-red-700 bg-red-900/20 px-3 py-2 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          {stats.critical_findings} critical findings across registered clusters — remediate immediately.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Cluster table */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-indigo-400" />
              Clusters ({clusters.length})
            </h3>
            <button onClick={load} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <RefreshCw className="h-3 w-3" /> Refresh
            </button>
          </div>
          {clusters.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No clusters found.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/10">
                  {["Cluster", "Env", "Score", "Findings", "Status"].map(h => (
                    <th key={h} className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {clusters.slice(0, 25).map(c => (
                  <tr key={c.cluster_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2 text-xs font-mono">{c.name ?? c.cluster_id.slice(0, 12)}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{c.environment ?? "—"}</td>
                    <td className="px-4 py-2 text-xs">{c.score != null ? `${c.score}%` : "—"}</td>
                    <td className="px-4 py-2 text-xs text-red-400">{c.finding_count ?? 0}</td>
                    <td className="px-4 py-2">
                      {c.status === "healthy"
                        ? <span className="inline-flex items-center gap-1 text-xs text-green-400"><CheckCircle2 className="h-3 w-3" />Healthy</span>
                        : <span className="inline-flex items-center gap-1 text-xs text-red-400"><AlertTriangle className="h-3 w-3" />{c.status ?? "unknown"}</span>
                      }
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Findings list */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium">Recent Findings ({findings.length})</h3>
          </div>
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No findings recorded.</p>
          ) : (
            <div className="divide-y divide-border/50 max-h-80 overflow-y-auto">
              {findings.slice(0, 30).map((f, idx) => (
                <div key={f.finding_id ?? idx} className="px-4 py-2.5 hover:bg-muted/10 transition-colors">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium truncate">{f.check_name ?? "Unnamed check"}</span>
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium flex-shrink-0 ${sevClass(f.severity)}`}>
                      {f.severity ?? "—"}
                    </span>
                  </div>
                  {f.description && (
                    <p className="text-xs text-muted-foreground mt-0.5 truncate">{f.description}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
