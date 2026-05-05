/**
 * ContainerRuntimePanel — Live runtime threat monitoring via CWPP
 * API: GET /api/v1/cwpp/summary + /workloads + /threats
 */

import { useEffect, useState } from "react";
import { Activity, RefreshCw, ShieldAlert, Server } from "lucide-react";
import { cwppApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface CWPPSummary {
  total_workloads: number;
  protected: number;
  unprotected: number;
  threats_detected: number;
  compliant: number;
}

interface Workload {
  workload_id: string;
  name?: string;
  type?: string;
  status?: string;
  threat_count?: number;
  org_id?: string;
}

interface ThreatEvent {
  event_id?: string;
  workload_id?: string;
  threat_type?: string;
  severity?: string;
  detected_at?: string;
  description?: string;
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

export function ContainerRuntimePanel() {
  const [summary, setSummary] = useState<CWPPSummary | null>(null);
  const [workloads, setWorkloads] = useState<Workload[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sumRes, wlRes, thRes] = await Promise.allSettled([
        cwppApi.summary(),
        cwppApi.workloads(),
        cwppApi.threats(),
      ]);
      if (sumRes.status === "fulfilled") setSummary(sumRes.value.data as CWPPSummary);
      if (wlRes.status === "fulfilled") {
        const d = wlRes.value.data;
        setWorkloads(Array.isArray(d) ? d : (d?.workloads ?? []));
      }
      if (thRes.status === "fulfilled") {
        const d = thRes.value.data;
        setThreats(Array.isArray(d) ? d : (d?.threats ?? d?.events ?? []));
      }
      if (sumRes.status === "rejected" && wlRes.status === "rejected") {
        throw new Error((sumRes.reason as Error).message ?? "Failed to load runtime data");
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
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="h-10 rounded bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  if (!summary && workloads.length === 0) {
    return (
      <EmptyState
        icon={Activity}
        title="No runtime data"
        description="No container workloads are registered for protection. Register a workload to start monitoring."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary stats */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "Total Workloads", value: summary.total_workloads ?? 0, color: "text-foreground" },
            { label: "Protected", value: summary.protected ?? 0, color: "text-green-400" },
            { label: "Unprotected", value: summary.unprotected ?? 0, color: "text-red-400" },
            { label: "Threats", value: summary.threats_detected ?? 0, color: "text-orange-400" },
            { label: "Compliant", value: summary.compliant ?? 0, color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Workloads table */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Server className="h-3.5 w-3.5 text-indigo-400" />
              Workloads ({workloads.length})
            </h3>
            <button onClick={load} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <RefreshCw className="h-3 w-3" /> Refresh
            </button>
          </div>
          {workloads.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No workloads registered.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/10">
                  {["Name", "Type", "Status", "Threats"].map(h => (
                    <th key={h} className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {workloads.slice(0, 25).map(w => (
                  <tr key={w.workload_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2 text-xs font-mono">{w.name ?? w.workload_id.slice(0, 10)}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{w.type ?? "—"}</td>
                    <td className="px-4 py-2 text-xs">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${w.status === "protected" ? "bg-green-700 text-green-100" : "bg-red-700 text-red-100"}`}>
                        {w.status ?? "unknown"}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-orange-400">{w.threat_count ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Threat events */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
              Recent Threats ({threats.length})
            </h3>
          </div>
          {threats.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No threat events detected.</p>
          ) : (
            <div className="divide-y divide-border/50">
              {threats.slice(0, 20).map((t, idx) => (
                <div key={t.event_id ?? idx} className="px-4 py-2.5 hover:bg-muted/10 transition-colors">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium">{t.threat_type ?? "Unknown threat"}</span>
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${sevClass(t.severity)}`}>
                      {t.severity ?? "—"}
                    </span>
                  </div>
                  {t.description && (
                    <p className="text-xs text-muted-foreground mt-0.5 truncate">{t.description}</p>
                  )}
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {t.detected_at ? new Date(t.detected_at).toLocaleString() : ""}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
