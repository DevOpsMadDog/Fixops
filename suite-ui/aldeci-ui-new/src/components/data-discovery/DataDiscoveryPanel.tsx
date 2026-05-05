/**
 * DataDiscoveryPanel — Datastore discovery and DSPM overview
 * API: GET /api/v1/data-discovery/stats + /datastores + /scans
 */

import { useEffect, useState } from "react";
import { Database, RefreshCw, Search, AlertTriangle } from "lucide-react";
import { dataDiscoveryApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface DiscoveryStats {
  total_datastores: number;
  scanned: number;
  sensitive_count: number;
  unscanned: number;
  scan_coverage?: number;
  last_scan_at?: string;
}

interface Datastore {
  datastore_id: string;
  name?: string;
  type?: string;
  location?: string;
  sensitivity?: string;
  status?: string;
  record_count?: number;
  last_scanned?: string;
}

interface ScanJob {
  job_id: string;
  datastore_id?: string;
  status?: string;
  progress?: number;
  started_at?: string;
  completed_at?: string;
}

const SENS_COLOR: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
  none: "bg-gray-700 text-gray-300",
};

function sensClass(s?: string): string {
  return SENS_COLOR[(s ?? "none").toLowerCase()] ?? SENS_COLOR.none;
}

export function DataDiscoveryPanel() {
  const [stats, setStats] = useState<DiscoveryStats | null>(null);
  const [datastores, setDatastores] = useState<Datastore[]>([]);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, dsRes, scanRes] = await Promise.allSettled([
        dataDiscoveryApi.stats(),
        dataDiscoveryApi.datastores(),
        dataDiscoveryApi.scans(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as DiscoveryStats);
      if (dsRes.status === "fulfilled") {
        const d = dsRes.value.data;
        setDatastores(Array.isArray(d) ? d : (d?.datastores ?? []));
      }
      if (scanRes.status === "fulfilled") {
        const d = scanRes.value.data;
        setScans(Array.isArray(d) ? d : (d?.scans ?? d?.jobs ?? []));
      }
      if (statsRes.status === "rejected" && dsRes.status === "rejected") {
        throw new Error((statsRes.reason as Error).message ?? "Failed to load discovery data");
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

  if (!stats && datastores.length === 0) {
    return (
      <EmptyState
        icon={Database}
        title="No datastores discovered"
        description="No datastores have been registered or scanned yet. Register a datastore to begin DSPM coverage."
      />
    );
  }

  const coverage = stats?.scan_coverage ?? (stats && stats.total_datastores > 0
    ? Math.round((stats.scanned / stats.total_datastores) * 100)
    : null);

  return (
    <div className="space-y-6">
      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Datastores", value: stats.total_datastores ?? 0, color: "text-foreground" },
            { label: "Scanned", value: stats.scanned ?? 0, color: "text-green-400" },
            { label: "Sensitive", value: stats.sensitive_count ?? 0, color: "text-red-400" },
            { label: "Coverage", value: coverage != null ? `${coverage}%` : "—", color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Unscanned warning */}
      {stats && (stats.unscanned ?? 0) > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-amber-700 bg-amber-900/20 px-3 py-2 text-sm text-amber-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          {stats.unscanned} datastore{stats.unscanned > 1 ? "s" : ""} not yet scanned — schedule a scan to complete DSPM coverage.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Datastores table */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Database className="h-3.5 w-3.5 text-indigo-400" />
              Datastores ({datastores.length})
            </h3>
            <button onClick={load} className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
              <RefreshCw className="h-3 w-3" /> Refresh
            </button>
          </div>
          {datastores.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No datastores registered.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/10">
                  {["Name", "Type", "Location", "Sensitivity", "Records"].map(h => (
                    <th key={h} className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {datastores.slice(0, 30).map(ds => (
                  <tr key={ds.datastore_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2 text-xs font-medium truncate max-w-[120px]">{ds.name ?? ds.datastore_id.slice(0, 10)}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{ds.type ?? "—"}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[100px]">{ds.location ?? "—"}</td>
                    <td className="px-4 py-2">
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${sensClass(ds.sensitivity)}`}>
                        {ds.sensitivity ?? "—"}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{ds.record_count?.toLocaleString() ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Scan jobs */}
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Search className="h-3.5 w-3.5 text-indigo-400" />
              Recent Scans ({scans.length})
            </h3>
          </div>
          {scans.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-6">No scan jobs recorded.</p>
          ) : (
            <div className="divide-y divide-border/50">
              {scans.slice(0, 20).map((s, idx) => (
                <div key={s.job_id ?? idx} className="px-4 py-2.5 hover:bg-muted/10 transition-colors">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono">{s.job_id?.slice(0, 12) ?? "—"}</span>
                    <span className={`text-xs font-medium ${s.status === "completed" ? "text-green-400" : s.status === "running" ? "text-amber-400" : "text-muted-foreground"}`}>
                      {s.status ?? "unknown"}
                    </span>
                  </div>
                  {s.progress != null && s.status === "running" && (
                    <div className="mt-1.5 h-1.5 rounded-full bg-muted overflow-hidden">
                      <div className="h-full bg-indigo-500 rounded-full transition-all" style={{ width: `${s.progress}%` }} />
                    </div>
                  )}
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {s.started_at ? new Date(s.started_at).toLocaleString() : ""}
                    {s.completed_at ? ` → ${new Date(s.completed_at).toLocaleString()}` : ""}
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
