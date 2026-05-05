/**
 * ContainerImagePanel — Image & build scan results
 * API: GET /api/v1/containers/stats + /history + /checks
 */

import { useEffect, useState } from "react";
import { Box, RefreshCw, AlertTriangle, CheckCircle2 } from "lucide-react";
import { containerScannerApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface ScanStats {
  total_scans: number;
  passed: number;
  failed: number;
  avg_score?: number;
  critical_issues?: number;
  high_issues?: number;
}

interface ScanRecord {
  scan_id: string;
  image_name?: string;
  score?: number;
  passed?: boolean;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
  scanned_at?: string;
}

const SEVERITY_BAR: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-amber-400",
  low: "bg-blue-400",
};

export function ContainerImagePanel() {
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, histRes] = await Promise.allSettled([
        containerScannerApi.stats(),
        containerScannerApi.history(),
      ]);
      if (statsRes.status === "fulfilled") {
        const d = statsRes.value.data as ScanStats;
        setStats(d);
      }
      if (histRes.status === "fulfilled") {
        const d = histRes.value.data;
        setHistory(Array.isArray(d) ? d : (d?.scans ?? d?.history ?? []));
      }
      if (statsRes.status === "rejected" && histRes.status === "rejected") {
        throw new Error((statsRes.reason as Error).message ?? "Failed to load image scan data");
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

  if (!stats && history.length === 0) {
    return (
      <EmptyState
        icon={Box}
        title="No image scans found"
        description="Scan a Dockerfile or container image to see results here."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Scans", value: stats.total_scans ?? 0, color: "text-foreground" },
            { label: "Passed", value: stats.passed ?? 0, color: "text-green-400" },
            { label: "Failed", value: stats.failed ?? 0, color: "text-red-400" },
            { label: "Avg Score", value: stats.avg_score != null ? `${stats.avg_score.toFixed(0)}%` : "—", color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Critical/High banner */}
      {stats && ((stats.critical_issues ?? 0) > 0 || (stats.high_issues ?? 0) > 0) && (
        <div className="flex items-center gap-2 rounded-md border border-red-700 bg-red-900/20 px-3 py-2 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          {stats.critical_issues ?? 0} critical + {stats.high_issues ?? 0} high severity issues across scanned images.
        </div>
      )}

      {/* Scan history table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <Box className="h-3.5 w-3.5 text-indigo-400" />
            Scan History ({history.length})
          </h3>
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" /> Refresh
          </button>
        </div>
        {history.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">No scan records yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                {["Image", "Score", "C", "H", "M", "L", "Status", "Scanned"].map(h => (
                  <th key={h} className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.slice(0, 50).map(s => (
                <tr key={s.scan_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs max-w-[160px] truncate">{s.image_name ?? s.scan_id.slice(0, 12)}</td>
                  <td className="px-4 py-2 text-xs">{s.score != null ? `${s.score}%` : "—"}</td>
                  <td className="px-4 py-2 text-xs text-red-400">{s.critical ?? 0}</td>
                  <td className="px-4 py-2 text-xs text-orange-400">{s.high ?? 0}</td>
                  <td className="px-4 py-2 text-xs text-amber-400">{s.medium ?? 0}</td>
                  <td className="px-4 py-2 text-xs text-blue-400">{s.low ?? 0}</td>
                  <td className="px-4 py-2">
                    {s.passed
                      ? <span className="inline-flex items-center gap-1 text-xs text-green-400"><CheckCircle2 className="h-3 w-3" />Pass</span>
                      : <span className="inline-flex items-center gap-1 text-xs text-red-400"><AlertTriangle className="h-3 w-3" />Fail</span>
                    }
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {s.scanned_at ? new Date(s.scanned_at).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Severity legend */}
      <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
        {Object.entries(SEVERITY_BAR).map(([sev, cls]) => (
          <span key={sev} className="flex items-center gap-1.5">
            <span className={`inline-block w-3 h-3 rounded-sm ${cls}`} />
            {sev.charAt(0).toUpperCase() + sev.slice(1)}
          </span>
        ))}
      </div>
    </div>
  );
}
