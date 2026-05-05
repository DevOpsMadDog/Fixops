/**
 * SecretsDetectionPanel — Live secrets inventory from /api/v1/secrets/
 * Shows active detected secrets with type, severity, location, and rotation status.
 */

import { useEffect, useState } from "react";
import { Key, RefreshCw, AlertTriangle, CheckCircle, XCircle } from "lucide-react";
import { secretsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface DetectedSecret {
  id: string;
  secret_type: string;
  file_path: string;
  severity: string;
  status: string;
  commit_sha?: string;
  author?: string;
  detected_at?: string;
  is_rotated?: boolean;
  is_false_positive?: boolean;
}

interface RotationStatus {
  org_id: string;
  total: number;
  active: number;
  rotated: number;
  false_positive: number;
  rotation_rate: number;
}

interface SecretsRoot {
  items: DetectedSecret[];
  total: number;
  rotation_status: RotationStatus;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-slate-600 text-slate-200",
};

const STATUS_COLORS: Record<string, string> = {
  active: "bg-red-800 text-red-200",
  rotated: "bg-green-800 text-green-200",
  false_positive: "bg-slate-700 text-slate-300",
};

function sevClass(s: string) {
  return SEVERITY_COLORS[s?.toLowerCase()] ?? SEVERITY_COLORS.low;
}
function statusClass(s: string) {
  return STATUS_COLORS[s?.toLowerCase()] ?? STATUS_COLORS.active;
}

export function SecretsDetectionPanel() {
  const [data, setData] = useState<SecretsRoot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await secretsApi.root();
      setData(res.data as SecretsRoot);
    } catch (e) {
      setError((e as Error).message ?? "Failed to load secrets");
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

  if (!data || data.total === 0) {
    return (
      <EmptyState
        icon={CheckCircle}
        title="No secrets detected"
        description="No hardcoded secrets found. Keep scanning regularly."
      />
    );
  }

  const { items, total, rotation_status: rs } = data;

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Total Detected", value: total, color: "text-foreground" },
          { label: "Active (Unrotated)", value: rs?.active ?? 0, color: "text-red-400" },
          { label: "Rotated", value: rs?.rotated ?? 0, color: "text-green-400" },
          { label: "False Positives", value: rs?.false_positive ?? 0, color: "text-muted-foreground" },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Rotation rate */}
      {rs && rs.total > 0 && (
        <div className={`flex items-center gap-2 rounded-md border px-3 py-2 text-sm ${rs.rotation_rate >= 80 ? "border-green-700 bg-green-900/20 text-green-300" : "border-amber-700 bg-amber-900/20 text-amber-300"}`}>
          {rs.rotation_rate >= 80 ? <CheckCircle className="h-4 w-4 flex-shrink-0" /> : <AlertTriangle className="h-4 w-4 flex-shrink-0" />}
          Rotation rate: {rs.rotation_rate.toFixed(1)}% — {rs.active} secret{rs.active !== 1 ? "s" : ""} still unrotated.
        </div>
      )}

      {/* Secrets table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <Key className="h-3.5 w-3.5 text-red-400" />
            Detected Secrets ({items.length}{total > items.length ? ` of ${total}` : ""})
          </h3>
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/10">
              <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Type</th>
              <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">File</th>
              <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Severity</th>
              <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Status</th>
              <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Author</th>
              <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Detected</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {items.slice(0, 50).map((s) => {
              const statusKey = s.is_false_positive ? "false_positive" : s.is_rotated ? "rotated" : "active";
              return (
                <tr key={s.id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 text-xs font-mono">{s.secret_type}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[200px]" title={s.file_path}>
                    {s.file_path}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${sevClass(s.severity)}`}>
                      {s.severity ?? "unknown"}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${statusClass(statusKey)}`}>
                      {statusKey}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{s.author ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {s.detected_at ? new Date(s.detected_at).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-4 py-2">
                    {statusKey === "active" && (
                      <button
                        title="Mark as false positive"
                        className="text-muted-foreground hover:text-amber-400 transition-colors"
                        onClick={() =>
                          secretsApi.markFalsePositive(s.id).then(load)
                        }
                      >
                        <XCircle className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
