/**
 * SecretScannerPanel — Regex-based secret scanner dashboard
 * API: GET /api/v1/secrets/ (active list) + GET /api/v1/secrets/rotation-status + GET /api/v1/secrets/patterns
 */

import { useEffect, useState } from "react";
import { ScanSearch, RefreshCw, AlertTriangle, Shield } from "lucide-react";
import { secretsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface DetectedSecret {
  id: string;
  secret_type: string;
  file_path: string;
  severity: string;
  line_number?: number;
  commit_sha?: string;
  author?: string;
  detected_at?: string;
  is_rotated?: boolean;
  is_false_positive?: boolean;
}

interface RotationStatus {
  total: number;
  active: number;
  rotated: number;
  false_positive: number;
  rotation_rate: number;
}

interface SecretPattern {
  type: string;
  description: string;
  severity: string;
  pattern?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-slate-400",
};

function sevColor(s: string) {
  return SEVERITY_COLORS[s?.toLowerCase()] ?? SEVERITY_COLORS.low;
}

export function SecretScannerPanel() {
  const [secrets, setSecrets] = useState<DetectedSecret[]>([]);
  const [status, setStatus] = useState<RotationStatus | null>(null);
  const [patterns, setPatterns] = useState<SecretPattern[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [rootRes, statusRes, patternsRes] = await Promise.allSettled([
        secretsApi.root(),
        secretsApi.rotationStatus(),
        secretsApi.patterns(),
      ]);

      if (rootRes.status === "fulfilled") {
        const d = rootRes.value.data as { items?: DetectedSecret[]; rotation_status?: RotationStatus } | DetectedSecret[];
        if (Array.isArray(d)) {
          setSecrets(d);
        } else {
          setSecrets(d.items ?? []);
          if (d.rotation_status) setStatus(d.rotation_status);
        }
      }
      if (statusRes.status === "fulfilled" && statusRes.value.data) {
        setStatus(statusRes.value.data as RotationStatus);
      }
      if (patternsRes.status === "fulfilled") {
        const d = patternsRes.value.data;
        setPatterns(Array.isArray(d) ? (d as SecretPattern[]) : []);
      }

      if (rootRes.status === "rejected") {
        throw new Error((rootRes.reason as Error).message ?? "Failed to load scanner data");
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
          <div key={i} className="h-12 rounded bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  if (secrets.length === 0 && patterns.length === 0) {
    return (
      <EmptyState
        icon={ScanSearch}
        title="No scan data available"
        description="Run a scan to detect hardcoded secrets in your codebase."
      />
    );
  }

  // Group secrets by type for breakdown chart
  const byType: Record<string, number> = {};
  for (const s of secrets) {
    byType[s.secret_type] = (byType[s.secret_type] ?? 0) + 1;
  }

  // Active (unrotated, not false positive) secrets
  const active = secrets.filter(s => !s.is_rotated && !s.is_false_positive);

  return (
    <div className="space-y-6">
      {/* Stats */}
      {status && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Found", value: status.total, color: "text-foreground" },
            { label: "Active", value: status.active, color: "text-red-400" },
            { label: "Rotated", value: status.rotated, color: "text-green-400" },
            { label: "Patterns", value: patterns.length, color: "text-indigo-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Active secrets alert */}
      {active.length > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-red-700 bg-red-900/20 px-3 py-2 text-sm text-red-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          {active.length} active secret{active.length !== 1 ? "s" : ""} detected — rotate immediately.
        </div>
      )}

      {/* Active secrets table */}
      {active.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <ScanSearch className="h-3.5 w-3.5 text-red-400" />
              Active Findings ({active.length})
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
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Line</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Severity</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Author</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Commit</th>
              </tr>
            </thead>
            <tbody>
              {active.slice(0, 50).map((s) => (
                <tr key={s.id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 text-xs font-mono">{s.secret_type}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[180px]" title={s.file_path}>
                    {s.file_path}
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{s.line_number ?? "—"}</td>
                  <td className={`px-4 py-2 text-xs font-medium ${sevColor(s.severity)}`}>
                    {s.severity ?? "unknown"}
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{s.author ?? "—"}</td>
                  <td className="px-4 py-2 text-xs font-mono text-muted-foreground">
                    {s.commit_sha ? s.commit_sha.slice(0, 7) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Secret type breakdown */}
      {Object.keys(byType).length > 0 && (
        <div className="rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium mb-3">Detection Breakdown by Type</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(byType)
              .sort(([, a], [, b]) => b - a)
              .map(([type, count]) => (
                <div key={type} className="flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-xs">
                  <span className="text-foreground font-medium">{type}</span>
                  <span className="text-muted-foreground">{count}</span>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Pattern catalog */}
      {patterns.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-indigo-400" />
              Detection Patterns ({patterns.length})
            </h3>
          </div>
          <div className="divide-y divide-border/50">
            {patterns.slice(0, 20).map((p, i) => (
              <div key={i} className="flex items-center justify-between px-4 py-2 hover:bg-muted/10 transition-colors">
                <div>
                  <p className="text-xs font-medium">{p.type}</p>
                  <p className="text-xs text-muted-foreground">{p.description}</p>
                </div>
                <span className={`text-xs font-medium ${sevColor(p.severity)}`}>{p.severity}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
