/**
 * AirGapFeedsPanel — Registry of offline intel feed bundles
 * API: GET /api/v1/air-gap/bundle/list + GET /api/v1/air-gap/bundle/stats
 */

import { useEffect, useState } from "react";
import { RefreshCw, Package, CheckCircle, Clock, AlertCircle } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface Bundle {
  bundle_id: string;
  bundle_version?: string;
  status?: string;
  exported_by?: string;
  created_at?: string;
  entry_count?: number;
  org_id?: string;
}

interface BundleStats {
  total?: number;
  by_status?: Record<string, number>;
  total_size_bytes?: number;
}

const STATUS_ICON: Record<string, React.ReactNode> = {
  verified: <CheckCircle className="h-3.5 w-3.5 text-green-400" />,
  applied: <CheckCircle className="h-3.5 w-3.5 text-blue-400" />,
  pending: <Clock className="h-3.5 w-3.5 text-amber-400" />,
  failed: <AlertCircle className="h-3.5 w-3.5 text-red-400" />,
};
const STATUS_CLASS: Record<string, string> = {
  verified: "text-green-400",
  applied: "text-blue-400",
  pending: "text-amber-400",
  failed: "text-red-400",
};

function fmtDate(s?: string) {
  if (!s) return "—";
  try { return new Date(s).toLocaleDateString(); } catch { return s; }
}

export function AirGapFeedsPanel() {
  const [bundles, setBundles] = useState<Bundle[]>([]);
  const [stats, setStats] = useState<BundleStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const { default: axios } = await import("axios");
      const token = window.localStorage.getItem("aldeci.authToken") || "";
      const headers = token ? { "X-API-Key": token } : {};
      const [listRes, statsRes] = await Promise.allSettled([
        axios.get("/api/v1/air-gap/bundle/list", { headers }),
        axios.get("/api/v1/air-gap/bundle/stats", { headers }),
      ]);
      if (listRes.status === "fulfilled") {
        const d = listRes.value.data;
        setBundles(Array.isArray(d) ? d : (d?.items ?? d?.bundles ?? []));
      }
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as BundleStats);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load bundle registry");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-16 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-4 p-1">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Bundle Registry</h3>
        <button onClick={load} className="p-1.5 rounded hover:bg-muted/50 text-muted-foreground">
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total", value: stats.total ?? bundles.length },
            { label: "Verified", value: stats.by_status?.verified ?? 0 },
            { label: "Applied", value: stats.by_status?.applied ?? 0 },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-border bg-card p-3 text-center">
              <div className="text-lg font-bold text-foreground">{value}</div>
              <div className="text-xs text-muted-foreground">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Bundle list */}
      {bundles.length === 0 ? (
        <EmptyState
          title="No bundles"
          description="No air-gap intel bundles have been exported yet. Use POST /api/v1/air-gap/bundle/export to create one."
        />
      ) : (
        <div className="space-y-2">
          {bundles.map(b => {
            const status = b.status ?? "pending";
            return (
              <div
                key={b.bundle_id}
                className="rounded-lg border border-border bg-card p-3 flex items-center gap-3"
              >
                <Package className="h-4 w-4 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-foreground truncate">
                    {b.bundle_id}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    v{b.bundle_version ?? "—"} · {b.entry_count ?? 0} entries · {fmtDate(b.created_at)}
                  </div>
                </div>
                <div className={`flex items-center gap-1 text-xs ${STATUS_CLASS[status] ?? "text-muted-foreground"}`}>
                  {STATUS_ICON[status] ?? <Clock className="h-3.5 w-3.5" />}
                  {status}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
