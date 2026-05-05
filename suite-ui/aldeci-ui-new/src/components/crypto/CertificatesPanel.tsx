/**
 * CertificatesPanel — TLS/signing/client certificate inventory
 * API: GET /api/v1/certificates/ + /api/v1/certificates/stats + /api/v1/certificates/alerts/expiry
 */

import { useEffect, useState } from "react";
import { ShieldCheck, RefreshCw, AlertTriangle } from "lucide-react";
import { certificatesApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface CertStats {
  total: number;
  valid: number;
  expiring_soon: number;
  expired: number;
  weak: number;
  by_type?: Record<string, number>;
}

interface Certificate {
  cert_id: string;
  subject?: string;
  issuer?: string;
  cert_type?: string;
  status?: string;
  expires_at?: string;
  algorithm?: string;
  key_size?: number;
}

interface ExpiryAlerts {
  critical?: Certificate[];
  warning?: Certificate[];
}

const STATUS_COLORS: Record<string, string> = {
  valid: "bg-green-700 text-green-100",
  expiring: "bg-amber-700 text-amber-100",
  expired: "bg-red-700 text-red-100",
  revoked: "bg-gray-700 text-gray-300",
  weak: "bg-orange-700 text-orange-100",
};

function statusClass(s: string): string {
  return STATUS_COLORS[s?.toLowerCase()] ?? STATUS_COLORS.revoked;
}

export function CertificatesPanel() {
  const [stats, setStats] = useState<CertStats | null>(null);
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [alerts, setAlerts] = useState<ExpiryAlerts>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, certsRes, alertsRes] = await Promise.allSettled([
        certificatesApi.stats(),
        certificatesApi.list(),
        certificatesApi.expiryAlerts(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as CertStats);
      if (certsRes.status === "fulfilled") {
        const d = certsRes.value.data;
        setCerts(Array.isArray(d) ? d : (d?.certificates ?? []));
      }
      if (alertsRes.status === "fulfilled") setAlerts(alertsRes.value.data as ExpiryAlerts);
      if (statsRes.status === "rejected" && certsRes.status === "rejected") {
        throw new Error((statsRes.reason as Error).message ?? "Failed to load certificates");
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

  if (!stats && certs.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No certificates found"
        description="No TLS or signing certificates are registered for this organization."
      />
    );
  }

  const criticalCount = (alerts.critical ?? []).length;
  const warningCount = (alerts.warning ?? []).length;

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "Total", value: stats.total, color: "text-foreground" },
            { label: "Valid", value: stats.valid, color: "text-green-400" },
            { label: "Expiring Soon", value: stats.expiring_soon, color: "text-amber-400" },
            { label: "Expired", value: stats.expired, color: "text-red-400" },
            { label: "Weak", value: stats.weak, color: "text-orange-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* Alerts */}
      {(criticalCount > 0 || warningCount > 0) && (
        <div className="space-y-2">
          {criticalCount > 0 && (
            <div className="flex items-center gap-2 rounded-md border border-red-700 bg-red-900/20 px-3 py-2 text-sm text-red-300">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              {criticalCount} certificate{criticalCount > 1 ? "s" : ""} expiring critically — immediate renewal required.
            </div>
          )}
          {warningCount > 0 && (
            <div className="flex items-center gap-2 rounded-md border border-amber-700 bg-amber-900/20 px-3 py-2 text-sm text-amber-300">
              <AlertTriangle className="h-4 w-4 flex-shrink-0" />
              {warningCount} certificate{warningCount > 1 ? "s" : ""} expiring within 30 days.
            </div>
          )}
        </div>
      )}

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5 text-indigo-400" />
            Certificate Inventory ({certs.length})
          </h3>
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
        </div>
        {certs.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">No certificates in inventory.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Subject</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Type</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Algo</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Status</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Expires</th>
              </tr>
            </thead>
            <tbody>
              {certs.slice(0, 50).map((c) => (
                <tr key={c.cert_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 text-xs font-mono max-w-[200px] truncate" title={c.subject}>
                    {c.subject ?? c.cert_id.slice(0, 16) + "…"}
                  </td>
                  <td className="px-4 py-2 text-xs">{c.cert_type ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">{c.algorithm ?? "—"}{c.key_size ? ` ${c.key_size}b` : ""}</td>
                  <td className="px-4 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${statusClass(c.status ?? "")}`}>
                      {c.status ?? "unknown"}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {c.expires_at ? new Date(c.expires_at).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Type breakdown */}
      {stats?.by_type && Object.keys(stats.by_type).length > 0 && (
        <div className="rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium mb-3">Certificate Types</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.by_type).map(([type, count]) => (
              <div key={type} className="flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-xs">
                <span className="text-foreground font-medium">{type}</span>
                <span className="text-muted-foreground">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
