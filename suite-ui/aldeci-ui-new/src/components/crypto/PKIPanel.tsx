/**
 * PKIPanel — Internal PKI hierarchy: CAs, intermediates, issued certs
 * API: GET /api/v1/pki/stats + /api/v1/pki/cas + /api/v1/pki/certificates
 */

import { useEffect, useState } from "react";
import { Network, RefreshCw, ShieldAlert } from "lucide-react";
import { pkiApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface PKIStats {
  total_cas: number;
  total_certificates: number;
  active_certificates: number;
  revoked_certificates: number;
  expiring_soon: number;
  chain_depth?: number;
}

interface CA {
  ca_id: string;
  name?: string;
  subject?: string;
  is_root?: boolean;
  status?: string;
  expires_at?: string;
  issued_count?: number;
}

interface PKICert {
  cert_id: string;
  subject?: string;
  ca_id?: string;
  status?: string;
  expires_at?: string;
}

export function PKIPanel() {
  const [stats, setStats] = useState<PKIStats | null>(null);
  const [cas, setCas] = useState<CA[]>([]);
  const [certs, setCerts] = useState<PKICert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, casRes, certsRes] = await Promise.allSettled([
        pkiApi.stats(),
        pkiApi.listCAs(),
        pkiApi.listCertificates(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as PKIStats);
      if (casRes.status === "fulfilled") {
        const d = casRes.value.data;
        setCas(Array.isArray(d) ? d : (d?.cas ?? []));
      }
      if (certsRes.status === "fulfilled") {
        const d = certsRes.value.data;
        setCerts(Array.isArray(d) ? d : (d?.certificates ?? []));
      }
      if (statsRes.status === "rejected" && casRes.status === "rejected") {
        throw new Error((statsRes.reason as Error).message ?? "Failed to load PKI data");
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

  if (!stats && cas.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No PKI hierarchy found"
        description="No certificate authorities or PKI infrastructure registered for this organization."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Certificate Authorities", value: stats.total_cas, color: "text-indigo-400" },
            { label: "Issued Certs", value: stats.total_certificates, color: "text-foreground" },
            { label: "Active", value: stats.active_certificates, color: "text-green-400" },
            { label: "Expiring Soon", value: stats.expiring_soon, color: "text-amber-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* CA hierarchy */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <ShieldAlert className="h-3.5 w-3.5 text-indigo-400" />
            Certificate Authorities ({cas.length})
          </h3>
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
        </div>
        {cas.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">No CAs registered.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Name / Subject</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Type</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Status</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Issued</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Expires</th>
              </tr>
            </thead>
            <tbody>
              {cas.map((ca) => (
                <tr key={ca.ca_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 text-xs font-mono max-w-[220px] truncate" title={ca.subject ?? ca.name}>
                    {ca.name ?? ca.subject ?? ca.ca_id.slice(0, 16) + "…"}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {ca.is_root ? (
                      <span className="inline-block rounded bg-purple-800 text-purple-200 px-1.5 py-0.5 text-xs">Root CA</span>
                    ) : (
                      <span className="inline-block rounded bg-blue-900 text-blue-200 px-1.5 py-0.5 text-xs">Intermediate</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${
                      ca.status === "active" ? "bg-green-700 text-green-100" : "bg-gray-700 text-gray-300"
                    }`}>
                      {ca.status ?? "unknown"}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{ca.issued_count ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {ca.expires_at ? new Date(ca.expires_at).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Recent issued certs */}
      {certs.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5 text-indigo-400" />
              Issued Certificates (latest {Math.min(certs.length, 20)})
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Subject</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">CA</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Status</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Expires</th>
              </tr>
            </thead>
            <tbody>
              {certs.slice(0, 20).map((c) => (
                <tr key={c.cert_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 text-xs font-mono truncate max-w-[200px]">{c.subject ?? c.cert_id.slice(0, 16) + "…"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{c.ca_id?.slice(0, 12) ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${
                      c.status === "active" ? "bg-green-700 text-green-100" : "bg-gray-700 text-gray-300"
                    }`}>
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
        </div>
      )}
    </div>
  );
}
