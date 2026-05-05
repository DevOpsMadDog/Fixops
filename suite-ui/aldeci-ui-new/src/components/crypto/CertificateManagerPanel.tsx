/**
 * CertificateManagerPanel — operational cert lifecycle: weak certs, domain probe, list
 * API: GET /api/v1/certificates/weak + /api/v1/certificates/stats + /api/v1/certificates/
 * Used by CryptoTrustHub "manager" tab.
 */

import { useEffect, useState } from "react";
import { FileBadge, AlertTriangle, RefreshCw, Search } from "lucide-react";
import { certificatesApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface Cert {
  cert_id?: string;
  id?: string;
  domain?: string;
  subject?: string;
  issuer?: string;
  expires_at?: string;
  algorithm?: string;
  key_size?: number;
  status?: string;
  cert_type?: string;
  weakness_reason?: string;
}

interface CertStats {
  total: number;
  valid: number;
  expiring_soon: number;
  expired: number;
  weak: number;
}

const STATUS_PILL: Record<string, string> = {
  valid:   "bg-green-700/40 text-green-300",
  expiring:"bg-amber-700/40 text-amber-300",
  expired: "bg-red-700/40 text-red-300",
  weak:    "bg-red-700/40 text-red-300",
  revoked: "bg-gray-700/40 text-gray-400",
};

function pill(s: string) {
  return STATUS_PILL[s?.toLowerCase()] ?? STATUS_PILL.revoked;
}

export function CertificateManagerPanel() {
  const [stats, setStats]   = useState<CertStats | null>(null);
  const [weak, setWeak]     = useState<Cert[]>([]);
  const [certs, setCerts]   = useState<Cert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<Record<string, unknown> | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, weakRes, listRes] = await Promise.allSettled([
        certificatesApi.stats(),
        certificatesApi.weak(),
        certificatesApi.list(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as CertStats);
      if (weakRes.status === "fulfilled") {
        const d = weakRes.value.data;
        setWeak(Array.isArray(d) ? d : (d?.certificates ?? d?.items ?? []));
      }
      if (listRes.status === "fulfilled") {
        const d = listRes.value.data;
        setCerts(Array.isArray(d) ? d : (d?.certificates ?? d?.items ?? []));
      }
      if (statsRes.status === "rejected" && listRes.status === "rejected") {
        throw new Error("Failed to load certificate data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const probeDomain = async () => {
    if (!domain.trim()) return;
    setProbing(true);
    setProbeResult(null);
    try {
      const res = await certificatesApi.check(domain.trim());
      setProbeResult(res.data as Record<string, unknown>);
    } catch (e) {
      setProbeResult({ error: (e as Error).message });
    } finally {
      setProbing(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-3 p-4 animate-pulse">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="h-10 rounded bg-muted/40" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  const noData = !stats && weak.length === 0 && certs.length === 0;
  if (noData) {
    return (
      <EmptyState
        icon={FileBadge}
        title="No certificates found"
        description="Add certificates via POST /api/v1/certificates or probe a domain below."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-3">
          {[
            { label: "Total",   value: stats.total,         color: "text-foreground" },
            { label: "Valid",   value: stats.valid,         color: "text-green-400" },
            { label: "Expiring",value: stats.expiring_soon, color: "text-amber-400" },
            { label: "Expired", value: stats.expired,       color: "text-red-400" },
            { label: "Weak",    value: stats.weak,          color: "text-red-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* Domain probe */}
      <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-3">
        <h3 className="text-sm font-medium flex items-center gap-1.5">
          <Search className="h-3.5 w-3.5 text-indigo-400" />
          Live Domain TLS Probe
        </h3>
        <div className="flex gap-2">
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === "Enter" && probeDomain()}
            placeholder="example.com"
            className="flex-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
          <button
            onClick={probeDomain}
            disabled={probing || !domain.trim()}
            className="rounded-md bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {probing ? "Probing…" : "Probe"}
          </button>
          <button
            onClick={load}
            title="Refresh"
            className="rounded-md border border-border px-2 py-1.5 text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
          </button>
        </div>
        {probeResult && (
          <pre className="rounded bg-muted/40 p-3 text-xs text-foreground overflow-x-auto max-h-48">
            {JSON.stringify(probeResult, null, 2)}
          </pre>
        )}
      </div>

      {/* Weak certificates */}
      {weak.length > 0 && (
        <div className="rounded-lg border border-red-800/50 overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 bg-red-900/20 border-b border-red-800/50">
            <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
            <span className="text-sm font-medium text-red-300">
              Weak Certificates ({weak.length})
            </span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Subject / Domain</th>
                <th className="text-left px-4 py-2 font-medium">Algorithm</th>
                <th className="text-left px-4 py-2 font-medium">Key Size</th>
                <th className="text-left px-4 py-2 font-medium">Weakness</th>
                <th className="text-left px-4 py-2 font-medium">Expires</th>
              </tr>
            </thead>
            <tbody>
              {weak.map((c, i) => (
                <tr key={c.cert_id ?? c.id ?? i} className="border-b border-border/40 hover:bg-muted/10">
                  <td className="px-4 py-2 font-mono text-xs">{c.domain ?? c.subject ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">{c.algorithm ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">{c.key_size ? `${c.key_size}b` : "—"}</td>
                  <td className="px-4 py-2 text-xs text-red-400">{c.weakness_reason ?? "weak"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {c.expires_at ? new Date(c.expires_at).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Full inventory */}
      {certs.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <FileBadge className="h-3.5 w-3.5 text-indigo-400" />
              Certificate Inventory ({certs.length})
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Subject / Domain</th>
                <th className="text-left px-4 py-2 font-medium">Issuer</th>
                <th className="text-left px-4 py-2 font-medium">Type</th>
                <th className="text-left px-4 py-2 font-medium">Status</th>
                <th className="text-left px-4 py-2 font-medium">Expires</th>
              </tr>
            </thead>
            <tbody>
              {certs.slice(0, 50).map((c, i) => (
                <tr key={c.cert_id ?? c.id ?? i} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs">{c.domain ?? c.subject ?? "—"}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground truncate max-w-[160px]">{c.issuer ?? "—"}</td>
                  <td className="px-4 py-2 text-xs capitalize">{c.cert_type ?? "—"}</td>
                  <td className="px-4 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${pill(c.status ?? "")}`}>
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
