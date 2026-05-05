/**
 * CryptoKeysPanel — Cryptographic key inventory with stats
 * API: GET /api/v1/crypto-keys/ + /api/v1/crypto-keys/stats + /api/v1/crypto-keys/expiring
 */

import { useEffect, useState } from "react";
import { Key, RefreshCw, AlertTriangle, RotateCcw } from "lucide-react";
import { cryptoKeysApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface KeyStats {
  total: number;
  active: number;
  expiring_soon: number;
  expired: number;
  revoked: number;
  by_algorithm?: Record<string, number>;
}

interface CryptoKey {
  key_id: string;
  algorithm: string;
  status: string;
  expires_at?: string;
  created_at?: string;
  key_size?: number;
  org_id?: string;
}

const STATUS_COLORS: Record<string, string> = {
  active: "bg-green-700 text-green-100",
  expiring: "bg-amber-700 text-amber-100",
  expired: "bg-red-700 text-red-100",
  revoked: "bg-gray-700 text-gray-300",
};

function statusClass(s: string): string {
  return STATUS_COLORS[s?.toLowerCase()] ?? STATUS_COLORS.revoked;
}

export function CryptoKeysPanel() {
  const [stats, setStats] = useState<KeyStats | null>(null);
  const [keys, setKeys] = useState<CryptoKey[]>([]);
  const [expiring, setExpiring] = useState<CryptoKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, keysRes, expiringRes] = await Promise.allSettled([
        cryptoKeysApi.stats(),
        cryptoKeysApi.list(),
        cryptoKeysApi.expiring(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as KeyStats);
      if (keysRes.status === "fulfilled") {
        const d = keysRes.value.data;
        setKeys(Array.isArray(d) ? d : (d?.keys ?? []));
      }
      if (expiringRes.status === "fulfilled") {
        const d = expiringRes.value.data;
        setExpiring(Array.isArray(d) ? d : (d?.keys ?? []));
      }
      if (statsRes.status === "rejected" && keysRes.status === "rejected") {
        throw new Error((statsRes.reason as Error).message ?? "Failed to load crypto keys");
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

  if (!stats && keys.length === 0) {
    return (
      <EmptyState
        icon={Key}
        title="No crypto keys found"
        description="No cryptographic keys are registered for this organization."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total", value: stats.total, color: "text-foreground" },
            { label: "Active", value: stats.active, color: "text-green-400" },
            { label: "Expiring Soon", value: stats.expiring_soon, color: "text-amber-400" },
            { label: "Expired / Revoked", value: (stats.expired ?? 0) + (stats.revoked ?? 0), color: "text-red-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* Expiring warning */}
      {expiring.length > 0 && (
        <div className="flex items-center gap-2 rounded-md border border-amber-700 bg-amber-900/20 px-3 py-2 text-sm text-amber-300">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          {expiring.length} key{expiring.length > 1 ? "s" : ""} expiring soon — rotate before expiry.
        </div>
      )}

      {/* Key table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <Key className="h-3.5 w-3.5 text-indigo-400" />
            Key Inventory ({keys.length})
          </h3>
          <button
            onClick={load}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
        </div>
        {keys.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">No keys in inventory.</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Key ID</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Algorithm</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Size</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Status</th>
                <th className="text-left px-4 py-2 text-xs text-muted-foreground font-medium">Expires</th>
                <th className="px-4 py-2" />
              </tr>
            </thead>
            <tbody>
              {keys.slice(0, 50).map((k) => (
                <tr key={k.key_id} className="border-b border-border/50 hover:bg-muted/10 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{k.key_id.slice(0, 12)}…</td>
                  <td className="px-4 py-2 text-xs">{k.algorithm ?? "—"}</td>
                  <td className="px-4 py-2 text-xs">{k.key_size ? `${k.key_size}b` : "—"}</td>
                  <td className="px-4 py-2">
                    <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${statusClass(k.status)}`}>
                      {k.status ?? "unknown"}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {k.expires_at ? new Date(k.expires_at).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-4 py-2">
                    <button
                      title="Rotate key"
                      className="text-muted-foreground hover:text-indigo-400 transition-colors"
                      onClick={() => cryptoKeysApi.rotate(k.key_id).then(load)}
                    >
                      <RotateCcw className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Algorithm breakdown */}
      {stats?.by_algorithm && Object.keys(stats.by_algorithm).length > 0 && (
        <div className="rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium mb-3">Algorithm Breakdown</h3>
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.by_algorithm).map(([algo, count]) => (
              <div key={algo} className="flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-xs">
                <span className="text-foreground font-medium">{algo}</span>
                <span className="text-muted-foreground">{count as number}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
