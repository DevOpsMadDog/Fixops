/**
 * QuantumCryptoPanel — Post-quantum readiness, assets, PQC migration tracking
 * API: GET /api/v1/quantum-crypto/status + /api/v1/quantum-crypto/keys + /api/v1/quantum-crypto/health
 */

import { useEffect, useState } from "react";
import { Atom, RefreshCw, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";
import { quantumCryptoApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface QuantumStatus {
  status?: string;
  pqc_algorithm?: string;
  signing_algorithm?: string;
  classical_algorithm?: string;
  public_key_size?: number;
  signature_size?: number;
  key_generation?: Record<string, unknown>;
  signing?: Record<string, unknown>;
  verification?: Record<string, unknown>;
  overall_health?: string;
  readiness_score?: number;
  quantum_resistant?: boolean;
}

interface QuantumKeys {
  public_key_id?: string;
  algorithm?: string;
  created_at?: string;
  key_size?: number;
  pqc?: boolean;
}

interface HealthData {
  status?: string;
  pqc_available?: boolean;
  engine?: string;
  checks?: Record<string, boolean | string>;
}

export function QuantumCryptoPanel() {
  const [status, setStatus] = useState<QuantumStatus | null>(null);
  const [keys, setKeys] = useState<QuantumKeys | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statusRes, keysRes, healthRes] = await Promise.allSettled([
        quantumCryptoApi.status(),
        quantumCryptoApi.keys(),
        quantumCryptoApi.health(),
      ]);
      if (statusRes.status === "fulfilled") setStatus(statusRes.value.data as QuantumStatus);
      if (keysRes.status === "fulfilled") setKeys(keysRes.value.data as QuantumKeys);
      if (healthRes.status === "fulfilled") setHealth(healthRes.value.data as HealthData);
      if (statusRes.status === "rejected" && healthRes.status === "rejected") {
        throw new Error((statusRes.reason as Error).message ?? "Failed to load quantum crypto data");
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

  if (!status && !health) {
    return (
      <EmptyState
        icon={Atom}
        title="No quantum crypto data"
        description="Post-quantum cryptography engine has not been configured for this organization."
      />
    );
  }

  const isQuantumReady = status?.quantum_resistant ?? (health?.pqc_available === true);
  const readinessScore = status?.readiness_score ?? (isQuantumReady ? 100 : 0);

  return (
    <div className="space-y-6">
      {/* Readiness banner */}
      <div className={`flex items-center gap-3 rounded-lg border p-4 ${
        isQuantumReady
          ? "border-green-700 bg-green-900/20"
          : "border-amber-700 bg-amber-900/20"
      }`}>
        {isQuantumReady ? (
          <CheckCircle2 className="h-6 w-6 text-green-400 flex-shrink-0" />
        ) : (
          <AlertTriangle className="h-6 w-6 text-amber-400 flex-shrink-0" />
        )}
        <div>
          <p className={`text-sm font-medium ${isQuantumReady ? "text-green-300" : "text-amber-300"}`}>
            {isQuantumReady ? "Post-Quantum Ready" : "Quantum Migration Required"}
          </p>
          <p className="text-xs text-muted-foreground mt-0.5">
            {isQuantumReady
              ? `PQC algorithm active: ${status?.pqc_algorithm ?? health?.engine ?? "CRYSTALS-Kyber"}`
              : "Classical cryptography in use — quantum-safe migration recommended."}
          </p>
        </div>
        {readinessScore > 0 && (
          <div className="ml-auto text-right">
            <p className="text-2xl font-bold text-foreground">{readinessScore}%</p>
            <p className="text-xs text-muted-foreground">Readiness</p>
          </div>
        )}
      </div>

      {/* Status details */}
      {status && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {[
            { label: "PQC Algorithm", value: status.pqc_algorithm ?? "—" },
            { label: "Signing Algorithm", value: status.signing_algorithm ?? "—" },
            { label: "Classical Fallback", value: status.classical_algorithm ?? "—" },
            { label: "Public Key Size", value: status.public_key_size ? `${status.public_key_size} bytes` : "—" },
            { label: "Signature Size", value: status.signature_size ? `${status.signature_size} bytes` : "—" },
            { label: "Overall Health", value: status.overall_health ?? health?.status ?? "—" },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/20 px-3 py-2">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className="text-sm font-medium mt-0.5">{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Health checks */}
      {health?.checks && Object.keys(health.checks).length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Atom className="h-3.5 w-3.5 text-indigo-400" />
              Engine Health Checks
            </h3>
            <button
              onClick={load}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>
          <ul className="divide-y divide-border/50">
            {Object.entries(health.checks).map(([check, result]) => {
              const passed = result === true || result === "ok" || result === "pass";
              return (
                <li key={check} className="flex items-center justify-between px-4 py-2.5">
                  <span className="text-sm capitalize">{check.replace(/_/g, " ")}</span>
                  {passed ? (
                    <CheckCircle2 className="h-4 w-4 text-green-400" />
                  ) : (
                    <XCircle className="h-4 w-4 text-red-400" />
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* Key info */}
      {keys && (
        <div className="rounded-lg border border-border p-4 space-y-3">
          <h3 className="text-sm font-medium flex items-center gap-1.5">
            <Atom className="h-3.5 w-3.5 text-indigo-400" />
            Active PQC Key
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div>
              <p className="text-muted-foreground">Key ID</p>
              <p className="font-mono mt-0.5">{keys.public_key_id?.slice(0, 16) ?? "—"}…</p>
            </div>
            <div>
              <p className="text-muted-foreground">Algorithm</p>
              <p className="mt-0.5">{keys.algorithm ?? "—"}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Key Size</p>
              <p className="mt-0.5">{keys.key_size ? `${keys.key_size} bytes` : "—"}</p>
            </div>
            <div>
              <p className="text-muted-foreground">PQC</p>
              <p className={`mt-0.5 font-medium ${keys.pqc ? "text-green-400" : "text-red-400"}`}>
                {keys.pqc ? "Yes" : "No"}
              </p>
            </div>
          </div>
          {keys.created_at && (
            <p className="text-xs text-muted-foreground">
              Generated {new Date(keys.created_at).toLocaleString()}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
