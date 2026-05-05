/**
 * AirGapFeedStatusPanel — Live status of air-gap mode, FIPS, LLM routing, isolation
 * API: GET /api/v1/airgap/status
 */

import { useEffect, useState } from "react";
import { RefreshCw, ShieldCheck, WifiOff, Cpu, Lock } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface AirGapStatus {
  mode?: string;
  classification_level?: string;
  fips?: { mode?: string; kernel_fips_enabled?: boolean };
  llm?: { backend?: string; available?: boolean; endpoint?: string; model_name?: string };
  vuln_db?: { available?: boolean; version?: string; cve_count?: number };
  network_isolation?: { is_isolated?: boolean };
  enabled_scanners?: string[];
}

const MODE_BADGE: Record<string, string> = {
  enforced: "bg-green-700 text-green-100",
  configured: "bg-blue-700 text-blue-100",
  detected: "bg-amber-700 text-amber-100",
  disabled: "bg-gray-700 text-gray-300",
};

function badge(label: string, cls: string) {
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {label}
    </span>
  );
}

export function AirGapFeedStatusPanel() {
  const [data, setData] = useState<AirGapStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const { default: axios } = await import("axios");
      const token = window.localStorage.getItem("aldeci.authToken") || "";
      const res = await axios.get("/api/v1/airgap/status", {
        headers: token ? { "X-API-Key": token } : {},
      });
      setData(res.data as AirGapStatus);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load air-gap status");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4">
        {[1, 2, 3, 4].map(i => (
          <div key={i} className="h-14 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }
  if (error) return <ErrorState message={error} onRetry={load} />;
  if (!data) return <EmptyState title="No status" description="Air-gap status unavailable." />;

  const mode = data.mode ?? "unknown";
  const modeClass = MODE_BADGE[mode] ?? "bg-gray-700 text-gray-300";
  const fipsMode = data.fips?.mode ?? "disabled";
  const llm = data.llm;
  const vulnDb = data.vuln_db;

  return (
    <div className="space-y-4 p-1">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Air-Gap Status</h3>
        <button onClick={load} className="p-1.5 rounded hover:bg-muted/50 text-muted-foreground">
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Mode + Classification */}
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-border bg-card p-3 space-y-1">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <WifiOff className="h-3.5 w-3.5" /> Mode
          </div>
          {badge(mode.toUpperCase(), modeClass)}
        </div>
        <div className="rounded-lg border border-border bg-card p-3 space-y-1">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Lock className="h-3.5 w-3.5" /> Classification
          </div>
          <span className="text-xs font-medium text-foreground">
            {data.classification_level ?? "UNCLASSIFIED"}
          </span>
        </div>
      </div>

      {/* FIPS */}
      <div className="rounded-lg border border-border bg-card p-3 space-y-1">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <ShieldCheck className="h-3.5 w-3.5" /> FIPS 140-2/3
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {badge(
            fipsMode.toUpperCase(),
            fipsMode === "enforced" ? "bg-green-700 text-green-100"
              : fipsMode === "audit" ? "bg-amber-700 text-amber-100"
              : "bg-gray-700 text-gray-300",
          )}
          {data.fips?.kernel_fips_enabled && (
            <span className="text-xs text-green-400">kernel FIPS enabled</span>
          )}
        </div>
      </div>

      {/* Local LLM */}
      <div className="rounded-lg border border-border bg-card p-3 space-y-1">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Cpu className="h-3.5 w-3.5" /> Local LLM
        </div>
        {llm?.available ? (
          <div className="space-y-0.5">
            <div className="text-xs font-medium text-green-400">
              {llm.backend} — {llm.model_name ?? "unknown model"}
            </div>
            <div className="text-xs text-muted-foreground">{llm.endpoint}</div>
          </div>
        ) : (
          <span className="text-xs text-amber-400">No local LLM configured</span>
        )}
      </div>

      {/* Offline Vuln DB */}
      <div className="rounded-lg border border-border bg-card p-3 space-y-1">
        <div className="text-xs text-muted-foreground">Offline Vuln DB</div>
        {vulnDb?.available ? (
          <div className="text-xs font-medium text-foreground">
            v{vulnDb.version} — {vulnDb.cve_count?.toLocaleString()} CVEs
          </div>
        ) : (
          <span className="text-xs text-amber-400">Not imported — use Import Vuln DB</span>
        )}
      </div>

      {/* Network isolation */}
      <div className="rounded-lg border border-border bg-card p-3 space-y-1">
        <div className="text-xs text-muted-foreground">Network Isolation</div>
        {badge(
          data.network_isolation?.is_isolated ? "ISOLATED" : "NOT ISOLATED",
          data.network_isolation?.is_isolated
            ? "bg-green-700 text-green-100"
            : "bg-red-700 text-red-100",
        )}
      </div>
    </div>
  );
}
