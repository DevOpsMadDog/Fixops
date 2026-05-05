/**
 * XDRPanel — DetectAndRespondHub "xdr" tab
 *
 * Wired to real backend:
 *   GET /api/v1/threat-vectors/stats   → KPI bar
 *   GET /api/v1/threat-vectors/vectors → threat vector table
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Layers, ShieldAlert, Activity, AlertTriangle, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface XDRStats {
  total_vectors?: number;
  critical_vectors?: number;
  high_vectors?: number;
  active_mitigations?: number;
  org_id?: string;
}

interface ThreatVector {
  vector_id?: string;
  id?: string;
  name?: string;
  vector_type?: string;
  severity?: string;
  frequency_score?: number;
  impact_score?: number;
  first_observed?: string;
  last_observed?: string;
  description?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["vectors", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function XDRPanel() {
  const [stats, setStats] = useState<XDRStats | null>(null);
  const [vectors, setVectors] = useState<ThreatVector[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<string>("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawVectors] = await Promise.all([
        apiFetch<XDRStats>("/api/v1/threat-vectors/stats"),
        apiFetch<unknown>("/api/v1/threat-vectors/vectors"),
      ]);
      setStats(rawStats);
      setVectors(extractArray<ThreatVector>(rawVectors));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load XDR data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Vectors", value: stats?.total_vectors ?? vectors.length, icon: Layers, color: "text-slate-300" },
    { label: "Critical", value: stats?.critical_vectors ?? vectors.filter(v => v.severity === "critical").length, icon: ShieldAlert, color: "text-red-400" },
    { label: "High", value: stats?.high_vectors ?? vectors.filter(v => v.severity === "high").length, icon: AlertTriangle, color: "text-orange-400" },
    { label: "Active Mitigations", value: stats?.active_mitigations ?? 0, icon: Activity, color: "text-emerald-400" },
  ];

  const filtered = sevFilter === "all" ? vectors : vectors.filter(v => v.severity === sevFilter);

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Layers className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">XDR — Cross-Domain Threat Vectors</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>
              {typeof value === "number" ? value.toLocaleString() : value}
            </span>
          </div>
        ))}
      </div>

      {/* Severity filter */}
      <div className="flex gap-2 flex-wrap">
        {["all", "critical", "high", "medium", "low"].map(s => (
          <button
            key={s}
            onClick={() => setSevFilter(s)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              sevFilter === s ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {s === "all" ? `All (${vectors.length})` : `${s} (${vectors.filter(v => v.severity === s).length})`}
          </button>
        ))}
      </div>

      {/* Vectors table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={Layers}
          title="No threat vectors"
          description="Threat vectors will appear once ingested via connectors or POST /api/v1/threat-vectors/vectors."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Name", "Type", "Severity", "Frequency", "Impact", "Last Observed"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 200).map((v, i) => (
                <tr key={v.vector_id ?? v.id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-medium max-w-[180px] truncate">{v.name ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground capitalize">{v.vector_type?.replace(/_/g, " ") ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[v.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                      {v.severity ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2 tabular-nums">{v.frequency_score != null ? `${v.frequency_score.toFixed(0)}` : "—"}</td>
                  <td className="px-3 py-2 tabular-nums">{v.impact_score != null ? `${v.impact_score.toFixed(0)}` : "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {v.last_observed ? new Date(v.last_observed).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
