/**
 * EDRPanel — DetectAndRespondHub "edr" tab
 *
 * Wired to real backend:
 *   GET /api/v1/endpoint-hunting/stats    → KPI bar
 *   GET /api/v1/endpoint-hunting/hunts    → hunt campaigns table
 *   GET /api/v1/endpoint-hunting/findings → endpoint findings
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Monitor, Bug, Target, Activity, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface EDRStats {
  total_hunts?: number;
  active_hunts?: number;
  total_findings?: number;
  endpoints_scanned?: number;
  org_id?: string;
}

interface HuntCampaign {
  hunt_id?: string;
  id?: string;
  hunt_name?: string;
  name?: string;
  status?: string;
  hunt_type?: string;
  hypothesis?: string;
  hunter?: string;
  started_at?: string;
  created_at?: string;
}

interface HuntFinding {
  finding_id?: string;
  id?: string;
  endpoint_id?: string;
  finding_type?: string;
  severity?: string;
  process_name?: string;
  status?: string;
  detected_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

const STATUS_VARIANT: Record<string, string> = {
  active: "text-emerald-400",
  completed: "text-slate-400",
  planned: "text-blue-400",
  cancelled: "text-red-400",
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
    for (const k of ["hunts", "findings", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function EDRPanel() {
  const [stats, setStats] = useState<EDRStats | null>(null);
  const [hunts, setHunts] = useState<HuntCampaign[]>([]);
  const [findings, setFindings] = useState<HuntFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subTab, setSubTab] = useState<"hunts" | "findings">("hunts");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawHunts, rawFindings] = await Promise.all([
        apiFetch<EDRStats>("/api/v1/endpoint-hunting/stats"),
        apiFetch<unknown>("/api/v1/endpoint-hunting/hunts"),
        apiFetch<unknown>("/api/v1/endpoint-hunting/findings"),
      ]);
      setStats(rawStats);
      setHunts(extractArray<HuntCampaign>(rawHunts));
      setFindings(extractArray<HuntFinding>(rawFindings));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load EDR data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Hunt Campaigns", value: stats?.total_hunts ?? hunts.length, icon: Target, color: "text-slate-300" },
    { label: "Active Hunts", value: stats?.active_hunts ?? hunts.filter(h => h.status === "active").length, icon: Activity, color: "text-emerald-400" },
    { label: "Findings", value: stats?.total_findings ?? findings.length, icon: Bug, color: "text-orange-400" },
    { label: "Endpoints Scanned", value: stats?.endpoints_scanned ?? 0, icon: Monitor, color: "text-indigo-400" },
  ];

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
          <Monitor className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">EDR — Endpoint Threat Hunting</span>
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

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["hunts", "findings"] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              subTab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "hunts" ? `Campaigns (${hunts.length})` : `Findings (${findings.length})`}
          </button>
        ))}
      </div>

      {/* Hunts table */}
      {subTab === "hunts" && (
        hunts.length === 0 ? (
          <EmptyState
            icon={Target}
            title="No hunt campaigns"
            description="Endpoint hunt campaigns will appear once created via the hunting engine."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Campaign", "Type", "Status", "Hunter", "Started"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {hunts.slice(0, 200).map((h, i) => (
                  <tr key={h.hunt_id ?? h.id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium max-w-[200px] truncate">{h.hunt_name ?? h.name ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{h.hunt_type ?? "—"}</td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className={`text-[10px] ${STATUS_VARIANT[h.status?.toLowerCase() ?? ""] ?? ""}`}>
                        {h.status ?? "—"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">{h.hunter || "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {(h.started_at ?? h.created_at) ? new Date((h.started_at ?? h.created_at)!).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Findings table */}
      {subTab === "findings" && (
        findings.length === 0 ? (
          <EmptyState
            icon={Bug}
            title="No findings"
            description="Endpoint findings will appear once hunt campaigns produce results."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Endpoint", "Type", "Severity", "Process", "Status", "Detected"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings.slice(0, 200).map((f, i) => (
                  <tr key={f.finding_id ?? f.id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 text-muted-foreground">{f.endpoint_id || "—"}</td>
                    <td className="px-3 py-2 font-medium capitalize">{f.finding_type ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[f.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {f.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground max-w-[120px] truncate">{f.process_name || "—"}</td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="text-[10px]">{f.status ?? "—"}</Badge>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {f.detected_at ? new Date(f.detected_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </motion.div>
  );
}
