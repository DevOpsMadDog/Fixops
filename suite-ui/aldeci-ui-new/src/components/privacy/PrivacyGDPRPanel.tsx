/**
 * PrivacyGDPRPanel — PrivacyComplianceHub "gdpr" tab
 *
 * Wired to real backend:
 *   GET /api/v1/privacy/stats                    → KPI bar
 *   GET /api/v1/privacy/dsrs                     → DSR table
 *   GET /api/v1/privacy/consents                 → consent list
 *   GET /api/v1/privacy/incidents                → incident list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, FileText, AlertTriangle, RefreshCw, Scale } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ──────────────────────────────────────────────────────────────────────

interface PrivacyStats {
  total_dsrs?: number;
  pending_dsrs?: number;
  overdue_dsrs?: number;
  total_incidents?: number;
  incidents_requiring_notification?: number;
  total_consents?: number;
  withdrawn_consents?: number;
  total_processing_activities?: number;
}

interface DSR {
  request_id: string;
  request_type?: string;
  subject_email?: string;
  subject_name?: string;
  status?: string;
  regulation?: string;
  overdue?: boolean;
  created_at?: string;
  due_date?: string;
}

interface PrivacyIncident {
  incident_id: string;
  incident_type?: string;
  severity?: string;
  status?: string;
  records_affected?: number;
  dpa_notified?: boolean;
  created_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const STATUS_CLASS: Record<string, string> = {
  fulfilled: "bg-emerald-700/70 text-emerald-100",
  closed: "bg-emerald-700/70 text-emerald-100",
  processing: "bg-blue-600/70 text-blue-100",
  received: "bg-slate-600/70 text-slate-100",
  rejected: "bg-red-700/70 text-red-100",
  expired: "bg-orange-600/70 text-orange-100",
  open: "bg-amber-600/70 text-amber-100",
  contained: "bg-blue-600/70 text-blue-100",
};

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
    for (const k of ["items", "dsrs", "incidents", "consents", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function PrivacyGDPRPanel() {
  const [stats, setStats] = useState<PrivacyStats | null>(null);
  const [dsrs, setDsrs] = useState<DSR[]>([]);
  const [incidents, setIncidents] = useState<PrivacyIncident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subtab, setSubtab] = useState<"dsrs" | "incidents">("dsrs");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawDsrs, rawIncidents] = await Promise.all([
        apiFetch<PrivacyStats>("/api/v1/privacy/stats"),
        apiFetch<unknown>("/api/v1/privacy/dsrs"),
        apiFetch<unknown>("/api/v1/privacy/incidents"),
      ]);
      setStats(rawStats);
      setDsrs(extractArray<DSR>(rawDsrs));
      setIncidents(extractArray<PrivacyIncident>(rawIncidents));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load privacy data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total DSRs", value: stats?.total_dsrs ?? 0, icon: FileText, color: "text-slate-300" },
    { label: "Overdue DSRs", value: stats?.overdue_dsrs ?? 0, icon: AlertTriangle, color: "text-red-400" },
    { label: "Privacy Incidents", value: stats?.total_incidents ?? 0, icon: ShieldAlert, color: "text-orange-400" },
    { label: "Processing Activities", value: stats?.total_processing_activities ?? 0, icon: Scale, color: "text-indigo-400" },
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
          <ShieldAlert className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Privacy & GDPR Compliance</span>
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
              {value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["dsrs", "incidents"] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubtab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              subtab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "dsrs" ? `Data Subject Requests (${dsrs.length})` : `Incidents (${incidents.length})`}
          </button>
        ))}
      </div>

      {/* DSR table */}
      {subtab === "dsrs" && (
        dsrs.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No data subject requests"
            description="DSRs will appear once created via POST /api/v1/privacy/dsrs."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Type", "Subject", "Regulation", "Status", "Overdue", "Created"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {dsrs.slice(0, 200).map((d, i) => (
                  <tr key={d.request_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium capitalize">{d.request_type ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{d.subject_email ?? d.subject_name ?? "—"}</td>
                    <td className="px-3 py-2 uppercase text-muted-foreground">{d.regulation ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_CLASS[d.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {d.status ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      {d.overdue ? (
                        <Badge variant="destructive" className="text-[10px]">Overdue</Badge>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {d.created_at ? new Date(d.created_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Incidents table */}
      {subtab === "incidents" && (
        incidents.length === 0 ? (
          <EmptyState
            icon={AlertTriangle}
            title="No privacy incidents"
            description="Privacy incidents will appear once reported via POST /api/v1/privacy/incidents."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Type", "Severity", "Records Affected", "DPA Notified", "Status", "Created"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {incidents.slice(0, 200).map((inc, i) => (
                  <tr key={inc.incident_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium capitalize">{inc.incident_type ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[inc.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {inc.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-muted-foreground">
                      {inc.records_affected?.toLocaleString() ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      {inc.dpa_notified ? (
                        <Badge className="text-[10px] bg-emerald-700/70 text-emerald-100">Notified</Badge>
                      ) : (
                        <Badge variant="outline" className="text-[10px]">Pending</Badge>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_CLASS[inc.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {inc.status ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {inc.created_at ? new Date(inc.created_at).toLocaleDateString() : "—"}
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
