/**
 * ServiceNowPanel — IntegrationTargetsHub "servicenow" tab
 *
 * Wired to real backend:
 *   GET /api/v1/servicenow/               → capability summary + health badge
 *   GET /api/v1/servicenow/api/now/table/incident  → incident list
 *   GET /api/v1/servicenow/api/now/table/cmdb_ci   → CMDB CI count
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Workflow, RefreshCw, AlertCircle, CheckCircle2, Clock } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface CapabilitySummary {
  service: string;
  status: string;
  servicenow_url_present: boolean;
  servicenow_user_present: boolean;
  servicenow_password_present: boolean;
  endpoints: string[];
}

interface SNIncident {
  sys_id?: string;
  number?: string;
  short_description?: string;
  state?: string | number;
  urgency?: string | number;
  impact?: string | number;
  category?: string;
  opened_at?: string;
  assignment_group?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const URGENCY_LABEL: Record<string, string> = { "1": "High", "2": "Medium", "3": "Low" };
const STATE_LABEL: Record<string, string> = {
  "1": "New", "2": "In Progress", "3": "On Hold",
  "6": "Resolved", "7": "Closed", "8": "Canceled",
};
const STATE_CLASS: Record<string, string> = {
  "1": "bg-blue-700/70 text-blue-100",
  "2": "bg-indigo-600/70 text-indigo-100",
  "3": "bg-amber-600/70 text-amber-100",
  "6": "bg-emerald-700/70 text-emerald-100",
  "7": "bg-slate-600/70 text-slate-200",
  "8": "bg-red-700/70 text-red-100",
};

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractIncidents(data: unknown): SNIncident[] {
  if (Array.isArray(data)) return data as SNIncident[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["result", "incidents", "items", "records"]) {
      if (Array.isArray(obj[k])) return obj[k] as SNIncident[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ServiceNowPanel() {
  const [capability, setCapability] = useState<CapabilitySummary | null>(null);
  const [incidents, setIncidents] = useState<SNIncident[]>([]);
  const [cmdbCount, setCmdbCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const cap = await apiFetch<CapabilitySummary>("/api/v1/servicenow/");
      setCapability(cap);

      if (cap.status === "ok") {
        const [incData, cmdbData] = await Promise.allSettled([
          apiFetch<unknown>("/api/v1/servicenow/api/now/table/incident?sysparm_limit=100"),
          apiFetch<unknown>("/api/v1/servicenow/api/now/table/cmdb_ci?sysparm_limit=1"),
        ]);
        if (incData.status === "fulfilled") setIncidents(extractIncidents(incData.value));
        if (cmdbData.status === "fulfilled") {
          const d = cmdbData.value as Record<string, unknown>;
          const arr = Array.isArray(d) ? d : (Array.isArray(d?.result) ? d.result as unknown[] : []);
          setCmdbCount(typeof d?.total === "number" ? d.total : arr.length);
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load ServiceNow data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const connected = capability?.status === "ok";

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
          <Workflow className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">ServiceNow ITSM</span>
          <Badge
            variant="outline"
            className={connected
              ? "border-emerald-600 text-emerald-400"
              : "border-amber-600 text-amber-400"}
          >
            {connected ? "Connected" : capability?.status ?? "Unknown"}
          </Badge>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {/* Config status cards */}
      {capability && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label: "Instance URL", ok: capability.servicenow_url_present },
            { label: "Username", ok: capability.servicenow_user_present },
            { label: "Password", ok: capability.servicenow_password_present },
          ].map(({ label, ok }) => (
            <div key={label} className="flex items-center gap-2 rounded-lg bg-muted/40 border border-border px-4 py-3">
              {ok
                ? <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                : <AlertCircle className="h-4 w-4 text-amber-400 shrink-0" />}
              <div>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="text-sm font-medium">{ok ? "Configured" : "Not set"}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* KPI row */}
      {connected && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {[
            { label: "Open Incidents", value: incidents.filter(i => String(i.state) === "1").length, color: "text-red-400" },
            { label: "In Progress", value: incidents.filter(i => String(i.state) === "2").length, color: "text-indigo-400" },
            { label: "CMDB CIs", value: cmdbCount ?? "—", color: "text-slate-300" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
              <span className="text-xs text-muted-foreground">{label}</span>
              <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
            </div>
          ))}
        </div>
      )}

      {/* Incidents table */}
      {!connected ? (
        <EmptyState
          icon={<Workflow className="h-8 w-8 text-amber-400" />}
          title="ServiceNow not configured"
          description="Set SERVICENOW_URL, SERVICENOW_USER, and SERVICENOW_PASSWORD environment variables to connect."
        />
      ) : incidents.length === 0 ? (
        <EmptyState
          icon={<CheckCircle2 className="h-8 w-8 text-emerald-400" />}
          title="No incidents"
          description="No incidents returned from ServiceNow."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Number", "Short Description", "State", "Urgency", "Category", "Opened"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {incidents.slice(0, 100).map((inc, i) => {
                const stateStr = String(inc.state ?? "");
                return (
                  <tr key={inc.sys_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-mono text-indigo-400">{inc.number ?? "—"}</td>
                    <td className="px-3 py-2 max-w-[200px] truncate font-medium">{inc.short_description ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATE_CLASS[stateStr] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {STATE_LABEL[stateStr] ?? inc.state ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {URGENCY_LABEL[String(inc.urgency ?? "")] ?? inc.urgency ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">{inc.category ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {inc.opened_at
                        ? new Date(inc.opened_at).toLocaleDateString()
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
