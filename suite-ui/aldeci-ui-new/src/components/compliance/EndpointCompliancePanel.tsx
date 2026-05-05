/**
 * EndpointCompliancePanel — ComplianceCoverageHub "endpoint" tab
 *
 * Wired to real backend:
 *   GET /api/v1/endpoint-compliance/stats                → KPI bar
 *   GET /api/v1/endpoint-compliance/endpoints            → endpoints table
 *   GET /api/v1/endpoint-compliance/department-compliance → department breakdown
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { MonitorCheck, RefreshCw, CheckCircle2, XCircle, Building2, Server } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface EndpointStats {
  total_endpoints?: number;
  compliant_endpoints?: number;
  non_compliant_endpoints?: number;
  unknown_endpoints?: number;
  overall_compliance_pct?: number;
  by_os?: Record<string, number>;
  by_status?: Record<string, number>;
}

interface Endpoint {
  endpoint_id: string;
  hostname?: string;
  ip_address?: string;
  os_type?: string;
  department?: string;
  compliance_status?: string;
  last_checked?: string;
  compliance_score?: number;
}

interface DepartmentCompliance {
  department: string;
  total_endpoints?: number;
  compliant_count?: number;
  compliance_pct?: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
    for (const k of ["items", "endpoints", "departments", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

const STATUS_CLASS: Record<string, string> = {
  compliant: "bg-emerald-700/70 text-emerald-100",
  non_compliant: "bg-red-700/70 text-red-100",
  unknown: "bg-slate-600/70 text-slate-100",
  partial: "bg-amber-600/70 text-amber-100",
};

// ── Component ─────────────────────────────────────────────────────────────────

export default function EndpointCompliancePanel() {
  const [stats, setStats] = useState<EndpointStats | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [departments, setDepartments] = useState<DepartmentCompliance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subtab, setSubtab] = useState<"endpoints" | "departments">("endpoints");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, epData, deptData] = await Promise.all([
        apiFetch<EndpointStats>("/api/v1/endpoint-compliance/stats"),
        apiFetch<unknown>("/api/v1/endpoint-compliance/endpoints"),
        apiFetch<unknown>("/api/v1/endpoint-compliance/department-compliance"),
      ]);
      setStats(statsData);
      setEndpoints(extractArray<Endpoint>(epData));
      setDepartments(extractArray<DepartmentCompliance>(deptData));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load endpoint compliance data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const pct = stats?.overall_compliance_pct ?? 0;
  const kpis = [
    { label: "Total Endpoints", value: stats?.total_endpoints ?? 0, icon: Server, color: "text-indigo-400" },
    { label: "Compliant", value: stats?.compliant_endpoints ?? 0, icon: CheckCircle2, color: "text-emerald-400" },
    { label: "Non-Compliant", value: stats?.non_compliant_endpoints ?? 0, icon: XCircle, color: "text-red-400" },
    { label: "Unknown", value: stats?.unknown_endpoints ?? 0, icon: MonitorCheck, color: "text-slate-400" },
    { label: "Coverage", value: `${pct}%`, icon: Building2, color: pct >= 80 ? "text-emerald-400" : pct >= 60 ? "text-amber-400" : "text-red-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-4"
    >
      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg border border-slate-700 bg-slate-800/60 p-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs text-muted-foreground">{label}</span>
            </div>
            <span className={`text-xl font-semibold ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["endpoints", "departments"] as const).map(k => (
          <button
            key={k}
            onClick={() => setSubtab(k)}
            className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
              subtab === k
                ? "bg-indigo-600 text-white"
                : "bg-slate-700/50 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {k === "endpoints" ? "Endpoints" : "By Department"}
          </button>
        ))}
        <Button size="sm" variant="ghost" className="ml-auto h-7 gap-1 text-xs" onClick={load}>
          <RefreshCw className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {/* Endpoints table */}
      {subtab === "endpoints" && (
        endpoints.length === 0
          ? <EmptyState title="No endpoints registered" description="Register endpoints to track compliance posture across your fleet." />
          : (
            <div className="overflow-x-auto rounded-lg border border-slate-700">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-700 bg-slate-800/80">
                    {["Hostname", "IP", "OS", "Department", "Status", "Score", "Last Checked"].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {endpoints.map((ep, i) => (
                    <tr key={ep.endpoint_id} className={`border-b border-slate-700/50 ${i % 2 === 0 ? "bg-slate-800/30" : ""} hover:bg-slate-700/30`}>
                      <td className="px-3 py-2 font-mono text-slate-200">{ep.hostname ?? ep.endpoint_id}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{ep.ip_address ?? "—"}</td>
                      <td className="px-3 py-2 text-slate-400">{ep.os_type ?? "—"}</td>
                      <td className="px-3 py-2 text-slate-400">{ep.department ?? "—"}</td>
                      <td className="px-3 py-2">
                        <Badge className={`text-[10px] ${STATUS_CLASS[ep.compliance_status?.toLowerCase() ?? ""] ?? "bg-slate-600/70 text-slate-100"}`}>
                          {ep.compliance_status ?? "—"}
                        </Badge>
                      </td>
                      <td className="px-3 py-2">
                        {ep.compliance_score != null ? (
                          <span className={ep.compliance_score >= 80 ? "text-emerald-400 font-semibold" : ep.compliance_score >= 60 ? "text-amber-400 font-semibold" : "text-red-400 font-semibold"}>
                            {ep.compliance_score}%
                          </span>
                        ) : <span className="text-slate-500">—</span>}
                      </td>
                      <td className="px-3 py-2 text-slate-500">{ep.last_checked ? new Date(ep.last_checked).toLocaleDateString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
      )}

      {/* Department breakdown */}
      {subtab === "departments" && (
        departments.length === 0
          ? <EmptyState title="No department data" description="Endpoint checks with department tags will appear here." />
          : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {departments.map(dept => {
                const deptPct = dept.compliance_pct ?? 0;
                const color = deptPct >= 80 ? "text-emerald-400" : deptPct >= 60 ? "text-amber-400" : "text-red-400";
                const barColor = deptPct >= 80 ? "bg-emerald-500" : deptPct >= 60 ? "bg-amber-500" : "bg-red-500";
                return (
                  <div key={dept.department} className="rounded-lg border border-slate-700 bg-slate-800/50 p-3 flex flex-col gap-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-200 flex items-center gap-1.5">
                        <Building2 className="h-3.5 w-3.5 text-slate-400" />
                        {dept.department}
                      </span>
                      <span className={`text-sm font-bold ${color}`}>{deptPct}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-slate-700 rounded-full overflow-hidden">
                      <div className={`h-full ${barColor} rounded-full transition-all`} style={{ width: `${deptPct}%` }} />
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {dept.compliant_count ?? 0} / {dept.total_endpoints ?? 0} endpoints compliant
                    </span>
                  </div>
                );
              })}
            </div>
          )
      )}
    </motion.div>
  );
}
