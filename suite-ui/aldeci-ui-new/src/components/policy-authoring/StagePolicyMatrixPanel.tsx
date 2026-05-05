/**
 * StagePolicyMatrixPanel — PolicyAuthoringHub "stage-matrix" tab
 *
 * Wired to real backend:
 *   GET /api/v1/policy-enforcement/policies  → policy list with stage + severity
 *   GET /api/v1/policy-enforcement/stats     → KPI bar
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Grid3x3, ShieldCheck, AlertTriangle, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";

interface PolicyStats {
  total_policies?: number;
  active_policies?: number;
  blocked_stages?: number;
  enforced_count?: number;
}

interface Policy {
  policy_id?: string;
  id?: string;
  name?: string;
  stage?: string;
  severity?: string;
  action?: string;
  enabled?: boolean;
  created_at?: string;
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-700/80 text-orange-100",
  medium: "bg-amber-700/80 text-amber-100",
  low: "bg-blue-700/80 text-blue-100",
  info: "bg-slate-600/80 text-slate-100",
};

const ACTION_CLASS: Record<string, string> = {
  block: "bg-red-500/20 text-red-400",
  warn: "bg-amber-500/20 text-amber-400",
  allow: "bg-emerald-500/20 text-emerald-400",
  audit: "bg-sky-500/20 text-sky-400",
};

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["policies", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

export default function StagePolicyMatrixPanel() {
  const [stats, setStats] = useState<PolicyStats | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawPolicies] = await Promise.all([
        apiFetch<PolicyStats>("/api/v1/policy-enforcement/stats").catch(() => ({} as PolicyStats)),
        apiFetch<unknown>("/api/v1/policy-enforcement/policies"),
      ]);
      setStats(rawStats);
      setPolicies(extractArray<Policy>(rawPolicies));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policy data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Policies", value: stats?.total_policies ?? policies.length, icon: Grid3x3, color: "text-indigo-400" },
    { label: "Active", value: stats?.active_policies ?? 0, icon: ShieldCheck, color: "text-emerald-400" },
    { label: "Blocked Stages", value: stats?.blocked_stages ?? 0, icon: AlertTriangle, color: "text-red-400" },
    { label: "Enforced", value: stats?.enforced_count ?? 0, icon: ShieldCheck, color: "text-sky-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Grid3x3 className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Stage Policy Matrix</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      {policies.length === 0 ? (
        <EmptyState
          icon={Grid3x3}
          title="No policies configured"
          description="Create a stage policy via POST /api/v1/policy-enforcement/policies to populate this matrix."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Name", "Stage", "Severity", "Action", "Enabled", "Created"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {policies.slice(0, 200).map((p, i) => {
                const id = p.policy_id ?? p.id ?? String(i);
                return (
                  <tr key={id} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{p.name ?? id}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{p.stage ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEVERITY_CLASS[p.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {p.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${ACTION_CLASS[p.action?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {p.action ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`font-semibold ${p.enabled ? "text-emerald-400" : "text-muted-foreground"}`}>
                        {p.enabled ? "Yes" : "No"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {p.created_at ? new Date(p.created_at).toLocaleDateString() : "—"}
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
