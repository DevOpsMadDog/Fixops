/**
 * HooksStatusPanel — PolicyAuthoringHub "hooks-status" tab
 *
 * Wired to real backend:
 *   GET /api/v1/policy-enforcement/hooks/status  → live hook runtime status list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Activity, CheckCircle2, XCircle, Clock, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";

interface HookStatus {
  hook_id?: string;
  id?: string;
  name?: string;
  hook_type?: string;
  stage?: string;
  status?: string;
  last_triggered?: string;
  trigger_count?: number;
  error_count?: number;
  avg_duration_ms?: number;
}

interface StatsBlock {
  total?: number;
  healthy?: number;
  errored?: number;
  idle?: number;
}

const STATUS_CLASS: Record<string, string> = {
  healthy: "bg-emerald-700/80 text-emerald-100",
  active: "bg-emerald-700/80 text-emerald-100",
  error: "bg-red-700/80 text-red-100",
  errored: "bg-red-700/80 text-red-100",
  idle: "bg-slate-600/80 text-slate-100",
  disabled: "bg-slate-700/60 text-slate-300",
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
    for (const k of ["hooks", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

function deriveStats(hooks: HookStatus[]): StatsBlock {
  return {
    total: hooks.length,
    healthy: hooks.filter(h => ["healthy", "active"].includes(h.status?.toLowerCase() ?? "")).length,
    errored: hooks.filter(h => ["error", "errored"].includes(h.status?.toLowerCase() ?? "")).length,
    idle: hooks.filter(h => h.status?.toLowerCase() === "idle").length,
  };
}

export default function HooksStatusPanel() {
  const [hooks, setHooks] = useState<HookStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const raw = await apiFetch<unknown>("/api/v1/policy-enforcement/hooks/status");
      setHooks(extractArray<HookStatus>(raw));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load hook status");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const s = deriveStats(hooks);

  const kpis = [
    { label: "Total Hooks", value: s.total ?? 0, icon: Activity, color: "text-indigo-400" },
    { label: "Healthy", value: s.healthy ?? 0, icon: CheckCircle2, color: "text-emerald-400" },
    { label: "Errored", value: s.errored ?? 0, icon: XCircle, color: "text-red-400" },
    { label: "Idle", value: s.idle ?? 0, icon: Clock, color: "text-amber-400" },
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
          <Activity className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Hooks Runtime Status</span>
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

      {hooks.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No hooks registered"
          description="Register a pre/post hook via POST /api/v1/policy-enforcement/hooks to see runtime status here."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Name", "Type", "Stage", "Status", "Triggers", "Errors", "Avg ms", "Last Triggered"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {hooks.slice(0, 200).map((h, i) => {
                const id = h.hook_id ?? h.id ?? String(i);
                return (
                  <tr key={id} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{h.name ?? id}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{h.hook_type ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{h.stage ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${STATUS_CLASS[h.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {h.status ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums">{h.trigger_count ?? 0}</td>
                    <td className="px-3 py-2 tabular-nums text-red-400">{h.error_count ?? 0}</td>
                    <td className="px-3 py-2 tabular-nums text-muted-foreground">
                      {h.avg_duration_ms != null ? h.avg_duration_ms.toFixed(0) : "—"}
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {h.last_triggered ? new Date(h.last_triggered).toLocaleString() : "—"}
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
