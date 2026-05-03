// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Violation Lifecycle Dashboard
 *
 * Finding/violation lifecycle reconciliation — open → triaged → resolved → verified.
 * Route: /violation-lifecycle
 * API: GET /api/v1/findings/lifecycle/summary; POST /api/v1/findings/lifecycle/reconcile
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, Zap, CheckCircle2, Clock, AlertTriangle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface StateCount { state?: string; count?: number }
interface TransitionRow { from_state?: string; to_state?: string; count?: number; avg_mins?: number }
interface Summary {
  states?: StateCount[];
  transitions?: TransitionRow[];
  total?: number;
  avg_cycle_time_hours?: number;
  reopened_count?: number;
  verified_count?: number;
  last_reconciled_at?: string;
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function stateColor(s?: string): string {
  const key = (s ?? "").toLowerCase();
  if (key.includes("open") || key.includes("new"))      return "bg-red-500/30 text-red-300 border-red-500/40";
  if (key.includes("triage") || key.includes("assign")) return "bg-yellow-500/30 text-yellow-300 border-yellow-500/40";
  if (key.includes("progress") || key.includes("fix"))  return "bg-blue-500/30 text-blue-300 border-blue-500/40";
  if (key.includes("verif") || key.includes("close"))   return "bg-green-500/30 text-green-300 border-green-500/40";
  if (key.includes("reopen"))                           return "bg-orange-500/30 text-orange-300 border-orange-500/40";
  return "bg-muted/60 text-muted-foreground border-border";
}

export default function ViolationLifecycleDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const s = await apiFetch<Summary>("/api/v1/findings/lifecycle/summary");
      setSummary(s ?? null);
    } catch (e) { setErr((e as Error).message); setSummary(null); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleReconcile = async () => {
    setReconciling(true);
    try {
      await apiFetch("/api/v1/findings/lifecycle/reconcile", { method: "POST", body: JSON.stringify({}) });
      await load();
    } catch (e) { setErr((e as Error).message); }
    finally { setReconciling(false); }
  };

  const states = summary?.states ?? [];
  const transitions = summary?.transitions ?? [];
  const total = summary?.total ?? states.reduce((s, x) => s + (x.count ?? 0), 0);
  const cycleHrs = summary?.avg_cycle_time_hours ?? 0;
  const reopened = summary?.reopened_count ?? 0;
  const verified = summary?.verified_count ?? 0;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Violation Lifecycle"
        description="End-to-end finding lifecycle — open → triage → fix → verify. Reconcile state drift across scanners."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" onClick={handleReconcile} disabled={reconciling}>
              <Zap className={cn("h-4 w-4 mr-2", reconciling && "animate-pulse")} />
              Reconcile Now
            </Button>
          </div>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Violations" value={total} icon={Activity} />
        <KpiCard title="Avg Cycle (hrs)" value={cycleHrs} icon={Clock} />
        <KpiCard title="Verified" value={verified} icon={CheckCircle2} trend="up" />
        <KpiCard title="Reopened" value={reopened} icon={AlertTriangle} trend="down" />
      </div>

      {loading ? (
        <div className="p-6 text-sm text-muted-foreground">Loading lifecycle…</div>
      ) : err ? (
        <ErrorState message={err} onRetry={load} />
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><Activity className="h-4 w-4" /> State Distribution</CardTitle>
              <CardDescription className="text-xs">Current counts by lifecycle state</CardDescription>
            </CardHeader>
            <CardContent>
              {states.length === 0 ? (
                <EmptyState icon={Activity} title="No violations" description="Lifecycle data will appear once findings exist." />
              ) : (
                <div className="space-y-2">
                  {states.map((s, i) => {
                    const pct = total > 0 ? Math.round(((s.count ?? 0) / total) * 100) : 0;
                    return (
                      <div key={i}>
                        <div className="flex justify-between items-center text-[11px] mb-1">
                          <Badge className={cn("text-[10px] border capitalize", stateColor(s.state))}>{s.state ?? "—"}</Badge>
                          <span className="font-mono text-muted-foreground">{s.count ?? 0} ({pct}%)</span>
                        </div>
                        <div className="w-full bg-muted/40 rounded-full h-1.5">
                          <div className="h-1.5 rounded-full bg-primary" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><Clock className="h-4 w-4" /> Transitions</CardTitle>
              <CardDescription className="text-xs">State-to-state transitions and average dwell time</CardDescription>
            </CardHeader>
            <CardContent>
              {transitions.length === 0 ? (
                <EmptyState icon={Clock} title="No transitions" description="No state transitions recorded yet." />
              ) : (
                <div className="space-y-1.5 text-[11px]">
                  {transitions.map((t, i) => (
                    <div key={i} className="flex items-center justify-between rounded border border-border/50 bg-muted/20 px-3 py-2">
                      <div className="flex items-center gap-2">
                        <Badge className={cn("text-[10px] border capitalize", stateColor(t.from_state))}>{t.from_state ?? "—"}</Badge>
                        <span className="text-muted-foreground">→</span>
                        <Badge className={cn("text-[10px] border capitalize", stateColor(t.to_state))}>{t.to_state ?? "—"}</Badge>
                      </div>
                      <div className="flex items-center gap-3 font-mono text-muted-foreground">
                        <span>{t.count ?? 0}×</span>
                        <span>{t.avg_mins ?? 0}m</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {summary?.last_reconciled_at && (
        <div className="text-[11px] text-muted-foreground">
          Last reconciled: {new Date(summary.last_reconciled_at).toLocaleString()}
        </div>
      )}
    </motion.div>
  );
}
