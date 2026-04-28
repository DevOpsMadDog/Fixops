// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * System Health Dashboard - Live API
 * Route: /system-health
 * API: GET /api/v1/system/health, /api/v1/platform/health
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Activity, RefreshCw, CheckCircle, AlertTriangle, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const statusIcon = (s: string) => s === "healthy" || s === "ok" ? <CheckCircle className="w-4 h-4 text-emerald-400" />
  : s === "degraded" || s === "warning" ? <AlertTriangle className="w-4 h-4 text-amber-400" />
  : <XCircle className="w-4 h-4 text-red-400" />;

export default function SystemHealthDashboard() {
  const [health, setHealth] = useState<any | null>(null);
  const [engines, setEngines] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, p] = await Promise.allSettled([
        apiFetch<any>("/api/v1/system/health"),
        apiFetch<any>("/api/v1/platform/health"),
      ]);
      if (s.status === "fulfilled") { setHealth(s.value); }
      if (p.status === "fulfilled") {
        const v = p.value as any;
        if (Array.isArray(v?.engines)) setEngines(v.engines);
        else if (Array.isArray(v?.components)) setEngines(v.components);
        else if (Array.isArray(v)) setEngines(v);
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const score = health?.score ?? health?.health_score ?? 0;
  const scoreColor = score >= 90 ? "text-emerald-400" : score >= 70 ? "text-amber-400" : "text-red-400";
  const healthy = engines.filter(e => e.status === "healthy" || e.status === "ok").length;
  const degraded = engines.filter(e => e.status === "degraded" || e.status === "warning").length;
  const down = engines.filter(e => e.status === "down" || e.status === "error" || e.status === "unhealthy").length;

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="System Health"
        description="Live health monitoring of all backend engines"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : !health && engines.length === 0 ? <EmptyState icon={Activity} title="No health data" description="Health endpoint returned no data." />
        : <>
          {health && <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="bg-gray-800 rounded-lg p-8 flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Overall Health Score</p>
              <p className={cn("text-7xl font-black", scoreColor)}>{score}</p>
              <p className="text-gray-500 text-sm mt-1">{health.status ?? "—"}</p>
            </div>
            <Activity className={cn("w-24 h-24", scoreColor)} />
          </motion.div>}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Engines" value={engines.length || (health?.total_engines ?? 0)} icon={Activity} />
            <KpiCard title="Healthy" value={healthy} icon={CheckCircle} />
            <KpiCard title="Degraded" value={degraded} icon={AlertTriangle} />
            <KpiCard title="Down" value={down} icon={XCircle} />
          </div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Engine Status</CardTitle></CardHeader>
            <CardContent className="p-0">
              {engines.length === 0 ? <p className="p-6 text-gray-500 text-sm">No engine data.</p>
                : <Table>
                  <TableHeader><TableRow><TableHead>Engine</TableHead><TableHead>Status</TableHead><TableHead>Latency</TableHead><TableHead>Last Check</TableHead></TableRow></TableHeader>
                  <TableBody>{engines.map(e => (
                    <TableRow key={e.id ?? e.name} className="border-b border-gray-700/50">
                      <TableCell className="text-sm text-gray-200">{e.name ?? e.engine_name}</TableCell>
                      <TableCell><span className="inline-flex items-center gap-1 text-xs">{statusIcon(e.status)}<span className="capitalize">{e.status}</span></span></TableCell>
                      <TableCell className="text-xs text-gray-400 font-mono">{e.latency_ms !== undefined ? `${e.latency_ms}ms` : "—"}</TableCell>
                      <TableCell className="text-xs text-gray-400">{e.last_check ?? "—"}</TableCell>
                    </TableRow>
                  ))}</TableBody>
                </Table>}
            </CardContent>
          </Card>
        </>}
    </div>
  );
}
