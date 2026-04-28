// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
// FOLDED into Remediate hero 2026-04-27 — preserve for git history
// Tab path: /remediate?tab=patch
/**
 * Patch Management Dashboard - Live API
 * Route: /patch-management
 * API: GET /api/v1/patch-management/{patches,stats}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, RefreshCw, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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

const sevColor: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-500 text-black",
  low: "bg-emerald-500 text-white",
};
const statusColor: Record<string, string> = {
  deployed: "bg-emerald-500/20 text-emerald-400",
  in_progress: "bg-blue-500/20 text-blue-400",
  pending: "bg-amber-500/20 text-amber-400",
  failed: "bg-red-500/20 text-red-400",
};

export default function PatchManagementDashboard() {
  const [patches, setPatches] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [p, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/patch-management/patches"),
        apiFetch<any>("/api/v1/patch-management/stats"),
      ]);
      if (p.status === "fulfilled") { const v = p.value as any; setPatches(Array.isArray(v) ? v : (v.patches ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Patch Management"
        description="Patch lifecycle tracking with deployment success rates"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : patches.length === 0 ? <EmptyState icon={Shield} title="No patches tracked" description="Connect your patch management system to start tracking." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Patches" value={stats?.total_patches ?? patches.length} icon={Shield} />
            <KpiCard title="Critical Patches" value={stats?.critical_patches ?? patches.filter(p => p.severity === "critical").length} icon={AlertTriangle} />
            <KpiCard title="Undeployed Critical" value={stats?.undeployed_critical ?? patches.filter(p => p.severity === "critical" && p.status !== "deployed").length} icon={AlertTriangle} />
            <KpiCard title="Success Rate" value={stats?.success_rate !== undefined ? `${stats.success_rate}%` : "—"} icon={Shield} />
          </motion.div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Patches</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow className="border-gray-700/50"><TableHead>Patch</TableHead><TableHead>Type</TableHead><TableHead>Severity</TableHead><TableHead>Status</TableHead><TableHead className="text-right">Deployed</TableHead><TableHead className="text-right">Failed</TableHead></TableRow></TableHeader>
                <TableBody>{patches.map(p => (
                  <TableRow key={p.id} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                    <TableCell className="text-sm text-gray-200 max-w-xs truncate">{p.title ?? p.name}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{p.patch_type ?? p.type}</Badge></TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs font-bold capitalize", sevColor[p.severity] ?? "bg-gray-700 text-white")}>{p.severity}</span></TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs font-medium capitalize", statusColor[p.status] ?? "bg-gray-700 text-gray-300")}>{(p.status ?? "").replace("_", " ")}</span></TableCell>
                    <TableCell className="text-right text-emerald-400 font-semibold">{p.deployed_count ?? 0}</TableCell>
                    <TableCell className="text-right text-red-400 font-semibold">{p.failed_count ?? 0}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>
        </>}
    </div>
  );
}
