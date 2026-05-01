// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
// FOLDED into IntegrationTargetsHub hero (servicenow tab) 2026-05-02 — preserve for git history
/**
 * ServiceNow Integration Dashboard - Live API
 * Route: /servicenow
 * API: GET /api/v1/servicenow/{connections,incidents,cmdb,mappings}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Workflow, RefreshCw, CheckCircle, XCircle } from "lucide-react";
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

export default function ServiceNowDashboard() {
  const [connections, setConnections] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [cmdb, setCmdb] = useState<any[]>([]);
  const [mappings, setMappings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [c, i, cm, m] = await Promise.allSettled([
        apiFetch<any>("/api/v1/servicenow/connections"),
        apiFetch<any>("/api/v1/servicenow/incidents"),
        apiFetch<any>("/api/v1/servicenow/cmdb"),
        apiFetch<any>("/api/v1/servicenow/mappings"),
      ]);
      if (c.status === "fulfilled") { const v = c.value as any; setConnections(Array.isArray(v) ? v : (v.connections ?? v.items ?? [])); }
      if (i.status === "fulfilled") { const v = i.value as any; setIncidents(Array.isArray(v) ? v : (v.incidents ?? v.items ?? [])); }
      if (cm.status === "fulfilled") { const v = cm.value as any; setCmdb(Array.isArray(v) ? v : (v.items ?? v.cmdb ?? [])); }
      if (m.status === "fulfilled") { const v = m.value as any; setMappings(Array.isArray(v) ? v : (v.mappings ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="ServiceNow Integration"
        description="Connection status, incident sync, CMDB sync, field mappings"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : connections.length === 0 && incidents.length === 0 ? <EmptyState icon={Workflow} title="No ServiceNow connection" description="Connect your ServiceNow instance to enable bidirectional sync." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Connections" value={connections.length} icon={Workflow} />
            <KpiCard title="Incidents" value={incidents.length} icon={Workflow} />
            <KpiCard title="CMDB Items" value={cmdb.length} icon={Workflow} />
            <KpiCard title="Mappings" value={mappings.length} icon={Workflow} />
          </motion.div>
          {connections.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Connections</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Instance</TableHead><TableHead>Status</TableHead><TableHead>Last Sync</TableHead><TableHead>Direction</TableHead></TableRow></TableHeader>
                <TableBody>{connections.map(c => (
                  <TableRow key={c.id ?? c.instance} className="border-b border-gray-700/50">
                    <TableCell className="text-sm font-mono text-gray-200">{c.instance ?? c.name}</TableCell>
                    <TableCell><span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs", c.status === "connected" || c.healthy ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400")}>{c.status === "connected" || c.healthy ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}{c.status ?? (c.healthy ? "connected" : "disconnected")}</span></TableCell>
                    <TableCell className="text-xs text-gray-400">{c.last_sync ?? "—"}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{c.direction ?? "bidirectional"}</Badge></TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
          {incidents.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Incidents</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Number</TableHead><TableHead>Short Description</TableHead><TableHead>Priority</TableHead><TableHead>State</TableHead><TableHead>Assignee</TableHead></TableRow></TableHeader>
                <TableBody>{incidents.slice(0, 50).map(i => (
                  <TableRow key={i.id ?? i.number} className="border-b border-gray-700/50">
                    <TableCell className="text-xs font-mono text-cyan-300">{i.number ?? i.id}</TableCell>
                    <TableCell className="text-sm text-gray-300 max-w-xs truncate">{i.short_description ?? i.title}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{i.priority ?? "—"}</Badge></TableCell>
                    <TableCell className="text-xs text-gray-400 capitalize">{i.state ?? i.status}</TableCell>
                    <TableCell className="text-xs text-gray-400">{i.assigned_to ?? i.assignee ?? "—"}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
