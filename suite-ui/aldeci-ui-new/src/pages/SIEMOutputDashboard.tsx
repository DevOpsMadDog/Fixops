/**
 * SIEM Output Dashboard - Live API
 * Route: /siem-output
 * API: GET /api/v1/siem-output/{targets,events,stats}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Send, RefreshCw, CheckCircle, XCircle } from "lucide-react";
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

export default function SIEMOutputDashboard() {
  const [targets, setTargets] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [t, e, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/siem-output/targets"),
        apiFetch<any>("/api/v1/siem-output/events"),
        apiFetch<any>("/api/v1/siem-output/stats"),
      ]);
      if (t.status === "fulfilled") { const v = t.value as any; setTargets(Array.isArray(v) ? v : (v.targets ?? v.items ?? [])); }
      if (e.status === "fulfilled") { const v = e.value as any; setEvents(Array.isArray(v) ? v : (v.events ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (er) { setError((er as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="SIEM Output"
        description="SIEM connector targets, event delivery, throughput stats"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : targets.length === 0 && events.length === 0 ? <EmptyState icon={Send} title="No SIEM targets" description="Configure Splunk, Sentinel, or another SIEM target to start streaming." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Targets" value={targets.length} icon={Send} />
            <KpiCard title="Events Sent" value={stats?.events_sent ?? events.length} icon={Send} />
            <KpiCard title="Failures" value={stats?.failures ?? 0} icon={XCircle} />
            <KpiCard title="Throughput/s" value={stats?.throughput_per_sec ?? "—"} icon={Send} />
          </motion.div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Targets</CardTitle></CardHeader>
            <CardContent className="p-0">
              {targets.length === 0 ? <p className="p-6 text-gray-500 text-sm">No targets configured.</p>
                : <Table>
                  <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Type</TableHead><TableHead>Endpoint</TableHead><TableHead>Status</TableHead><TableHead>Last Event</TableHead></TableRow></TableHeader>
                  <TableBody>{targets.map(t => (
                    <TableRow key={t.id ?? t.name} className="border-b border-gray-700/50">
                      <TableCell className="text-sm text-gray-200">{t.name}</TableCell>
                      <TableCell><Badge variant="outline" className="text-xs">{t.target_type ?? t.type}</Badge></TableCell>
                      <TableCell className="text-xs font-mono text-gray-400 max-w-xs truncate">{t.endpoint ?? t.url ?? "—"}</TableCell>
                      <TableCell><span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs", t.healthy || t.status === "connected" ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400")}>{t.healthy || t.status === "connected" ? <CheckCircle className="w-3 h-3" /> : <XCircle className="w-3 h-3" />}{t.status ?? (t.healthy ? "healthy" : "down")}</span></TableCell>
                      <TableCell className="text-xs text-gray-400">{t.last_event ?? "—"}</TableCell>
                    </TableRow>
                  ))}</TableBody>
                </Table>}
            </CardContent>
          </Card>
          {events.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Recent Events</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Timestamp</TableHead><TableHead>Target</TableHead><TableHead>Event Type</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
                <TableBody>{events.slice(0, 50).map(e => (
                  <TableRow key={e.id} className="border-b border-gray-700/50">
                    <TableCell className="text-xs text-gray-400 font-mono">{e.timestamp ?? "—"}</TableCell>
                    <TableCell className="text-xs text-gray-300">{e.target ?? e.target_name}</TableCell>
                    <TableCell className="text-xs text-gray-400">{e.event_type ?? e.type}</TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs capitalize", e.status === "delivered" || e.status === "sent" ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400")}>{e.status}</span></TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
