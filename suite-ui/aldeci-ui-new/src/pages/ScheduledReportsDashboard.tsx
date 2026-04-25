/**
 * Scheduled Reports Dashboard - Live API
 * Route: /scheduled-reports
 * API: GET /api/v1/scheduled-reports/{schedules,history,templates,stats}
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Calendar, RefreshCw, Mail, FileText } from "lucide-react";
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

export default function ScheduledReportsDashboard() {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [templates, setTemplates] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, h, t, st] = await Promise.allSettled([
        apiFetch<any>("/api/v1/scheduled-reports/schedules"),
        apiFetch<any>("/api/v1/scheduled-reports/history"),
        apiFetch<any>("/api/v1/scheduled-reports/templates"),
        apiFetch<any>("/api/v1/scheduled-reports/stats"),
      ]);
      if (s.status === "fulfilled") { const v = s.value as any; setSchedules(Array.isArray(v) ? v : (v.schedules ?? v.items ?? [])); }
      if (h.status === "fulfilled") { const v = h.value as any; setHistory(Array.isArray(v) ? v : (v.history ?? v.items ?? [])); }
      if (t.status === "fulfilled") { const v = t.value as any; setTemplates(Array.isArray(v) ? v : (v.templates ?? v.items ?? [])); }
      if (st.status === "fulfilled") { setStats(st.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Scheduled Reports"
        description="Report schedules, delivery history, templates"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : schedules.length === 0 && templates.length === 0 ? <EmptyState icon={Calendar} title="No reports scheduled" description="Create a schedule to deliver reports via email or webhook." />
        : <>
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Active Schedules" value={stats?.active_schedules ?? schedules.filter(s => s.enabled !== false).length} icon={Calendar} />
            <KpiCard title="Reports Sent" value={stats?.reports_sent ?? history.filter(h => h.status === "sent" || h.status === "delivered").length} icon={Mail} />
            <KpiCard title="Failures" value={stats?.failures ?? history.filter(h => h.status === "failed").length} icon={Mail} />
            <KpiCard title="Templates" value={stats?.templates ?? templates.length} icon={FileText} />
          </motion.div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Schedules</CardTitle></CardHeader>
            <CardContent className="p-0">
              {schedules.length === 0 ? <p className="p-6 text-gray-500 text-sm">No schedules.</p>
                : <Table>
                  <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Cron</TableHead><TableHead>Recipients</TableHead><TableHead>Format</TableHead><TableHead>Next Run</TableHead><TableHead>Enabled</TableHead></TableRow></TableHeader>
                  <TableBody>{schedules.map(s => (
                    <TableRow key={s.id} className="border-b border-gray-700/50">
                      <TableCell className="text-sm text-gray-200">{s.name ?? s.schedule_name}</TableCell>
                      <TableCell className="text-xs font-mono text-gray-400">{s.cron ?? s.schedule}</TableCell>
                      <TableCell className="text-xs text-gray-400 max-w-xs truncate">{Array.isArray(s.recipients) ? s.recipients.join(", ") : (s.recipients ?? "—")}</TableCell>
                      <TableCell><Badge variant="outline" className="text-xs">{s.format ?? "PDF"}</Badge></TableCell>
                      <TableCell className="text-xs text-gray-400">{s.next_run ?? "—"}</TableCell>
                      <TableCell><span className={cn("px-2 py-0.5 rounded text-xs", (s.enabled ?? true) ? "bg-emerald-500/20 text-emerald-400" : "bg-gray-500/20 text-gray-400")}>{(s.enabled ?? true) ? "Yes" : "No"}</span></TableCell>
                    </TableRow>
                  ))}</TableBody>
                </Table>}
            </CardContent>
          </Card>
          {history.length > 0 && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Delivery History</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Report</TableHead><TableHead>Status</TableHead><TableHead>Delivered</TableHead><TableHead>Recipients</TableHead></TableRow></TableHeader>
                <TableBody>{history.slice(0, 50).map(h => (
                  <TableRow key={h.id} className="border-b border-gray-700/50">
                    <TableCell className="text-sm text-gray-300">{h.report_name ?? h.name}</TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs capitalize", h.status === "sent" || h.status === "delivered" ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400")}>{h.status}</span></TableCell>
                    <TableCell className="text-xs text-gray-400">{h.delivered_at ?? h.timestamp ?? "—"}</TableCell>
                    <TableCell className="text-xs text-gray-400">{h.recipient_count ?? (Array.isArray(h.recipients) ? h.recipients.length : "—")}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
