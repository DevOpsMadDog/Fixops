// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * SOC Triage Dashboard - Live API
 * Route: /soc-triage
 * API: GET /api/v1/soc-triage/{alerts,stats}, POST /api/v1/soc-triage/alerts/{id}/verdict
 */
import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, CheckCircle, RefreshCw, Brain, Send } from "lucide-react";
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

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...init, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const sevColor: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-500 text-black",
  low: "bg-emerald-500 text-white",
};
const classColor: Record<string, string> = {
  TP: "bg-red-500/20 text-red-400 border-red-500/30",
  FP: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  undetermined: "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

export default function SOCTriageDashboard() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [stats, setStats] = useState<any | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [verdictMsg, setVerdictMsg] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, s] = await Promise.allSettled([
        apiFetch<any>("/api/v1/soc-triage/alerts"),
        apiFetch<any>("/api/v1/soc-triage/stats"),
      ]);
      if (a.status === "fulfilled") { const v = a.value as any; setAlerts(Array.isArray(v) ? v : (v.alerts ?? v.items ?? [])); }
      if (s.status === "fulfilled") { setStats(s.value); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const submitVerdict = async (id: string, verdict: "confirm" | "dispute") => {
    try {
      await apiFetch<any>(`/api/v1/soc-triage/alerts/${id}/verdict`, { method: "POST", body: JSON.stringify({ verdict }) });
      setVerdictMsg(`Verdict ${verdict} submitted`);
      setTimeout(() => setVerdictMsg(null), 3000);
      load();
    } catch (e) { setError((e as Error).message); }
  };

  const selectedAlert = alerts.find(a => a.id === selected);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="SOC Alert Triage"
        description="ML-powered alert classification and analyst verdict workflow"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}
      />
      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : alerts.length === 0 ? <EmptyState icon={Shield} title="No alerts in queue" description="Alerts will appear here once SIEM ingestion is active." />
        : <>
          {verdictMsg && <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-lg px-4 py-2 text-sm">{verdictMsg}</div>}
          <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="New Alerts" value={stats?.new_alerts ?? alerts.filter(a => a.status === "new").length} icon={AlertTriangle} />
            <KpiCard title="True Positives" value={stats?.true_positives ?? alerts.filter(a => a.classification === "TP").length} icon={CheckCircle} />
            <KpiCard title="False Positives" value={stats?.false_positives ?? alerts.filter(a => a.classification === "FP").length} icon={Shield} />
            <KpiCard title="Escalated" value={stats?.escalated ?? alerts.filter(a => a.escalated).length} icon={Brain} />
          </motion.div>
          <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Alert Queue</CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Alert</TableHead><TableHead>Severity</TableHead><TableHead>AI Class</TableHead><TableHead>Confidence</TableHead><TableHead>MITRE</TableHead><TableHead>Action</TableHead></TableRow></TableHeader>
                <TableBody>{alerts.map(a => (
                  <TableRow key={a.id} onClick={() => setSelected(a.id)} className={cn("border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/30", selected === a.id && "bg-blue-900/20")}>
                    <TableCell className="text-sm text-gray-200 max-w-xs truncate">{a.title ?? a.alert_name}</TableCell>
                    <TableCell><span className={cn("px-2 py-0.5 rounded text-xs font-bold capitalize", sevColor[a.severity] ?? "bg-gray-700 text-white")}>{a.severity}</span></TableCell>
                    <TableCell><Badge className={cn("text-xs border", classColor[a.classification] ?? classColor.undetermined)}>{a.classification ?? "undetermined"}</Badge></TableCell>
                    <TableCell className="text-xs text-gray-300">{a.confidence !== undefined ? `${Math.round((a.confidence ?? 0) * 100)}%` : "—"}</TableCell>
                    <TableCell className="text-xs text-gray-400 font-mono">{a.mitre_technique ?? "—"}</TableCell>
                    <TableCell>{selected === a.id && <div className="flex gap-1">
                      <Button size="sm" variant="outline" className="h-6 text-xs gap-1" onClick={e => { e.stopPropagation(); submitVerdict(a.id, "confirm"); }}><Send className="w-3 h-3" /> Confirm</Button>
                      <Button size="sm" variant="outline" className="h-6 text-xs gap-1" onClick={e => { e.stopPropagation(); submitVerdict(a.id, "dispute"); }}>Dispute</Button>
                    </div>}</TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>
          {selectedAlert && <Card>
            <CardHeader><CardTitle className="text-sm font-semibold">Selected: {selectedAlert.title ?? selectedAlert.alert_name}</CardTitle></CardHeader>
            <CardContent>
              {selectedAlert.description && <p className="text-sm text-gray-300">{selectedAlert.description}</p>}
              {selectedAlert.source && <p className="text-xs text-gray-500 mt-2">Source: {selectedAlert.source}</p>}
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
