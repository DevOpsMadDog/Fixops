// FOLDED into HuntingHub hero (sessions tab) 2026-05-02 — preserve for git history
/**
 * Threat Hunting - Live API
 * Route: /threat-hunting (now redirects to /mission-control/hunt?tab=sessions)
 * API: GET /api/v1/hunting/sessions
 */
import { useState, useEffect } from "react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import { Crosshair, Activity, CheckCircle2, Clock, Search, Play, Eye, Target, Zap, Network, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
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

function statusBadge(s: string) {
  return s === "active" || s === "in_progress"
    ? <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">Active</Badge>
    : <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">Complete</Badge>;
}
function confidenceBadge(c: string) {
  const map: Record<string, string> = {
    high: "bg-red-500/20 text-red-400 border-red-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low: "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return <Badge className={cn("capitalize", map[c] ?? map.low)}>{c}</Badge>;
}

const TACTIC_OPTIONS = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "C2", "Exfiltration", "Impact"];
const DATA_SOURCES = ["Windows Event Logs", "DNS Logs", "Network Flow", "EDR Telemetry", "Proxy Logs", "Authentication Logs"];

export default function ThreatHuntingPage() {
  const [hunts, setHunts] = useState<any[]>([]);
  const [iocs, setIocs] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<any[]>([]);
  const [hypothesis, setHypothesis] = useState("");
  const [tactic, setTactic] = useState("");
  const [dataSource, setDataSource] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [h, i, c] = await Promise.allSettled([
        apiFetch<any>("/api/v1/hunting/sessions"),
        apiFetch<any>("/api/v1/hunting/iocs"),
        apiFetch<any>("/api/v1/hunting/coverage"),
      ]);
      if (h.status === "fulfilled") { const v = h.value as any; setHunts(Array.isArray(v) ? v : (v.sessions ?? v.hunts ?? v.items ?? [])); }
      if (i.status === "fulfilled") { const v = i.value as any; setIocs(Array.isArray(v) ? v : (v.iocs ?? v.items ?? [])); }
      if (c.status === "fulfilled") { const v = c.value as any; setCoverage(Array.isArray(v) ? v : (v.tactics ?? v.coverage ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const startHunt = async () => {
    if (!hypothesis.trim() || !tactic || !dataSource) return;
    setSubmitting(true);
    try {
      await apiFetch<any>("/api/v1/hunting/sessions", {
        method: "POST",
        body: JSON.stringify({ name: `${tactic}: ${hypothesis}`, hunter_email: "analyst@aldeci.local" }),
      });
      toast.success("Hunt session started", { description: `${tactic} via ${dataSource}` });
      setHypothesis(""); setTactic(""); setDataSource("");
      load();
    } catch (e) {
      toast.error("Failed to start hunt", { description: (e as Error).message });
    } finally { setSubmitting(false); }
  };

  if (loading) return <PageSkeleton />;

  const activeCount = hunts.filter(h => h.status === "active" || h.status === "in_progress").length;
  const findings = hunts.reduce((s, h) => s + (h.findings_count ?? 0), 0);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-screen bg-background">
      <PageHeader
        title="Threat Hunting"
        description="Proactive hypothesis-driven threat detection"
        actions={<Button size="sm" variant="outline" onClick={load} className="gap-2"><RefreshCw className="w-3.5 h-3.5" /> Refresh</Button>}
      />

      {error ? <ErrorState message={error} onRetry={load} />
        : hunts.length === 0 ? <EmptyState icon={Crosshair} title="No active hunts" description="Start a threat hunt with a hypothesis below." />
        : <>
          <motion.div className="grid grid-cols-2 gap-4 md:grid-cols-4" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
            <KpiCard title="Active Hunts" value={String(activeCount)} icon={<Activity className="h-4 w-4" />} trend="flat" />
            <KpiCard title="Total Hunts" value={String(hunts.length)} icon={<CheckCircle2 className="h-4 w-4" />} trend="up" />
            <KpiCard title="IOCs Discovered" value={String(iocs.length)} icon={<Search className="h-4 w-4" />} trend="up" />
            <KpiCard title="Findings" value={String(findings)} icon={<Clock className="h-4 w-4" />} trend="flat" />
          </motion.div>

          <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Target className="h-4 w-4 text-primary" /> Active Hunts <Badge className="ml-2 bg-blue-500/20 text-blue-400 border-blue-500/30">{activeCount} active</Badge></CardTitle></CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader><TableRow><TableHead>Hunt Name</TableHead><TableHead>MITRE Tactic</TableHead><TableHead>Status</TableHead><TableHead>Hunter</TableHead><TableHead>Started</TableHead><TableHead className="text-right">Findings</TableHead></TableRow></TableHeader>
                <TableBody>{hunts.map(h => (
                  <TableRow key={h.id ?? h.hunt_name} className="hover:bg-muted/30">
                    <TableCell className="font-medium max-w-[260px] truncate">{h.hunt_name ?? h.name}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{h.mitre_tactic ?? h.tactic ?? "—"}</Badge></TableCell>
                    <TableCell>{statusBadge(h.status)}</TableCell>
                    <TableCell className="text-muted-foreground">{h.hunter ?? h.hunter_email ?? "—"}</TableCell>
                    <TableCell className="text-muted-foreground">{h.started_date ?? h.created_at ?? "—"}</TableCell>
                    <TableCell className="text-right"><span className={cn("font-semibold", (h.findings_count ?? 0) > 0 ? "text-red-400" : "text-muted-foreground")}>{h.findings_count ?? 0}</span></TableCell>
                  </TableRow>
                ))}</TableBody>
              </Table>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Zap className="h-4 w-4 text-primary" /> Hypothesis Builder</CardTitle></CardHeader>
              <CardContent className="flex flex-col gap-3">
                <textarea className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none resize-none" rows={4} placeholder="Describe your hunt hypothesis..." value={hypothesis} onChange={e => setHypothesis(e.target.value)} />
                <select className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" value={tactic} onChange={e => setTactic(e.target.value)}>
                  <option value="">Select MITRE Tactic...</option>
                  {TACTIC_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
                <select className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" value={dataSource} onChange={e => setDataSource(e.target.value)}>
                  <option value="">Select Data Source...</option>
                  {DATA_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <Button className="w-full gap-2" disabled={!hypothesis.trim() || !tactic || !dataSource || submitting} onClick={startHunt}><Play className="h-4 w-4" /> {submitting ? "Starting..." : "Start Hunt"}</Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Eye className="h-4 w-4 text-primary" /> Recent IOC Discoveries <Badge className="ml-auto bg-red-500/20 text-red-400 border-red-500/30">{iocs.length} new</Badge></CardTitle></CardHeader>
              <CardContent className="flex flex-col gap-2">
                {iocs.length === 0 ? <p className="text-muted-foreground text-sm">No IOCs discovered yet.</p>
                  : iocs.map((ioc, i) => (
                    <div key={i} className="flex items-center gap-3 rounded-md border border-border p-2 text-sm">
                      <Badge variant="outline" className="shrink-0 text-xs w-20 justify-center">{ioc.ioc_type ?? ioc.type}</Badge>
                      <span className="font-mono text-xs text-foreground truncate flex-1">{ioc.value}</span>
                      <span className="text-muted-foreground text-xs truncate max-w-[120px]">{ioc.hunt_name ?? ioc.session ?? "—"}</span>
                      {confidenceBadge(ioc.confidence ?? "low")}
                    </div>
                  ))}
              </CardContent>
            </Card>
          </div>

          {coverage.length > 0 && <Card>
            <CardHeader><CardTitle className="flex items-center gap-2 text-base"><Network className="h-4 w-4 text-primary" /> MITRE ATT&CK Coverage <span className="ml-auto text-xs text-muted-foreground">{coverage.filter(t => t.covered).length}/{coverage.length} tactics covered</span></CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7">{coverage.map(t => (
                <div key={t.name} className={cn("rounded-md border p-2 text-center text-xs font-medium", t.covered ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" : "border-border bg-muted/20 text-muted-foreground")}>
                  <div className="truncate mb-1">{t.name}</div>
                  {t.covered ? <Badge className="text-[10px] px-1 py-0 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">Covered</Badge> : <Badge variant="outline" className="text-[10px] px-1 py-0 text-muted-foreground">Uncovered</Badge>}
                </div>
              ))}</div>
            </CardContent>
          </Card>}
        </>}
    </div>
  );
}
