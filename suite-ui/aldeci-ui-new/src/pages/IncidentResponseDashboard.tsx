/**
 * Incident Response Dashboard — management view
 *
 * Full lifecycle incident management and playbook execution.
 * NOTE: IncidentTimeline.tsx exists at route /incident-timeline (different page).
 * This is the management/command view at /incident-response.
 *
 *   1. KPIs: Active Incidents, P1 Critical, MTTR, SLA Compliance
 *   2. Incidents table (12 rows)
 *   3. Response timeline stepper for first incident (6 steps, progress at step 3)
 *   4. Task checklist panel (8 tasks for active incident)
 *   5. Artifact list (5 artifacts)
 *
 * Route: /incident-response
 * API stubs: GET /api/v1/incidents  GET /api/v1/incidents/{id}/tasks
 */

import { useState, useEffect, useCallback } from "react";
import { useAutoRefresh } from "@/hooks/use-auto-refresh";
import { Pause, Play } from "lucide-react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Clock,
  Shield,
  Activity,
  RefreshCw,
  CheckCircle2,
  Circle,
  FileText,
  ExternalLink,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";
import { EntityLink } from "@/components/EntityLink";
import { LiveEventStream } from "@/components/shared/LiveEventStream";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const INCIDENTS = [
  { id: "INC-0421", title: "Ransomware detected on finance workstations",    type: "ransomware",   sev: "P1", status: "active",      analyst: "s.kim",     open: "6h 14m", slaDue: "2026-04-16 16:00", slaBreach: true  },
  { id: "INC-0420", title: "Credential stuffing attack on customer portal",   type: "phishing",     sev: "P1", status: "contained",   analyst: "a.wright",  open: "9h 02m", slaDue: "2026-04-16 19:00", slaBreach: false },
  { id: "INC-0419", title: "Suspected data exfiltration via cloud storage",   type: "data_breach",  sev: "P2", status: "investigating",analyst: "j.doe",     open: "1d 2h",  slaDue: "2026-04-17 08:00", slaBreach: false },
  { id: "INC-0418", title: "DDoS targeting public API endpoints",             type: "ddos",         sev: "P2", status: "mitigating",  analyst: "m.chen",    open: "3h 45m", slaDue: "2026-04-17 12:00", slaBreach: false },
  { id: "INC-0417", title: "Insider printing sensitive HR records",           type: "insider",      sev: "P2", status: "investigating",analyst: "r.patel",   open: "2d 4h",  slaDue: "2026-04-18 09:00", slaBreach: false },
  { id: "INC-0416", title: "Phishing campaign targeting executives",          type: "phishing",     sev: "P3", status: "contained",   analyst: "t.nguyen",  open: "4d 1h",  slaDue: "2026-04-19 10:00", slaBreach: false },
  { id: "INC-0415", title: "Malicious npm package in build pipeline",         type: "data_breach",  sev: "P2", status: "eradicated",  analyst: "k.wilson",  open: "5d 3h",  slaDue: "2026-04-20 11:00", slaBreach: false },
  { id: "INC-0414", title: "Brute force on SSH jump host",                    type: "phishing",     sev: "P3", status: "resolved",    analyst: "b.johnson", open: "6d 0h",  slaDue: "2026-04-21 14:00", slaBreach: false },
  { id: "INC-0413", title: "Unauthorized API key usage from foreign IP",      type: "insider",      sev: "P3", status: "resolved",    analyst: "d.smith",   open: "7d 2h",  slaDue: "2026-04-22 15:00", slaBreach: false },
  { id: "INC-0412", title: "Web application SQLi attempt on login form",      type: "data_breach",  sev: "P4", status: "resolved",    analyst: "p.brown",   open: "8d 0h",  slaDue: "2026-04-23 09:00", slaBreach: false },
  { id: "INC-0411", title: "Volume spike in outbound DNS queries",            type: "ddos",         sev: "P3", status: "resolved",    analyst: "n.taylor",  open: "9d 1h",  slaDue: "2026-04-24 10:00", slaBreach: false },
  { id: "INC-0410", title: "Misconfigured S3 bucket exposed read-only",       type: "data_breach",  sev: "P4", status: "resolved",    analyst: "l.garcia",  open: "10d 3h", slaDue: "2026-04-25 16:00", slaBreach: false },
];

const TIMELINE_STEPS = [
  { label: "Detect",    desc: "Threat detected by EDR agent",      done: true,    current: false },
  { label: "Triage",    desc: "Severity assessed — P1 Ransomware", done: true,    current: false },
  { label: "Contain",   desc: "Network segment isolated",           done: false,   current: true  },
  { label: "Eradicate", desc: "Remove malware artifacts",           done: false,   current: false },
  { label: "Recover",   desc: "Restore systems from clean backup",  done: false,   current: false },
  { label: "Review",    desc: "Post-incident report and lessons",   done: false,   current: false },
];

const TASKS = [
  { done: true,  label: "Isolate affected workstations from network",           owner: "s.kim",    due: "09:00", priority: "P1" },
  { done: true,  label: "Capture memory dump from primary infected host",       owner: "forensics",due: "09:30", priority: "P1" },
  { done: true,  label: "Revoke all active sessions for finance AD group",      owner: "iam-team", due: "10:00", priority: "P1" },
  { done: false, label: "Block IOC hashes across all AV/EDR policies",         owner: "secops",   due: "10:30", priority: "P1" },
  { done: false, label: "Notify CISO and legal team (ransomware playbook §4)", owner: "s.kim",    due: "11:00", priority: "P2" },
  { done: false, label: "Enumerate lateral movement from patient-zero host",    owner: "a.wright", due: "12:00", priority: "P2" },
  { done: false, label: "Begin backup integrity verification",                  owner: "infra",    due: "13:00", priority: "P2" },
  { done: false, label: "Submit CISA incident notification (72h deadline)",     owner: "legal",    due: "16:00", priority: "P3" },
];

const ARTIFACTS = [
  { name: "finance-pc-01_memory.raw",    type: "memory_dump",     size: "16.2 GB", by: "forensics",  ts: "2026-04-16 09:35" },
  { name: "INC-0421_traffic.pcap",       type: "pcap",            size: "4.8 GB",  by: "netops",     ts: "2026-04-16 09:20" },
  { name: "edr-alert-bundle.zip",        type: "logs",            size: "248 MB",  by: "edr-agent",  ts: "2026-04-16 08:55" },
  { name: "ransom_binary_sample.bin",    type: "malware_sample",  size: "892 KB",  by: "s.kim",      ts: "2026-04-16 09:10" },
  { name: "finance-pc-01_disk.e01",      type: "forensic_image",  size: "512 GB",  by: "forensics",  ts: "2026-04-16 10:02" },
];

// ── Helpers ────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  ransomware:  "border-red-500/30 text-red-400 bg-red-500/10",
  phishing:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
  data_breach: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  ddos:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
  insider:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
};

const SEV_COLORS: Record<string, string> = {
  P1: "border-red-500/30 text-red-400 bg-red-500/10",
  P2: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  P3: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  P4: "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

const STATUS_COLORS: Record<string, string> = {
  active:        "border-red-500/30 text-red-400 bg-red-500/10",
  contained:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
  investigating: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  mitigating:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
  eradicated:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  resolved:      "border-green-500/30 text-green-400 bg-green-500/10",
};

const ARTIFACT_COLORS: Record<string, string> = {
  memory_dump:    "border-violet-500/30 text-violet-400 bg-violet-500/10",
  pcap:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
  logs:           "border-green-500/30 text-green-400 bg-green-500/10",
  malware_sample: "border-red-500/30 text-red-400 bg-red-500/10",
  forensic_image: "border-amber-500/30 text-amber-400 bg-amber-500/10",
};

const PRIORITY_COLORS: Record<string, string> = {
  P1: "text-red-400",
  P2: "text-amber-400",
  P3: "text-blue-400",
};

// ── Component ──────────────────────────────────────────────────

export default function IncidentResponseDashboard() {
  usePageTitle("Incident Response");
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = useCallback(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/incidents/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incidents?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/soar/playbooks?org_id=${ORG_ID}`),
    ]).then(([statsResult, incidentsResult, playbooksResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const incidents = incidentsResult.status === "fulfilled" ? incidentsResult.value : null;
      const playbooks = playbooksResult.status === "fulfilled" ? playbooksResult.value : null;
      if (stats || incidents || playbooks) {
        setLiveData({ stats, incidents, playbooks });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const { isPaused, togglePause, secondsAgo } = useAutoRefresh(fetchData, 30_000);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveActiveCount = liveData?.stats?.active_count ?? liveData?.stats?.open ?? 7;
  const liveP1Count     = liveData?.stats?.p1_count ?? liveData?.stats?.critical ?? 2;
  const liveMttr        = liveData?.stats?.mttr ?? liveData?.stats?.avg_mttr ?? "6.8h";
  const liveSlaComp     = liveData?.stats?.sla_compliance ?? liveData?.stats?.sla_met ?? "91.4%";
  const liveIncidents: typeof INCIDENTS =
    Array.isArray(liveData?.incidents)
      ? liveData.incidents.slice(0, 12).map((inc: any) => ({
          id: inc.incident_id ?? inc.id ?? inc.title?.slice(0, 8) ?? "INC-???",
          title: inc.title ?? inc.name ?? "Unknown incident",
          type: inc.type ?? inc.incident_type ?? "phishing",
          sev: inc.severity ?? inc.priority ?? "P3",
          status: inc.status ?? "active",
          analyst: inc.assigned_to ?? inc.analyst ?? "Unassigned",
          open: inc.open_duration ?? inc.age ?? "—",
          slaDue: inc.sla_due ?? inc.due_date ?? "—",
          slaBreach: inc.sla_breached ?? false,
        }))
      : Array.isArray(liveData?.incidents?.incidents)
        ? liveData.incidents.incidents.slice(0, 12).map((inc: any) => ({
            id: inc.incident_id ?? inc.id ?? "INC-???",
            title: inc.title ?? "Unknown incident",
            type: inc.type ?? "phishing",
            sev: inc.severity ?? "P3",
            status: inc.status ?? "active",
            analyst: inc.assigned_to ?? "Unassigned",
            open: inc.open_duration ?? "—",
            slaDue: inc.sla_due ?? "—",
            slaBreach: inc.sla_breached ?? false,
          }))
        : INCIDENTS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Incident Response"
        description="Full lifecycle incident management and playbook execution"
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500">Updated {secondsAgo}s ago</span>
            <Button variant="outline" size="sm" onClick={togglePause}>
              {isPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            </Button>
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Incidents"  value={liveActiveCount} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="P1 Critical"       value={liveP1Count}     icon={Shield}        trend="up"   className="border-red-500/20" />
        <KpiCard title="MTTR"              value={liveMttr}        icon={Clock}         trend="down" />
        <KpiCard title="SLA Compliance"    value={liveSlaComp}     icon={Activity}      trend="up"   className="border-green-500/20" />
      </div>

      {/* Real-time security event stream */}
      <LiveEventStream
        title="Live Incident & Threat Stream"
        eventTypes={["incident", "threat", "alert", "sla_breach"]}
        heightClass="h-48"
        onEvent={() => { handleRefresh(); }}
        emptyMessage="No incidents in the live stream. New incidents from the SOC will appear here."
      />

      {/* Incidents table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Active &amp; Recent Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {liveActiveCount} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Full incident list — sorted by severity and open time</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Sev</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Analyst</TableHead>
                  <TableHead className="text-[11px] h-8">Open</TableHead>
                  <TableHead className="text-[11px] h-8">SLA Due</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveIncidents.map((inc) => (
                  <TableRow
                    key={inc.id}
                    className={cn("hover:bg-muted/30", inc.slaBreach && "bg-red-500/5 border-l-2 border-l-red-500")}
                  >
                    <TableCell className="text-xs font-mono py-2.5">
                      <EntityLink type="incident" id={inc.id}>
                        {inc.id}
                      </EntityLink>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{inc.title}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", TYPE_COLORS[inc.type])}>
                        {inc.type.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border font-bold", SEV_COLORS[inc.sev])}>
                        {inc.sev}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border capitalize", STATUS_COLORS[inc.status])}>
                        {inc.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{inc.analyst}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{inc.open}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums py-2.5", inc.slaBreach ? "text-red-400 font-bold" : "text-muted-foreground")}>
                      {inc.slaDue.split(" ")[1]}
                      {inc.slaBreach && <span className="ml-1 text-[10px]">⚠ breached</span>}
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        <ExternalLink className="h-3 w-3 mr-1" />Open
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Response timeline + Task checklist */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Response timeline stepper */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Response Timeline — INC-0421
            </CardTitle>
            <CardDescription className="text-xs">6-step incident response lifecycle progress</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="relative flex flex-col gap-0">
              {TIMELINE_STEPS.map((step, i) => (
                <div key={step.label} className="flex items-start gap-3">
                  {/* Icon + connector line */}
                  <div className="flex flex-col items-center">
                    <div className={cn(
                      "h-7 w-7 rounded-full border-2 flex items-center justify-center shrink-0 z-10",
                      step.done
                        ? "border-green-500 bg-green-500/20"
                        : step.current
                          ? "border-blue-400 bg-blue-400/20"
                          : "border-muted bg-background"
                    )}>
                      {step.done
                        ? <CheckCircle2 className="h-4 w-4 text-green-400" />
                        : step.current
                          ? <ChevronRight className="h-4 w-4 text-blue-400" />
                          : <Circle className="h-4 w-4 text-muted-foreground" />}
                    </div>
                    {i < TIMELINE_STEPS.length - 1 && (
                      <div className={cn("w-0.5 h-8 mt-0.5", step.done ? "bg-green-500/40" : "bg-muted/40")} />
                    )}
                  </div>
                  {/* Label + desc */}
                  <div className="pb-4">
                    <p className={cn(
                      "text-xs font-semibold",
                      step.done ? "text-green-400" : step.current ? "text-blue-400" : "text-muted-foreground"
                    )}>
                      {step.label}
                    </p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{step.desc}</p>
                    {step.current && (
                      <Badge className="mt-1 text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">in progress</Badge>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Task checklist */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              Task Checklist — INC-0421
            </CardTitle>
            <CardDescription className="text-xs">
              {TASKS.filter(t => t.done).length}/{TASKS.length} tasks completed
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {TASKS.map((task, i) => (
              <div
                key={i}
                className={cn(
                  "flex items-start gap-2 p-2 rounded-md border",
                  task.done
                    ? "border-green-500/20 bg-green-500/5 opacity-70"
                    : "border-border bg-muted/10"
                )}
              >
                {task.done
                  ? <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0 mt-0.5" />
                  : <Circle className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />}
                <div className="flex-1 min-w-0">
                  <p className={cn("text-xs leading-snug", task.done && "line-through text-muted-foreground")}>
                    {task.label}
                  </p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[10px] text-muted-foreground">{task.owner}</span>
                    <span className="text-[10px] text-muted-foreground">· due {task.due}</span>
                    <span className={cn("text-[10px] font-bold", PRIORITY_COLORS[task.priority] ?? "text-muted-foreground")}>
                      {task.priority}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Artifact list */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-amber-400" />
              Forensic Artifacts — INC-0421
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {ARTIFACTS.length} artifacts
            </Badge>
          </div>
          <CardDescription className="text-xs">Evidence collected during incident investigation</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Filename</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Size</TableHead>
                  <TableHead className="text-[11px] h-8">Uploaded By</TableHead>
                  <TableHead className="text-[11px] h-8">Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ARTIFACTS.map((a, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 max-w-[220px] truncate">{a.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", ARTIFACT_COLORS[a.type])}>
                        {a.type.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{a.size}</TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{a.by}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{a.ts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
