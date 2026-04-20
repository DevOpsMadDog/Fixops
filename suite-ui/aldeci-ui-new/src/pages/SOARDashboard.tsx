/**
 * SOAR Dashboard
 *
 * Playbook orchestration and incident response automation.
 *   1. KPIs: Active Playbooks, Executions Today, Automation Rate, MTTR Saved
 *   2. Playbook table (10 rows)
 *   3. Recent executions feed (12 rows)
 *   4. Integration status cards (6 integrations)
 *   5. Action success rates (6 action types)
 *
 * API stubs: GET /api/v1/soar/playbooks, /api/v1/soar/executions, /api/v1/soar/integrations
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Zap, PlayCircle, GitBranch, Clock, RefreshCw, Activity, Link2 } from "lucide-react";
import { toast } from "sonner";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const PLAYBOOKS = [
  { name: "Critical Alert Response",      trigger: "Alert",     enabled: true,  execs: 412, success: 97.1, lastRun: "2026-04-16 09:42" },
  { name: "IP Block & Notify",            trigger: "Alert",     enabled: true,  execs: 891, success: 99.3, lastRun: "2026-04-16 09:38" },
  { name: "High CVSS Auto-Ticket",        trigger: "Threshold", enabled: true,  execs: 234, success: 98.7, lastRun: "2026-04-16 09:21" },
  { name: "Ransomware Isolate Host",      trigger: "Alert",     enabled: true,  execs: 18,  success: 94.4, lastRun: "2026-04-15 23:11" },
  { name: "Daily Vuln Summary Report",    trigger: "Scheduled", enabled: true,  execs: 45,  success: 100,  lastRun: "2026-04-16 08:00" },
  { name: "Credential Stuffing Response", trigger: "Alert",     enabled: true,  execs: 67,  success: 95.5, lastRun: "2026-04-16 07:54" },
  { name: "Phishing Quarantine",          trigger: "Alert",     enabled: true,  execs: 153, success: 96.7, lastRun: "2026-04-16 07:12" },
  { name: "S3 Public Exposure Remediate", trigger: "Threshold", enabled: false, execs: 29,  success: 86.2, lastRun: "2026-04-14 16:00" },
  { name: "Weekly Patch Compliance",      trigger: "Scheduled", enabled: true,  execs: 12,  success: 100,  lastRun: "2026-04-14 06:00" },
  { name: "Insider Alert Escalation",     trigger: "Threshold", enabled: true,  execs: 44,  success: 93.2, lastRun: "2026-04-16 06:30" },
];

const EXECUTIONS = [
  { playbook: "IP Block & Notify",            event: "Brute force from 185.220.101.x",  status: "completed", steps: "4/4", duration: "3.2s",  ts: "09:42:11" },
  { playbook: "Critical Alert Response",      event: "SQLi attempt on /api/auth",        status: "completed", steps: "6/6", duration: "5.8s",  ts: "09:38:44" },
  { playbook: "Ransomware Isolate Host",      event: "Suspicious process on PROD-WEB-3", status: "running",   steps: "3/5", duration: "12.1s", ts: "09:35:02" },
  { playbook: "High CVSS Auto-Ticket",        event: "CVE-2025-29927 CVSS 9.8",         status: "completed", steps: "3/3", duration: "2.1s",  ts: "09:21:55" },
  { playbook: "Credential Stuffing Response", event: "1,240 failed logins in 60s",       status: "completed", steps: "5/5", duration: "4.7s",  ts: "09:18:22" },
  { playbook: "Phishing Quarantine",          event: "Phishing URL in email thread",     status: "completed", steps: "4/4", duration: "6.3s",  ts: "08:54:10" },
  { playbook: "IP Block & Notify",            event: "Port scan from 91.108.4.x",        status: "failed",    steps: "2/4", duration: "8.9s",  ts: "08:41:33" },
  { playbook: "Daily Vuln Summary Report",    event: "Scheduled 08:00",                  status: "completed", steps: "2/2", duration: "14.2s", ts: "08:00:04" },
  { playbook: "Insider Alert Escalation",     event: "Unusual data exfil pattern",       status: "completed", steps: "3/3", duration: "2.9s",  ts: "07:54:18" },
  { playbook: "Critical Alert Response",      event: "Privilege escalation attempt",     status: "completed", steps: "6/6", duration: "5.1s",  ts: "07:43:01" },
  { playbook: "High CVSS Auto-Ticket",        event: "CVE-2026-0042 CVSS 9.1",          status: "completed", steps: "3/3", duration: "1.8s",  ts: "07:12:45" },
  { playbook: "S3 Public Exposure Remediate", event: "Threshold: 3 public buckets",      status: "failed",    steps: "1/4", duration: "22.0s", ts: "06:30:59" },
];

const INTEGRATIONS = [
  { name: "PagerDuty",   connected: true  },
  { name: "Jira",        connected: true  },
  { name: "Slack",       connected: true  },
  { name: "ServiceNow",  connected: true  },
  { name: "Splunk",      connected: false },
  { name: "Sentinel",    connected: false },
];

const ACTION_RATES = [
  { action: "notify",         pct: 98.7, color: "bg-green-500" },
  { action: "block_ip",       pct: 96.2, color: "bg-blue-500" },
  { action: "create_ticket",  pct: 99.1, color: "bg-indigo-500" },
  { action: "isolate_host",   pct: 91.4, color: "bg-amber-500" },
  { action: "run_scan",       pct: 88.3, color: "bg-purple-500" },
  { action: "send_email",     pct: 97.8, color: "bg-cyan-500" },
];

// ── Helpers ────────────────────────────────────────────────────

function TriggerBadge({ t }: { t: string }) {
  const cls =
    t === "Alert"     ? "border-red-500/30 text-red-400 bg-red-500/10" :
    t === "Threshold" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                        "border-blue-500/30 text-blue-400 bg-blue-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{t}</Badge>;
}

function StatusBadge({ s }: { s: string }) {
  const cls =
    s === "completed" ? "border-green-500/30 text-green-400 bg-green-500/10" :
    s === "failed"    ? "border-red-500/30 text-red-400 bg-red-500/10" :
                        "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{s}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function SOARDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/soar/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/soar/playbooks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/soar/executions?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/soar/mttr?org_id=${ORG_ID}`),
    ]).then(([statsRes, playbooksRes, executionsRes, mttrRes]) => {
      const stats      = statsRes.status      === "fulfilled" ? statsRes.value      : null;
      const playbooks  = playbooksRes.status  === "fulfilled" ? playbooksRes.value  : null;
      const executions = executionsRes.status === "fulfilled" ? executionsRes.value : null;
      const mttr       = mttrRes.status       === "fulfilled" ? mttrRes.value       : null;
      if (stats || playbooks || executions || mttr) {
        setLiveData({ stats, playbooks, executions, mttr });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="SOAR Automation"
        description="Playbook orchestration and incident response automation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Playbooks" value={liveData?.stats?.total_playbooks ?? (liveData?.playbooks?.length ?? 24)} icon={GitBranch} trend="up" className="border-blue-500/20" />
        <KpiCard title="Executions Today" value={liveData?.stats?.total_executions ?? (liveData?.executions?.length ?? 187)} icon={PlayCircle} trend="up" className="border-green-500/20" />
        <KpiCard title="Automation Rate"  value={liveData?.stats?.completion_rate != null ? `${liveData.stats.completion_rate.toFixed(1)}%` : "73.4%"} icon={Zap} trend="up" className="border-purple-500/20" />
        <KpiCard title="MTTR Saved"       value={liveData?.mttr?.mttr_minutes != null ? `${liveData.mttr.mttr_minutes.toFixed(1)}m` : "4.2h avg"} icon={Clock} trend="up" className="border-cyan-500/20" />
      </div>

      {/* Playbook table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-blue-400" />
              Playbooks
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">New Playbook</Button>
          </div>
          <CardDescription className="text-xs">Automated response workflows — click Run Now to trigger manually</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Trigger</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Executions</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Success %</TableHead>
                  <TableHead className="text-[11px] h-8">Last Run</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.playbooks ?? PLAYBOOKS).map((row: any) => {
                  const isEnabled = row.enabled !== false;
                  const triggerVal = row.trigger ?? row.trigger_type ?? "Alert";
                  const execCount = row.execution_count ?? row.execs ?? 0;
                  const successPct = row.success_rate ?? row.success ?? 0;
                  return (
                  <TableRow key={row.id ?? row.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[200px] truncate">{row.name}</TableCell>
                    <TableCell className="py-2.5"><TriggerBadge t={typeof triggerVal === "string" ? triggerVal.charAt(0).toUpperCase() + triggerVal.slice(1) : String(triggerVal)} /></TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-semibold", isEnabled ? "text-green-400" : "text-muted-foreground")}>
                        {isEnabled ? "Enabled" : "Disabled"}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{execCount}</TableCell>
                    <TableCell className={cn(
                      "text-xs tabular-nums py-2.5 font-bold text-right",
                      successPct >= 97 ? "text-green-400" : successPct >= 90 ? "text-yellow-400" : "text-red-400"
                    )}>
                      {successPct}%
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground tabular-nums">{row.last_executed_at ?? row.lastRun ?? "—"}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Run Now</Button>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Recent executions + integrations */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Recent executions — 2/3 width */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-green-400" />
              Recent Executions
            </CardTitle>
            <CardDescription className="text-xs">Last 12 playbook runs</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Playbook</TableHead>
                    <TableHead className="text-[11px] h-8">Trigger Event</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8">Steps</TableHead>
                    <TableHead className="text-[11px] h-8">Duration</TableHead>
                    <TableHead className="text-[11px] h-8">Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.executions ?? EXECUTIONS).map((row: any, i: number) => {
                    const execStatus = row.status ?? "completed";
                    const stepsStr = row.steps_completed != null && row.total_steps != null
                      ? `${row.steps_completed}/${row.total_steps}`
                      : (row.steps ?? "—");
                    const durationStr = row.duration_seconds != null
                      ? `${row.duration_seconds.toFixed(1)}s`
                      : (row.duration ?? "—");
                    return (
                    <TableRow key={row.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2 max-w-[140px] truncate">{row.playbook_id ?? row.playbook}</TableCell>
                      <TableCell className="text-xs py-2 text-muted-foreground max-w-[160px] truncate">{row.trigger_event ?? row.event ?? "—"}</TableCell>
                      <TableCell className="py-2"><StatusBadge s={execStatus} /></TableCell>
                      <TableCell className="text-xs tabular-nums py-2">{stepsStr}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2 text-muted-foreground">{durationStr}</TableCell>
                      <TableCell className="text-xs tabular-nums py-2 text-muted-foreground">{row.started_at ?? row.ts ?? "—"}</TableCell>
                    </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Integrations — 1/3 width */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Link2 className="h-4 w-4 text-purple-400" />
              Integrations
            </CardTitle>
            <CardDescription className="text-xs">SOAR platform connections</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {INTEGRATIONS.map((intg) => (
              <div key={intg.name} className="flex items-center justify-between p-2 rounded-lg bg-muted/20 border border-border/50">
                <div className="flex items-center gap-2">
                  <div className={cn("w-2 h-2 rounded-full", intg.connected ? "bg-green-400" : "bg-red-400")} />
                  <span className="text-xs font-medium">{intg.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge className={cn(
                    "text-[9px] border",
                    intg.connected
                      ? "border-green-500/30 text-green-400 bg-green-500/10"
                      : "border-red-500/30 text-red-400 bg-red-500/10"
                  )}>
                    {intg.connected ? "Connected" : "Disconnected"}
                  </Badge>
                  <Button variant="ghost" size="sm" className="h-5 px-1.5 text-[9px]">Test</Button>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Action success rates */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Zap className="h-4 w-4 text-yellow-400" />
            Action Success Rates
          </CardTitle>
          <CardDescription className="text-xs">Success rate per action type across all executions</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {ACTION_RATES.map((a) => (
            <div key={a.action} className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono text-muted-foreground">{a.action}</span>
                <span className="font-bold tabular-nums">{a.pct}%</span>
              </div>
              <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${a.pct}%` }}
                  transition={{ duration: 0.8, ease: "easeOut" }}
                  className={cn("h-full rounded-full", a.color)}
                />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
