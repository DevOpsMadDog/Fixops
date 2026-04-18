/**
 * Autonomous Remediation Dashboard
 *
 * AI-driven automated remediation workflow orchestration.
 *   1. KPI cards: Total Workflows, Active Workflows, Succeeded Executions, Success Rate
 *   2. Workflows table
 *   3. Executions table
 *
 * API: GET /api/v1/autonomous-remediation/{stats,workflows,executions}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Zap, RefreshCw, CheckCircle, Play, Settings, Activity,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_workflows: 24,
  active_workflows: 8,
  succeeded_executions: 187,
  success_rate: 91.2,
};

const MOCK_WORKFLOWS = [
  { name: "Patch Critical CVEs",        trigger_type: "scheduled",  action_type: "patch",    automation_level: "full",   status: "active",   success_count: 42 },
  { name: "Isolate Compromised Hosts",  trigger_type: "alert",      action_type: "isolate",  automation_level: "full",   status: "active",   success_count: 18 },
  { name: "Rotate Leaked Secrets",      trigger_type: "webhook",    action_type: "rotate",   automation_level: "semi",   status: "active",   success_count: 31 },
  { name: "Block Malicious IPs",        trigger_type: "threat_feed",action_type: "block",    automation_level: "full",   status: "active",   success_count: 67 },
  { name: "Remediate Misconfigs",       trigger_type: "scan",       action_type: "remediate",automation_level: "semi",   status: "paused",   success_count: 14 },
  { name: "Disable Inactive Accounts",  trigger_type: "scheduled",  action_type: "disable",  automation_level: "full",   status: "active",   success_count: 9  },
  { name: "Scale Down Exposed Services",trigger_type: "alert",      action_type: "scale",    automation_level: "manual", status: "draft",    success_count: 0  },
  { name: "Quarantine Malware Files",   trigger_type: "edr",        action_type: "quarantine",automation_level: "full",  status: "active",   success_count: 6  },
];

const MOCK_EXECUTIONS = [
  { workflow_id: "wf-001", target_id: "host-web-01", target_type: "host",   status: "succeeded", started_at: "2026-04-16T10:12:00Z" },
  { workflow_id: "wf-002", target_id: "10.0.1.45",   target_type: "ip",     status: "succeeded", started_at: "2026-04-16T10:08:22Z" },
  { workflow_id: "wf-003", target_id: "sec-db-pass",  target_type: "secret", status: "running",   started_at: "2026-04-16T10:05:11Z" },
  { workflow_id: "wf-001", target_id: "host-api-02", target_type: "host",   status: "failed",    started_at: "2026-04-16T09:55:44Z" },
  { workflow_id: "wf-004", target_id: "198.51.100.7", target_type: "ip",    status: "succeeded", started_at: "2026-04-16T09:40:30Z" },
  { workflow_id: "wf-006", target_id: "usr-legacy-12",target_type: "user",  status: "succeeded", started_at: "2026-04-16T09:22:05Z" },
  { workflow_id: "wf-008", target_id: "proc-svchost", target_type: "process",status: "succeeded", started_at: "2026-04-16T09:10:17Z" },
  { workflow_id: "wf-002", target_id: "203.0.113.99", target_type: "ip",    status: "succeeded", started_at: "2026-04-16T08:58:42Z" },
];

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-green-500/30 text-green-400 bg-green-500/10",
    paused:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    draft:     "border-gray-500/30 text-gray-400 bg-gray-500/10",
    succeeded: "border-green-500/30 text-green-400 bg-green-500/10",
    running:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function AutoLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    full:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    semi:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    manual: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function AutonomousRemediationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    workflows: any[] | null;
    executions: any[] | null;
  }>({ stats: null, workflows: null, executions: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/autonomous-remediation/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/autonomous-remediation/workflows?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/autonomous-remediation/executions?org_id=${ORG_ID}`),
    ]).then(([statsRes, workflowsRes, executionsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        workflows:  workflowsRes.status  === "fulfilled" ? workflowsRes.value  : null,
        executions: executionsRes.status === "fulfilled" ? executionsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const workflows  = liveData.workflows  ?? MOCK_WORKFLOWS;
  const executions = liveData.executions ?? MOCK_EXECUTIONS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Autonomous Remediation"
        description="AI-driven automated remediation workflows and execution tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Workflows"       value={stats.total_workflows}                         icon={Settings}     trend="up"   />
        <KpiCard title="Active Workflows"      value={stats.active_workflows}                        icon={Play}         trend="up"   className="border-blue-500/20" />
        <KpiCard title="Succeeded Executions"  value={stats.succeeded_executions}                    icon={CheckCircle}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Success Rate"          value={`${stats.success_rate}%`}                      icon={Zap}          trend="up"   className="border-purple-500/20" />
      </div>

      {/* Workflows Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Settings className="h-4 w-4 text-blue-400" />
              Remediation Workflows
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {workflows.length} workflows
            </Badge>
          </div>
          <CardDescription className="text-xs">Configured automated remediation workflows and their settings</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Trigger</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Automation</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Successes</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {workflows.map((w: any, i: number) => (
                  <TableRow key={w.name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{w.name}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{w.trigger_type?.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{w.action_type}</TableCell>
                    <TableCell className="py-2"><AutoLevelBadge level={w.automation_level ?? "manual"} /></TableCell>
                    <TableCell className="py-2"><StatusBadge status={w.status ?? "draft"} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{w.success_count ?? 0}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Executions Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <Activity className="h-4 w-4" />
              Recent Executions
            </CardTitle>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {executions.filter((e: any) => e.status === "failed").length} failures
            </Badge>
          </div>
          <CardDescription className="text-xs">Live and historical workflow execution events</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Workflow ID</TableHead>
                  <TableHead className="text-[11px] h-8">Target</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Started At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {executions.map((e: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{e.workflow_id}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{e.target_id}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{e.target_type}</TableCell>
                    <TableCell className="py-2"><StatusBadge status={e.status ?? "running"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(e.started_at)}</TableCell>
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
