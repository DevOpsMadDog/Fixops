/**
 * Vulnerability Workflow Dashboard
 *
 * Vulnerability remediation workflow tracking with SLA and priority management.
 *   1. KPIs: Total Workflows, Open, Overdue, Closed Today
 *   2. Workflows table (title, workflow_type, priority, sla_tier, sla_due_date, status)
 *
 * Route: /vuln-workflow
 * API: GET /api/v1/vuln-workflow
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Workflow, RefreshCw, AlertOctagon, Clock, CheckCircle, XCircle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_WORKFLOWS = [
  { id: "wf-001", title: "Patch Log4Shell on prod-web-01",         workflow_type: "patch",         priority: "critical", sla_tier: "P1", sla_due_date: "2026-04-17", status: "open"       },
  { id: "wf-002", title: "Remediate SSRF in billing service",       workflow_type: "code_fix",      priority: "high",     sla_tier: "P2", sla_due_date: "2026-04-18", status: "in_progress"},
  { id: "wf-003", title: "Rotate exposed AWS credentials",          workflow_type: "credential",    priority: "critical", sla_tier: "P1", sla_due_date: "2026-04-16", status: "overdue"    },
  { id: "wf-004", title: "Update OpenSSL on bastion hosts",         workflow_type: "patch",         priority: "high",     sla_tier: "P2", sla_due_date: "2026-04-20", status: "in_progress"},
  { id: "wf-005", title: "Fix XSS in customer portal",             workflow_type: "code_fix",      priority: "medium",   sla_tier: "P3", sla_due_date: "2026-04-25", status: "open"       },
  { id: "wf-006", title: "Disable TLS 1.0 on API gateway",         workflow_type: "configuration", priority: "medium",   sla_tier: "P3", sla_due_date: "2026-04-22", status: "closed"     },
  { id: "wf-007", title: "Patch VMware ESXi hypervisors",           workflow_type: "patch",         priority: "critical", sla_tier: "P1", sla_due_date: "2026-04-15", status: "overdue"    },
  { id: "wf-008", title: "Remediate SQLi in legacy API",            workflow_type: "code_fix",      priority: "high",     sla_tier: "P2", sla_due_date: "2026-04-19", status: "in_progress"},
  { id: "wf-009", title: "Update nginx — CVE-2026-0482",           workflow_type: "patch",         priority: "low",      sla_tier: "P4", sla_due_date: "2026-04-30", status: "open"       },
  { id: "wf-010", title: "Enforce MFA on admin accounts",           workflow_type: "configuration", priority: "high",     sla_tier: "P2", sla_due_date: "2026-04-16", status: "closed"     },
];

const MOCK_STATS = { total_workflows: 218, open_workflows: 87, overdue: 14, closed_today: 9 };

// ── Badge helpers ──────────────────────────────────────────────

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[priority] ?? "border-border")}>
      {priority}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    overdue:     "border-red-500/30 text-red-400 bg-red-500/10",
    closed:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const label: Record<string, string> = {
    open:        "Open",
    in_progress: "In Progress",
    overdue:     "Overdue",
    closed:      "Closed",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function VulnWorkflowDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveWorkflows, setLiveWorkflows] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-workflow/workflows?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-workflow/stats?org_id=${ORG_ID}`),
    ]).then(([wfRes, statsRes]) => {
      if (wfRes.status === "fulfilled") setLiveWorkflows(wfRes.value?.workflows ?? wfRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const workflows = liveWorkflows ?? MOCK_WORKFLOWS;
  const stats     = liveStats     ?? MOCK_STATS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Vulnerability Workflow"
        description="Vulnerability remediation workflow management with SLA tracking, priority triage, and closure metrics"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Workflows" value={stats.total_workflows} icon={Workflow}     trend="flat" className="border-amber-500/20" />
        <KpiCard title="Open"           value={stats.open_workflows}  icon={AlertOctagon} trend="down" className="border-orange-500/20" />
        <KpiCard title="Overdue"        value={stats.overdue}         icon={Clock}        trend="down" className="border-amber-500/20" />
        <KpiCard title="Closed Today"   value={stats.closed_today}    icon={CheckCircle}  trend="up"   className="border-orange-500/20" />
      </div>

      {/* Workflows Table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <XCircle className="h-4 w-4" />
              Remediation Workflows
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {workflows.filter((w: any) => w.status === "overdue").length} overdue
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Active remediation workflows with priority, SLA tier, due date, and current status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">SLA Tier</TableHead>
                  <TableHead className="text-[11px] h-8">Due Date</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {workflows.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  workflows.map((wf: any, i: number) => (
                  <TableRow key={wf.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-amber-300 max-w-[240px] truncate">
                      {wf.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(wf.workflow_type ?? "—").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2">
                      <PriorityBadge priority={wf.priority ?? "medium"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-orange-300">
                      {wf.sla_tier ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {wf.sla_due_date ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={wf.status ?? "open"} />
                    </TableCell>
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
