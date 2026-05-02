// FOLDED into VulnLifecyclePipelineHub hero (workflow tab) 2026-05-02 — preserve for git history
/**
 * Vulnerability Workflow Dashboard
 *
 * Vulnerability remediation workflow tracking with SLA and priority management.
 *   1. KPIs: Total Workflows, Open, Overdue, Closed Today
 *   2. Workflows table (title, workflow_type, priority, sla_tier, sla_due_date, status)
 *
 * Route: /vuln-workflow
 * API: GET /api/v1/vuln-workflow/workflows + /api/v1/vuln-workflow/stats
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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

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
  const [loading, setLoading] = useState(true);
  const [workflows, setWorkflows] = useState<Record<string, unknown>[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});

  const fetchData = () => {
    setLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/vuln-workflow/workflows?org_id=default"),
      apiFetch("/api/v1/vuln-workflow/stats?org_id=default"),
    ]).then(([wfRes, statsRes]) => {
      if (wfRes.status === "fulfilled") {
        const v = wfRes.value;
        setWorkflows(Array.isArray(v) ? v : Array.isArray(v?.workflows) ? v.workflows : []);
      }
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value ?? {});
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
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
        <KpiCard title="Total Workflows" value={stats.total_workflows ?? 0} icon={Workflow}     trend="flat" className="border-amber-500/20" />
        <KpiCard title="Open"           value={stats.open_workflows ?? 0}  icon={AlertOctagon} trend="down" className="border-orange-500/20" />
        <KpiCard title="Overdue"        value={stats.overdue ?? 0}         icon={Clock}        trend="down" className="border-amber-500/20" />
        <KpiCard title="Closed Today"   value={stats.closed_today ?? 0}    icon={CheckCircle}  trend="up"   className="border-orange-500/20" />
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
              {workflows.filter((w) => w.status === "overdue").length} overdue
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Active remediation workflows with priority, SLA tier, due date, and current status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {workflows.length === 0 ? (
            <EmptyState
              icon={Workflow}
              title="No workflows found"
              description="Remediation workflows will appear here once the API returns data."
            />
          ) : (
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
                  {workflows.map((wf, i) => (
                    <TableRow key={(wf.id as string) ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-semibold text-[11px] text-amber-300 max-w-[240px] truncate">
                        {(wf.title as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                        {((wf.workflow_type as string) ?? "—").replace(/_/g, " ")}
                      </TableCell>
                      <TableCell className="py-2">
                        <PriorityBadge priority={(wf.priority as string) ?? "medium"} />
                      </TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-orange-300">
                        {(wf.sla_tier as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">
                        {(wf.sla_due_date as string) ?? "—"}
                      </TableCell>
                      <TableCell className="py-2 text-right">
                        <StatusBadge status={(wf.status as string) ?? "open"} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
