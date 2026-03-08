import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Wrench, AlertTriangle, Clock, CheckCircle2, Search, RefreshCw } from "lucide-react";
import { useRemediationTasks } from "@/hooks/use-api";

export default function RemediationCenter() {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const tasks = useRemediationTasks();
  const refetch = useCallback(() => tasks.refetch(), [tasks]);

  if (tasks.isLoading) return <PageSkeleton />;
  if (tasks.isError) return <ErrorState onRetry={refetch} />;

  const items = tasks.data?.tasks ?? [];
  const filtered = items.filter((t: Record<string, unknown>) => {
    const matchSearch = !search || String(t.title ?? "").toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || t.status === statusFilter;
    return matchSearch && matchStatus;
  });

  const assigned = items.filter((t: Record<string, unknown>) => t.status === "assigned");
  const inProgress = items.filter((t: Record<string, unknown>) => t.status === "in_progress");
  const completed = items.filter((t: Record<string, unknown>) => t.status === "resolved" || t.status === "completed");
  const breached = items.filter((t: Record<string, unknown>) => t.sla_breached || t.is_overdue);

  const cols = [
    { key: "title", header: "Task", render: (r: Record<string, unknown>) => (
      <div className="max-w-md">
        <p className="font-medium truncate text-sm">{String(r.title)}</p>
        <p className="text-xs text-muted-foreground">{String(r.app_id ?? "")} · {String(r.assignee ?? "Unassigned")}</p>
      </div>
    )},
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
    { key: "sla_hours", header: "SLA", render: (r: Record<string, unknown>) => <span className="font-mono text-sm">{r.sla_hours ?? "—"}h</span> },
    { key: "due_at", header: "Due", render: (r: Record<string, unknown>) => <span className="text-xs text-muted-foreground">{r.due_at ? new Date(String(r.due_at)).toLocaleDateString() : "—"}</span> },
    { key: "overdue", header: "SLA", render: (r: Record<string, unknown>) => (r.sla_breached || r.is_overdue) ? <Badge variant="destructive">Breached</Badge> : <Badge variant="outline">OK</Badge> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Remediation Center" description="Track and manage all remediation tasks" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Tasks" value={items.length} icon={Wrench} />
        <KpiCard title="Assigned" value={assigned.length} icon={Clock} />
        <KpiCard title="Completed" value={completed.length} icon={CheckCircle2} trend="up" />
        <KpiCard title="SLA Breached" value={breached.length} icon={AlertTriangle} trend={breached.length > 0 ? "up" : "flat"} />
      </div>
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input placeholder="Search tasks..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" /></div>
        <Select value={statusFilter} onValueChange={setStatusFilter}><SelectTrigger className="w-[140px]"><SelectValue placeholder="Status" /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="assigned">Assigned</SelectItem><SelectItem value="in_progress">In Progress</SelectItem><SelectItem value="resolved">Resolved</SelectItem></SelectContent></Select>
      </div>
      <Card><CardContent className="pt-6"><DataTable columns={cols} data={filtered} emptyMessage="No remediation tasks. Tasks are auto-created from findings." /></CardContent></Card>
    </div>
  );
}
