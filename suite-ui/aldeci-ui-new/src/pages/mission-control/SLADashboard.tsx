import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Clock, AlertTriangle, CheckCircle2, Timer, RefreshCw } from "lucide-react";
import { useRemediationTasks } from "@/hooks/use-api";

export default function SLADashboard() {
  const tasks = useRemediationTasks();
  const refetch = useCallback(() => { tasks.refetch(); }, [tasks]);

  if (tasks.isLoading) return <PageSkeleton />;
  if (tasks.isError) return <ErrorState onRetry={refetch} />;

  const items = tasks.data?.tasks ?? [];
  const breached = items.filter((t: Record<string, unknown>) => t.sla_breached || t.is_overdue);
  const onTrack = items.filter((t: Record<string, unknown>) => !t.sla_breached && !t.is_overdue);

  const cols = [
    { key: "title", header: "Task", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate text-sm">{String(r.title)}</p><p className="text-xs text-muted-foreground">{String(r.assignee ?? "Unassigned")}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
    { key: "sla_hours", header: "SLA", render: (r: Record<string, unknown>) => <span className="font-mono text-sm">{r.sla_hours}h</span> },
    { key: "due_at", header: "Due", render: (r: Record<string, unknown>) => <span className="text-xs text-muted-foreground">{r.due_at ? new Date(String(r.due_at)).toLocaleDateString() : "—"}</span> },
    { key: "is_overdue", header: "Overdue", render: (r: Record<string, unknown>) => (r.sla_breached || r.is_overdue) ? <Badge variant="destructive">Breached</Badge> : <Badge variant="outline">On Track</Badge> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="SLA Dashboard" description="Track remediation SLA compliance across all tasks" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Tasks" value={items.length} icon={Clock} />
        <KpiCard title="On Track" value={onTrack.length} icon={CheckCircle2} trend="up" />
        <KpiCard title="SLA Breached" value={breached.length} icon={AlertTriangle} trend={breached.length > 0 ? "up" : "flat"} />
        <KpiCard title="Avg SLA" value={items.length > 0 ? `${Math.round(items.reduce((a: number, t: Record<string, unknown>) => a + Number(t.sla_hours ?? 0), 0) / items.length)}h` : "—"} icon={Timer} />
      </div>
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Remediation Tasks ({items.length})</CardTitle></CardHeader>
        <CardContent><DataTable columns={cols} data={items} emptyMessage="No remediation tasks. Create tasks from findings." /></CardContent>
      </Card>
    </div>
  );
}
