import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Layers, Users, GitPullRequest, Ticket, RefreshCw, Shield, AlertTriangle } from "lucide-react";
import { useRemediationTasks, useTeams } from "@/hooks/use-api";

export default function Collaboration() {
  const tasks = useRemediationTasks();
  const teams = useTeams();
  const refetch = useCallback(() => { tasks.refetch(); teams.refetch(); }, [tasks, teams]);
  if (tasks.isLoading) return <PageSkeleton />;
  if (tasks.isError) return <ErrorState onRetry={refetch} />;
  const items = tasks.data?.tasks ?? [];
  const teamList = Array.isArray(teams.data) ? teams.data : teams.data?.teams ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Collaboration" description="Team coordination for remediation efforts" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Tasks" value={items.length} icon={GitPullRequest} /><KpiCard title="Teams" value={teamList.length} icon={Users} /><KpiCard title="Assigned" value={items.filter((t: Record<string, unknown>) => t.assignee).length} icon={Shield} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Team Assignments</CardTitle></CardHeader><CardContent>
        <div className="space-y-2">{items.filter((t: Record<string, unknown>) => t.assignee).map((t: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><div className="min-w-0 flex-1"><p className="font-medium text-sm truncate">{String(t.title)}</p><p className="text-xs text-muted-foreground">Assigned to: {String(t.assignee)}</p></div><Badge variant="outline" className="capitalize">{String(t.status)}</Badge></div>
        ))}{items.filter((t: Record<string, unknown>) => t.assignee).length === 0 && <p className="text-sm text-muted-foreground text-center py-8">No team assignments. Assign tasks to teams.</p>}</div>
      </CardContent></Card>
    </div>
  );
}
