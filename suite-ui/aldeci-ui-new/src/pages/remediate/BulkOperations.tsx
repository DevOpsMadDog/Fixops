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
import { useRemediationTasks } from "@/hooks/use-api";

export default function BulkOperations() {
  const tasks = useRemediationTasks();
  const refetch = useCallback(() => tasks.refetch(), [tasks]);
  if (tasks.isLoading) return <PageSkeleton />;
  if (tasks.isError) return <ErrorState onRetry={refetch} />;
  const items = tasks.data?.tasks ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Bulk Operations" description="Batch remediation actions across multiple findings" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Tasks" value={items.length} icon={Layers} /><KpiCard title="Critical" value={items.filter((t: Record<string, unknown>) => t.severity === "critical").length} icon={AlertTriangle} /><KpiCard title="Assigned" value={items.filter((t: Record<string, unknown>) => t.status === "assigned").length} icon={Shield} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Available for Bulk Action ({items.length})</CardTitle></CardHeader><CardContent>
        <div className="space-y-2">{items.map((t: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center gap-3 p-3 rounded-lg border border-border/50"><input type="checkbox" className="rounded" /><div className="flex-1 min-w-0"><p className="font-medium text-sm truncate">{String(t.title)}</p></div><Badge variant={t.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(t.severity)}</Badge></div>
        ))}{items.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">No tasks available for bulk operations.</p>}</div>
      </CardContent></Card>
    </div>
  );
}
