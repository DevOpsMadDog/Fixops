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
import { useIntegrations, useRemediationTasks } from "@/hooks/use-api";

export default function TicketIntegration() {
  const integrations = useIntegrations();
  const tasks = useRemediationTasks();
  const refetch = useCallback(() => { integrations.refetch(); tasks.refetch(); }, [integrations, tasks]);
  if (tasks.isLoading) return <PageSkeleton />;
  if (tasks.isError) return <ErrorState onRetry={refetch} />;
  const intList = Array.isArray(integrations.data) ? integrations.data : integrations.data?.integrations ?? [];
  const items = tasks.data?.tasks ?? [];
  const ticketed = items.filter((t: Record<string, unknown>) => t.ticket_url);
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Ticket Integration" description="Sync remediation tasks with ticketing systems" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Integrations" value={intList.length} icon={Ticket} /><KpiCard title="Ticketed" value={ticketed.length} icon={Layers} /><KpiCard title="Pending" value={items.length - ticketed.length} icon={Shield} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Connected Systems ({intList.length})</CardTitle></CardHeader><CardContent>
        {intList.length > 0 ? <div className="space-y-2">{intList.map((int: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><span className="font-medium text-sm">{String(int.name ?? int.type ?? `Integration ${i + 1}`)}</span><Badge variant="outline">{String(int.status ?? "active")}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No ticket integrations configured. Connect Jira, ServiceNow, or GitHub Issues.</p>}
      </CardContent></Card>
    </div>
  );
}
