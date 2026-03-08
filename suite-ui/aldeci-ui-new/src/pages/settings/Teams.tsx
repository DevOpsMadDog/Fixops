import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Users, Plus, RefreshCw } from "lucide-react";
import { useTeams } from "@/hooks/use-api";

export default function Teams() {
  const teams = useTeams();
  const refetch = useCallback(() => teams.refetch(), [teams]);
  if (teams.isLoading) return <PageSkeleton />;
  if (teams.isError) return <ErrorState onRetry={refetch} />;
  const list = Array.isArray(teams.data) ? teams.data : teams.data?.teams ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Teams" description="Team management and assignments" actions={<div className="flex gap-2"><Button size="sm"><Plus className="mr-2 h-4 w-4" />Create Team</Button><Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>} />
      <KpiCard title="Teams" value={list.length} icon={Users} className="max-w-xs" />
      <Card><CardHeader><CardTitle className="text-sm font-medium">Teams ({list.length})</CardTitle></CardHeader><CardContent>
        {list.length > 0 ? <div className="space-y-2">{list.map((t: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><span className="font-medium text-sm">{String(t.name ?? `Team ${i + 1}`)}</span><Badge variant="outline">{String(t.members_count ?? 0)} members</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No teams created. Create teams to assign remediation tasks.</p>}
      </CardContent></Card>
    </div>
  );
}
