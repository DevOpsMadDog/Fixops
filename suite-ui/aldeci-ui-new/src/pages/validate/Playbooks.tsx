import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { BookOpen, Play, RefreshCw, FileText } from "lucide-react";
import { usePlaybooks } from "@/hooks/use-api";

export default function Playbooks() {
  const pb = usePlaybooks();
  const refetch = useCallback(() => pb.refetch(), [pb]);
  if (pb.isLoading) return <PageSkeleton />;
  if (pb.isError) return <ErrorState onRetry={refetch} />;
  const list = Array.isArray(pb.data) ? pb.data : pb.data?.playbooks ?? [];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Playbooks" description="Security response playbook library" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Playbooks" value={list.length} icon={BookOpen} /><KpiCard title="Active" value={list.filter((p: Record<string, unknown>) => p.status === "active").length} icon={Play} /><KpiCard title="Total" value={list.length} icon={FileText} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Playbook Library ({list.length})</CardTitle></CardHeader><CardContent>
        {list.length > 0 ? <div className="space-y-2">{list.map((p: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50">
            <div><p className="font-medium text-sm">{String(p.name ?? p.id ?? `Playbook ${i + 1}`)}</p><p className="text-xs text-muted-foreground">{String(p.description ?? "")}</p></div>
            <Badge variant="outline" className="capitalize">{String(p.status ?? "active")}</Badge>
          </div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No playbooks created. Create response playbooks to automate incident handling.</p>}
      </CardContent></Card>
    </div>
  );
}
