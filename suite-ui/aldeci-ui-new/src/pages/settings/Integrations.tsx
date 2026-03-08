import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Plug, RefreshCw, CheckCircle2, XCircle } from "lucide-react";
import { useIntegrations } from "@/hooks/use-api";

export default function Integrations() {
  const ints = useIntegrations();
  const refetch = useCallback(() => ints.refetch(), [ints]);
  if (ints.isLoading) return <PageSkeleton />;
  if (ints.isError) return <ErrorState onRetry={refetch} />;
  const list = Array.isArray(ints.data) ? ints.data : ints.data?.integrations ?? [];
  const connected = list.filter((i: Record<string, unknown>) => i.status === "connected" || i.status === "active");
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Integrations" description="External service connections" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Total" value={list.length} icon={Plug} /><KpiCard title="Connected" value={connected.length} icon={CheckCircle2} /><KpiCard title="Disconnected" value={list.length - connected.length} icon={XCircle} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Integrations ({list.length})</CardTitle></CardHeader><CardContent>
        {list.length > 0 ? <div className="space-y-2">{list.map((int: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><div><p className="font-medium text-sm">{String(int.name ?? int.type ?? `Integration ${i + 1}`)}</p><p className="text-xs text-muted-foreground">{String(int.type ?? "")}</p></div><Badge variant={int.status === "connected" || int.status === "active" ? "default" : "outline"} className="capitalize">{String(int.status ?? "unknown")}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No integrations configured. Connect Jira, GitHub, Slack, and more.</p>}
      </CardContent></Card>
    </div>
  );
}
