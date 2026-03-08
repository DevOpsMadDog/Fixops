import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Shield, AlertTriangle, RefreshCw, Activity, Layers, Cloud, Container, Box, GitBranch, Radio, Globe } from "lucide-react";
import { useIntelligenceMap } from "@/hooks/use-api";

export default function KnowledgeGraph() {
  const intel = useIntelligenceMap();
  const refetch = useCallback(() => intel.refetch(), [intel]);
  if (intel.isLoading) return <PageSkeleton />;
  if (intel.isError) return <ErrorState onRetry={refetch} />;
  const nodes = intel.data?.nodes ?? [];
  const edges = intel.data?.edges ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Knowledge Graph" description="Security intelligence relationship graph" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Nodes" value={nodes.length} icon={GitBranch} /><KpiCard title="Edges" value={edges.length} icon={Activity} /><KpiCard title="Suites" value={[...new Set(nodes.map((n: Record<string, unknown>) => n.suite))].length} icon={Layers} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Graph Nodes ({nodes.length})</CardTitle></CardHeader><CardContent>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {nodes.map((n: Record<string, unknown>) => (
            <div key={String(n.id)} className="rounded-lg border border-border/50 p-3 space-y-2">
              <div className="flex items-center gap-2"><GitBranch className="h-4 w-4 text-primary" /><span className="font-medium text-sm">{String(n.label)}</span></div>
              <p className="text-xs text-muted-foreground">{String(n.suite)} · {String(n.type)}</p>
              <div className="flex flex-wrap gap-1">{(n.apis as string[] ?? []).map((a: string) => <Badge key={a} variant="outline" className="text-[10px]">{a}</Badge>)}</div>
            </div>
          ))}
        </div>
        {nodes.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">Graph is empty. Data will populate as findings are ingested.</p>}
      </CardContent></Card>
    </div>
  );
}
