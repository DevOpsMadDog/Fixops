import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { FileText, Plus, RefreshCw, Shield } from "lucide-react";
import { usePolicies } from "@/hooks/use-api";

export default function Policies() {
  const policies = usePolicies();
  const refetch = useCallback(() => policies.refetch(), [policies]);
  if (policies.isLoading) return <PageSkeleton />;
  if (policies.isError) return <ErrorState onRetry={refetch} />;
  const list = Array.isArray(policies.data) ? policies.data : policies.data?.policies ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Policies" description="Security policy management" actions={<div className="flex gap-2"><Button size="sm"><Plus className="mr-2 h-4 w-4" />Create Policy</Button><Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Policies" value={list.length} icon={FileText} /><KpiCard title="Active" value={list.filter((p: Record<string, unknown>) => p.enabled).length} icon={Shield} /><KpiCard title="Total" value={list.length} icon={FileText} /></div>
      <Card><CardContent className="pt-6">
        {list.length > 0 ? <div className="space-y-2">{list.map((p: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><span className="font-medium text-sm">{String(p.name ?? `Policy ${i + 1}`)}</span><Badge variant="outline">{p.enabled ? "Active" : "Disabled"}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No policies defined. Create security policies to enforce standards.</p>}
      </CardContent></Card>
    </div>
  );
}
