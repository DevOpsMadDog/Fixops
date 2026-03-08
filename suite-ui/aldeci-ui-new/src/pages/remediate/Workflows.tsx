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
import { useWorkflowRules } from "@/hooks/use-api";

export default function Workflows() {
  const rules = useWorkflowRules();
  const refetch = useCallback(() => rules.refetch(), [rules]);
  if (rules.isLoading) return <PageSkeleton />;
  if (rules.isError) return <ErrorState onRetry={refetch} />;
  const ruleList = Array.isArray(rules.data) ? rules.data : rules.data?.rules ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Workflows" description="Automation rules and workflow management" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Rules" value={ruleList.length} icon={GitPullRequest} /><KpiCard title="Active" value={ruleList.filter((r: Record<string, unknown>) => r.enabled).length} icon={Shield} /><KpiCard title="Total" value={ruleList.length} icon={Layers} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Workflow Rules ({ruleList.length})</CardTitle></CardHeader><CardContent>
        {ruleList.length > 0 ? <div className="space-y-2">{ruleList.map((r: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><span className="font-medium text-sm">{String(r.name ?? r.id ?? `Rule ${i + 1}`)}</span><Badge variant="outline">{r.enabled ? "Active" : "Disabled"}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No workflow rules configured. Create rules to automate remediation workflows.</p>}
      </CardContent></Card>
    </div>
  );
}
