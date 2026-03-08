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
import { useCases } from "@/hooks/use-api";

export default function ExposureCases() {
  const cases = useCases();
  const refetch = useCallback(() => cases.refetch(), [cases]);
  if (cases.isLoading) return <PageSkeleton />;
  if (cases.isError) return <ErrorState onRetry={refetch} />;
  const caseList = cases.data?.cases ?? [];
  const cols = [
    { key: "case_id", header: "ID", render: (r: Record<string, unknown>) => <span className="font-mono text-xs text-primary">{String(r.case_id)}</span> },
    { key: "title", header: "Case", render: (r: Record<string, unknown>) => <p className="font-medium text-sm max-w-sm truncate">{String(r.title)}</p> },
    { key: "priority", header: "Priority", render: (r: Record<string, unknown>) => <Badge variant={r.priority === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.priority)}</Badge> },
    { key: "finding_count", header: "Findings", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.finding_count ?? 0)}</span> },
    { key: "risk_score", header: "Risk", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.risk_score ?? 0).toFixed(1)}</span> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Exposure Cases" description="Aggregated exposure cases from correlated findings" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Cases" value={caseList.length} icon={Ticket} /><KpiCard title="Critical" value={caseList.filter((c: Record<string, unknown>) => c.priority === "critical").length} icon={AlertTriangle} /><KpiCard title="Open" value={caseList.filter((c: Record<string, unknown>) => c.status === "open").length} icon={Shield} /></div>
      <Card><CardContent className="pt-6"><DataTable columns={cols} data={caseList} emptyMessage="No exposure cases yet." /></CardContent></Card>
    </div>
  );
}
