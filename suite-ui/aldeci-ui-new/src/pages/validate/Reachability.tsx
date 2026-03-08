import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Network, Shield, AlertTriangle, RefreshCw } from "lucide-react";
import { useDashboardTopRisks } from "@/hooks/use-api";

export default function Reachability() {
  const risks = useDashboardTopRisks();
  const refetch = useCallback(() => risks.refetch(), [risks]);
  if (risks.isLoading) return <PageSkeleton />;
  if (risks.isError) return <ErrorState onRetry={refetch} />;
  const allRisks = risks.data?.risks ?? [];
  const reachable = allRisks.filter((r: Record<string, unknown>) => r.exploitable);
  const cols = [
    { key: "title", header: "Finding", render: (r: Record<string, unknown>) => <p className="font-medium text-sm max-w-sm truncate">{String(r.title)}</p> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "exploitable", header: "Reachable", render: (r: Record<string, unknown>) => <Badge variant={r.exploitable ? "destructive" : "outline"}>{r.exploitable ? "Yes" : "No"}</Badge> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Reachability Analysis" description="Determine which vulnerabilities are actually reachable" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Total" value={allRisks.length} icon={Shield} /><KpiCard title="Reachable" value={reachable.length} icon={Network} /><KpiCard title="Critical" value={reachable.filter((r: Record<string, unknown>) => r.severity === "critical").length} icon={AlertTriangle} /></div>
      <Card><CardContent className="pt-6"><DataTable columns={cols} data={allRisks} emptyMessage="No reachability data. Run MPTE scans to determine reachability." /></CardContent></Card>
    </div>
  );
}
