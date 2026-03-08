import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { ShieldCheck, AlertTriangle, CheckCircle2, RefreshCw, FileText, Download, BarChart3, History, Package } from "lucide-react";
import { useDashboardOverview, useDashboardTrends, useDashboardCompliance } from "@/hooks/use-api";

export default function Analytics() {
  const overview = useDashboardOverview();
  const trends = useDashboardTrends();
  const compliance = useDashboardCompliance();
  const refetch = useCallback(() => { overview.refetch(); trends.refetch(); compliance.refetch(); }, [overview, trends, compliance]);
  if (overview.isLoading) return <PageSkeleton />;
  if (overview.isError) return <ErrorState onRetry={refetch} />;
  const ov = overview.data ?? {};
  const comp = compliance.data ?? {};
  const sevTotals = trends.data?.severity_totals ?? {};
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Compliance Analytics" description="Metrics and trends for compliance posture" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Findings" value={ov.total_findings ?? 0} icon={BarChart3} />
        <KpiCard title="Critical" value={ov.critical_findings ?? 0} icon={AlertTriangle} />
        <KpiCard title="Compliance" value={`${Number(comp.compliance_score ?? 0).toFixed(0)}%`} icon={ShieldCheck} />
        <KpiCard title="Open" value={comp.open_findings ?? 0} icon={FileText} />
      </div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Severity Distribution</CardTitle></CardHeader><CardContent>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">{Object.entries(sevTotals).map(([k, v]) => (
          <div key={k} className="rounded-lg border border-border/50 p-3 text-center"><p className="text-xs text-muted-foreground capitalize">{k}</p><p className="text-2xl font-bold">{String(v)}</p></div>
        ))}</div>
        {Object.keys(sevTotals).length === 0 && <p className="text-sm text-muted-foreground text-center py-4">No severity data available.</p>}
      </CardContent></Card>
    </div>
  );
}
