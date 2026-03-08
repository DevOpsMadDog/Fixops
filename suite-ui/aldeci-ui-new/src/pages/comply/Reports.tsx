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
import { useReports } from "@/hooks/use-api";

export default function Reports() {
  const reports = useReports();
  const refetch = useCallback(() => reports.refetch(), [reports]);
  if (reports.isLoading) return <PageSkeleton />;
  if (reports.isError) return <ErrorState onRetry={refetch} />;
  const list = Array.isArray(reports.data) ? reports.data : reports.data?.reports ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Reports" description="Generated compliance and security reports" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Reports" value={list.length} icon={FileText} /><KpiCard title="Generated" value={list.length} icon={Download} /><KpiCard title="Available" value={list.length} icon={BarChart3} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Report Library ({list.length})</CardTitle></CardHeader><CardContent>
        {list.length > 0 ? <div className="space-y-2">{list.map((r: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><span className="font-medium text-sm">{String(r.name ?? r.title ?? `Report ${i + 1}`)}</span><Badge variant="outline">{String(r.type ?? "report")}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No reports generated. Use the compliance dashboard to trigger report generation.</p>}
      </CardContent></Card>
    </div>
  );
}
