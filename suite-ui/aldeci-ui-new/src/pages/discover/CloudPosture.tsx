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
import { useDashboardTopRisks, useDashboardOverview } from "@/hooks/use-api";

export default function CloudPosture() {
  const risks = useDashboardTopRisks();
  const overview = useDashboardOverview();
  const refetch = useCallback(() => { risks.refetch(); overview.refetch(); }, [risks, overview]);
  if (risks.isLoading) return <PageSkeleton />;
  if (risks.isError) return <ErrorState onRetry={refetch} />;
  const allRisks = risks.data?.risks ?? [];
  const ov = overview.data ?? {};
  const cloudFindings = allRisks.filter((r: Record<string, unknown>) => { const t = String(r.title ?? "").toLowerCase(); return t.includes("cloud") || t.includes("s3") || t.includes("gcp") || t.includes("aws") || t.includes("azure"); });
  const cols = [
    { key: "title", header: "Finding", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate">{String(r.title)}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Cloud Posture" description="Cloud security posture management (CSPM)" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Cloud Issues" value={cloudFindings.length} icon={Cloud} /><KpiCard title="Total Findings" value={ov.total_findings ?? 0} icon={Shield} /><KpiCard title="Critical" value={ov.critical_findings ?? 0} icon={AlertTriangle} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Cloud Findings ({cloudFindings.length})</CardTitle></CardHeader><CardContent><DataTable columns={cols} data={cloudFindings} emptyMessage="No cloud posture findings. Connect cloud accounts to begin." /></CardContent></Card>
    </div>
  );
}
