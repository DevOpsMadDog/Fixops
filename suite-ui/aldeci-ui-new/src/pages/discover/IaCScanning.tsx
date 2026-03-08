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
import { useDashboardTopRisks } from "@/hooks/use-api";

export default function IaCScanning() {
  const risks = useDashboardTopRisks();
  const refetch = useCallback(() => risks.refetch(), [risks]);
  if (risks.isLoading) return <PageSkeleton />;
  if (risks.isError) return <ErrorState onRetry={refetch} />;
  const allRisks = risks.data?.risks ?? [];
  const iacFindings = allRisks.filter((r: Record<string, unknown>) => { const t = String(r.title ?? "").toLowerCase(); return t.includes("terraform") || t.includes("iac") || t.includes("cloudformation") || t.includes("kubernetes") || String(r.rule_id ?? "").startsWith("IAC"); });
  const cols = [
    { key: "title", header: "Finding", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate">{String(r.title)}</p><p className="text-xs text-muted-foreground">{(r.metadata as Record<string, unknown>)?.file_path ?? "—"}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="IaC Scanning" description="Infrastructure-as-Code security analysis" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="IaC Issues" value={iacFindings.length} icon={Layers} /><KpiCard title="All Risks" value={allRisks.length} icon={Shield} /><KpiCard title="Critical" value={iacFindings.filter((r: Record<string, unknown>) => r.severity === "critical").length} icon={AlertTriangle} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">IaC Findings ({iacFindings.length})</CardTitle></CardHeader><CardContent><DataTable columns={cols} data={iacFindings} emptyMessage="No IaC findings. Configure Checkov or Terraform scanning." /></CardContent></Card>
    </div>
  );
}
