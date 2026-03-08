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

export default function AttackPaths() {
  const risks = useDashboardTopRisks();
  const refetch = useCallback(() => risks.refetch(), [risks]);
  if (risks.isLoading) return <PageSkeleton />;
  if (risks.isError) return <ErrorState onRetry={refetch} />;
  const allRisks = risks.data?.risks ?? [];
  const exploitable = allRisks.filter((r: Record<string, unknown>) => r.exploitable);
  const cols = [
    { key: "title", header: "Attack Vector", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate">{String(r.title)}</p><p className="text-xs text-muted-foreground">{String(r.source ?? "")}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
    { key: "epss_score", header: "EPSS", render: (r: Record<string, unknown>) => <span className="font-mono">{r.epss_score != null ? (Number(r.epss_score) * 100).toFixed(0) + "%" : "—"}</span> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Attack Paths" description="Exploitable vulnerability chains and blast radius" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Exploitable" value={exploitable.length} icon={Radio} /><KpiCard title="Total Risks" value={allRisks.length} icon={Shield} /><KpiCard title="Critical" value={allRisks.filter((r: Record<string, unknown>) => r.severity === "critical").length} icon={AlertTriangle} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Exploitable Paths ({exploitable.length})</CardTitle></CardHeader><CardContent><DataTable columns={cols} data={exploitable} emptyMessage="No exploitable paths found. MPTE validation identifies reachable attack paths." /></CardContent></Card>
    </div>
  );
}
