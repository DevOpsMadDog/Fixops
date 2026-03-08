import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Code2, AlertTriangle, FileCode, RefreshCw, Bug } from "lucide-react";
import { useDashboardTopRisks } from "@/hooks/use-api";

export default function CodeScanning() {
  const risks = useDashboardTopRisks();
  const refetch = useCallback(() => risks.refetch(), [risks]);
  if (risks.isLoading) return <PageSkeleton />;
  if (risks.isError) return <ErrorState onRetry={refetch} />;

  const allRisks = risks.data?.risks ?? [];
  const codeFindings = allRisks.filter((r: Record<string, unknown>) => String(r.source ?? "").toLowerCase().includes("sast") || String(r.rule_id ?? "").startsWith("SAST"));

  const cols = [
    { key: "title", header: "Finding", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate">{String(r.title)}</p><p className="text-xs text-muted-foreground">{(r.metadata as Record<string, unknown>)?.file_path ?? "—"} L{(r.metadata as Record<string, unknown>)?.line_number ?? ""}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "rule_id", header: "Rule", render: (r: Record<string, unknown>) => <span className="font-mono text-xs">{String(r.rule_id)}</span> },
    { key: "cwe", header: "CWE", render: (r: Record<string, unknown>) => <span className="font-mono text-xs">{String((r.metadata as Record<string, unknown>)?.cwe_id ?? "—")}</span> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Code Scanning" description="SAST findings from static analysis of source code" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Findings" value={allRisks.length} icon={Code2} />
        <KpiCard title="SAST Findings" value={codeFindings.length} icon={FileCode} />
        <KpiCard title="Critical" value={codeFindings.filter((r: Record<string, unknown>) => r.severity === "critical").length} icon={AlertTriangle} trend="up" />
        <KpiCard title="Exploitable" value={codeFindings.filter((r: Record<string, unknown>) => r.exploitable).length} icon={Bug} />
      </div>
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">SAST Findings ({codeFindings.length})</CardTitle></CardHeader>
        <CardContent><DataTable columns={cols} data={codeFindings} emptyMessage="No code scanning findings. Configure SAST scanners to begin." /></CardContent>
      </Card>
    </div>
  );
}
