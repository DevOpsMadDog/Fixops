import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Key, AlertTriangle, RefreshCw, Lock } from "lucide-react";
import { useDashboardTopRisks } from "@/hooks/use-api";

export default function SecretsDetection() {
  const risks = useDashboardTopRisks();
  const refetch = useCallback(() => risks.refetch(), [risks]);
  if (risks.isLoading) return <PageSkeleton />;
  if (risks.isError) return <ErrorState onRetry={refetch} />;

  const allRisks = risks.data?.risks ?? [];
  const secrets = allRisks.filter((r: Record<string, unknown>) => {
    const title = String(r.title ?? "").toLowerCase();
    const cwe = String((r.metadata as Record<string, unknown>)?.cwe_id ?? "");
    return title.includes("secret") || title.includes("key") || title.includes("credential") || title.includes("token") || title.includes("password") || cwe === "CWE-798";
  });

  const cols = [
    { key: "title", header: "Secret", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate">{String(r.title)}</p><p className="text-xs text-muted-foreground">{(r.metadata as Record<string, unknown>)?.file_path ?? "—"}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Secrets Detection" description="Detect exposed credentials, API keys, and tokens" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Secrets" value={secrets.length} icon={Key} />
        <KpiCard title="Critical" value={secrets.filter((s: Record<string, unknown>) => s.severity === "critical").length} icon={AlertTriangle} trend="up" />
        <KpiCard title="All Risks" value={allRisks.length} icon={Lock} />
        <KpiCard title="Open" value={secrets.filter((s: Record<string, unknown>) => s.status === "open").length} icon={Key} />
      </div>
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Detected Secrets ({secrets.length})</CardTitle></CardHeader>
        <CardContent><DataTable columns={cols} data={secrets} emptyMessage="No exposed secrets detected. Configure secret scanning." /></CardContent>
      </Card>
    </div>
  );
}
