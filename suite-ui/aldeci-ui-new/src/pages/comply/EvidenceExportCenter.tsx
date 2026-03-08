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
import { useEvidenceBundles, useGenerateEvidence } from "@/hooks/use-api";

export default function EvidenceExportCenter() {
  const bundles = useEvidenceBundles();
  const generate = useGenerateEvidence();
  const refetch = useCallback(() => bundles.refetch(), [bundles]);
  if (bundles.isLoading) return <PageSkeleton />;
  if (bundles.isError) return <ErrorState onRetry={refetch} />;
  const list = bundles.data?.bundles ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Evidence Export Center" description="Export evidence bundles for external auditors"
        actions={<div className="flex gap-2"><Button size="sm" onClick={() => generate.mutate({ framework: "SOC2", org_id: "default" })} disabled={generate.isPending}><Download className="mr-2 h-4 w-4" />{generate.isPending ? "Generating..." : "Generate Bundle"}</Button><Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Bundles" value={list.length} icon={Package} /><KpiCard title="Exportable" value={list.filter((b: Record<string, unknown>) => b.status === "signed").length} icon={Download} /><KpiCard title="Total Size" value={`${list.reduce((a: number, b: Record<string, unknown>) => a + Number(b.size_mb ?? 0), 0).toFixed(1)}MB`} icon={FileText} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Available for Export ({list.length})</CardTitle></CardHeader><CardContent>
        {list.length > 0 ? <div className="space-y-2">{list.map((b: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><div><p className="font-medium text-sm">{String(b.id)}</p><p className="text-xs text-muted-foreground">{((b.frameworks as string[]) ?? []).join(", ")} · {b.size_mb}MB</p></div><Button size="sm" variant="outline"><Download className="mr-1 h-3 w-3" />Export</Button></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No exportable bundles. Generate evidence bundles first.</p>}
      </CardContent></Card>
    </div>
  );
}
