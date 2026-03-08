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
import { useEvidenceBundles } from "@/hooks/use-api";

export default function SLSAProvenance() {
  const bundles = useEvidenceBundles();
  const refetch = useCallback(() => bundles.refetch(), [bundles]);
  if (bundles.isLoading) return <PageSkeleton />;
  if (bundles.isError) return <ErrorState onRetry={refetch} />;
  const list = bundles.data?.bundles ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="SLSA Provenance" description="Supply chain integrity and SLSA level tracking" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Bundles" value={list.length} icon={Package} /><KpiCard title="Signed" value={list.filter((b: Record<string, unknown>) => b.signature_valid).length} icon={ShieldCheck} /><KpiCard title="Verified" value={list.filter((b: Record<string, unknown>) => b.status === "signed").length} icon={CheckCircle2} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Provenance Records</CardTitle></CardHeader><CardContent>
        {list.length > 0 ? <div className="space-y-2">{list.map((b: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><div><p className="font-medium text-sm">{String(b.id)}</p><p className="text-xs text-muted-foreground">Hash: {String(b.hash ?? "").slice(0, 30)}...</p></div><Badge variant={b.signature_valid ? "default" : "destructive"}>{b.signature_valid ? "Verified" : "Unverified"}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No provenance records. Generate evidence bundles to create provenance.</p>}
      </CardContent></Card>
    </div>
  );
}
