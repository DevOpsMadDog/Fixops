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
import { useComplianceSoc2, useComplianceGaps } from "@/hooks/use-api";

export default function SOC2Evidence() {
  const soc2 = useComplianceSoc2();
  const gaps = useComplianceGaps();
  const refetch = useCallback(() => { soc2.refetch(); gaps.refetch(); }, [soc2, gaps]);
  if (soc2.isLoading) return <PageSkeleton />;
  if (soc2.isError) return <ErrorState onRetry={refetch} />;
  const s = soc2.data ?? {};
  const soc2Gaps = (gaps.data?.gaps ?? []).filter((g: Record<string, unknown>) => g.framework === "SOC2");
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="SOC 2 Evidence" description="SOC 2 Type II compliance tracking and evidence" badge={String(s.status ?? "").toUpperCase()} actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Score" value={`${Number(s.overall_score ?? 0).toFixed(0)}%`} icon={ShieldCheck} />
        <KpiCard title="Controls" value={s.total_controls ?? 0} icon={CheckCircle2} />
        <KpiCard title="Satisfied" value={s.satisfied ?? 0} icon={CheckCircle2} trend="up" />
        <KpiCard title="Gaps" value={s.gaps_count ?? 0} icon={AlertTriangle} trend={Number(s.gaps_count ?? 0) > 0 ? "up" : "flat"} />
      </div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Control Status</CardTitle></CardHeader><CardContent>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 text-sm">
          <div className="space-y-1"><span className="text-muted-foreground">Satisfied</span><p className="text-2xl font-bold text-green-400">{s.satisfied ?? 0}</p></div>
          <div className="space-y-1"><span className="text-muted-foreground">Partial</span><p className="text-2xl font-bold text-yellow-400">{s.partially_satisfied ?? 0}</p></div>
          <div className="space-y-1"><span className="text-muted-foreground">Not Satisfied</span><p className="text-2xl font-bold text-red-400">{s.not_satisfied ?? 0}</p></div>
          <div className="space-y-1"><span className="text-muted-foreground">Not Assessed</span><p className="text-2xl font-bold text-muted-foreground">{s.not_assessed ?? 0}</p></div>
        </div>
      </CardContent></Card>
      <Card><CardHeader><CardTitle className="text-sm font-medium">SOC 2 Gaps ({soc2Gaps.length})</CardTitle></CardHeader><CardContent>
        <div className="space-y-2">{soc2Gaps.slice(0, 10).map((g: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><div><span className="font-mono text-xs text-primary mr-2">{String(g.control_id)}</span><span className="text-sm font-medium">{String(g.title)}</span></div><Badge variant="destructive" className="text-[10px]">{String(g.gap_type ?? "").replace(/_/g, " ")}</Badge></div>
        ))}{soc2Gaps.length === 0 && <p className="text-sm text-muted-foreground text-center py-4">No SOC 2 gaps. Run assessment to check.</p>}</div>
      </CardContent></Card>
    </div>
  );
}
