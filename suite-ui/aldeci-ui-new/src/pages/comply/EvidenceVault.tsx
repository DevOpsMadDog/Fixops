import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Archive, ShieldCheck, FileText, RefreshCw, Download } from "lucide-react";
import { useEvidenceBundles, useEvidenceComplianceStatus } from "@/hooks/use-api";

export default function EvidenceVault() {
  const bundles = useEvidenceBundles();
  const compStatus = useEvidenceComplianceStatus();
  const refetch = useCallback(() => { bundles.refetch(); compStatus.refetch(); }, [bundles, compStatus]);
  if (bundles.isLoading) return <PageSkeleton />;
  if (bundles.isError) return <ErrorState onRetry={refetch} />;

  const bundleList = bundles.data?.bundles ?? [];
  const fwStatus = compStatus.data?.frameworks ?? {};

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Evidence Vault" description="Cryptographically signed evidence bundles for audit" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Bundles" value={bundleList.length} icon={Archive} />
        <KpiCard title="Signed" value={bundleList.filter((b: Record<string, unknown>) => b.signature_valid).length} icon={ShieldCheck} />
        <KpiCard title="Frameworks" value={Object.keys(fwStatus).length} icon={FileText} />
        <KpiCard title="Total Pages" value={bundleList.reduce((a: number, b: Record<string, unknown>) => a + ((b.sections as Record<string, unknown>[]) ?? []).reduce((s: number, sec: Record<string, unknown>) => s + Number(sec.page_count ?? 0), 0), 0)} icon={FileText} />
      </div>

      {/* Framework Status */}
      {Object.keys(fwStatus).length > 0 && (
        <Card><CardHeader><CardTitle className="text-sm font-medium">Framework Coverage</CardTitle></CardHeader><CardContent>
          <div className="grid gap-3 sm:grid-cols-2">
            {Object.entries(fwStatus).map(([name, fw]) => {
              const f = fw as Record<string, unknown>;
              return (
                <div key={name} className="rounded-lg border border-border/50 p-3 space-y-2">
                  <div className="flex items-center justify-between"><span className="font-medium text-sm">{name}</span><Badge variant={f.status === "in_progress" ? "default" : "outline"} className="capitalize">{String(f.status)}</Badge></div>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <div className="flex justify-between"><span>Coverage</span><span className="font-mono">{Number(f.coverage_pct ?? 0).toFixed(0)}%</span></div>
                    <div className="flex justify-between"><span>Controls</span><span className="font-mono">{f.controls_mapped}/{f.controls_total}</span></div>
                    <div className="flex justify-between"><span>Evidence</span><span className="font-mono">{f.evidence_collected ?? 0}</span></div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent></Card>
      )}

      {/* Bundles */}
      <Card><CardHeader><CardTitle className="text-sm font-medium">Evidence Bundles ({bundleList.length})</CardTitle></CardHeader><CardContent>
        <div className="space-y-3">
          {bundleList.map((b: Record<string, unknown>, i: number) => (
            <div key={i} className="rounded-lg border border-border/50 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div><p className="font-medium">{String(b.id)}</p><p className="text-xs text-muted-foreground">{((b.frameworks as string[]) ?? []).join(", ")} · {b.finding_count ?? 0} findings</p></div>
                <div className="flex items-center gap-2">
                  <Badge variant={b.signature_valid ? "default" : "destructive"}>{b.signature_valid ? "Verified" : "Invalid"}</Badge>
                  <Badge variant="outline" className="capitalize">{String(b.status)}</Badge>
                </div>
              </div>
              <div className="text-xs text-muted-foreground grid grid-cols-2 gap-2 sm:grid-cols-4">
                <span>Size: {b.size_mb}MB</span>
                <span>Remediations: {b.remediation_count}</span>
                <span>Signed: {String(b.signed_by ?? "")}</span>
                <span>Range: {(b.date_range as Record<string, string>)?.start} — {(b.date_range as Record<string, string>)?.end}</span>
              </div>
              <div className="flex flex-wrap gap-1">{((b.sections as Record<string, unknown>[]) ?? []).map((s: Record<string, unknown>, j: number) => <Badge key={j} variant="outline" className="text-[10px]">{String(s.name)} ({s.page_count}p)</Badge>)}</div>
            </div>
          ))}
          {bundleList.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">No evidence bundles generated. Run compliance assessments to generate.</p>}
        </div>
      </CardContent></Card>
    </div>
  );
}
