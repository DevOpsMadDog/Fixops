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
import { useAuditLog } from "@/hooks/use-api";

export default function AuditTrail() {
  const audit = useAuditLog();
  const refetch = useCallback(() => audit.refetch(), [audit]);
  if (audit.isLoading) return <PageSkeleton />;
  if (audit.isError) return <ErrorState onRetry={refetch} />;
  const entries = Array.isArray(audit.data) ? audit.data : audit.data?.entries ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Audit Trail" description="Immutable, tamper-proof audit log of all actions" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Entries" value={entries.length} icon={History} /><KpiCard title="Actions" value={entries.length} icon={FileText} /><KpiCard title="Verified" value={entries.length} icon={ShieldCheck} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Audit Log ({entries.length})</CardTitle></CardHeader><CardContent>
        {entries.length > 0 ? <div className="space-y-2">{entries.slice(0, 20).map((e: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><div><p className="font-medium text-sm">{String(e.action ?? e.event ?? "Event")}</p><p className="text-xs text-muted-foreground">{String(e.user ?? "")} · {e.timestamp ? new Date(String(e.timestamp)).toLocaleString() : ""}</p></div><Badge variant="outline">{String(e.type ?? "audit")}</Badge></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">Audit trail is empty. Actions will be logged as you use the platform.</p>}
      </CardContent></Card>
    </div>
  );
}
