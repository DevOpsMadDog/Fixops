import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { FileText, RefreshCw, Activity } from "lucide-react";
import { useAuditLog } from "@/hooks/use-api";

export default function LogViewer() {
  const audit = useAuditLog();
  const refetch = useCallback(() => audit.refetch(), [audit]);
  if (audit.isLoading) return <PageSkeleton />;
  if (audit.isError) return <ErrorState onRetry={refetch} />;
  const entries = Array.isArray(audit.data) ? audit.data : audit.data?.entries ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Log Viewer" description="System and audit log viewer" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <KpiCard title="Log Entries" value={entries.length} icon={FileText} className="max-w-xs" />
      <Card><CardContent className="pt-6">
        {entries.length > 0 ? <div className="space-y-1 font-mono text-xs">{entries.slice(0, 50).map((e: Record<string, unknown>, i: number) => (
          <div key={i} className="flex gap-3 py-1 border-b border-border/20"><span className="text-muted-foreground shrink-0">{e.timestamp ? new Date(String(e.timestamp)).toLocaleTimeString() : "—"}</span><span className="text-primary">{String(e.level ?? "INFO")}</span><span>{String(e.message ?? e.action ?? JSON.stringify(e))}</span></div>
        ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No log entries. Logs will appear as the system operates.</p>}
      </CardContent></Card>
    </div>
  );
}
