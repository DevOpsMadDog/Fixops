import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Sparkles, Wrench, RefreshCw, Play } from "lucide-react";
import { useRemediationTasks, useAutofix } from "@/hooks/use-api";
import { toast } from "sonner";

export default function AutoFix() {
  const [findingId, setFindingId] = useState("");
  const tasks = useRemediationTasks();
  const autofix = useAutofix();
  const refetch = useCallback(() => tasks.refetch(), [tasks]);

  if (tasks.isLoading) return <PageSkeleton />;
  if (tasks.isError) return <ErrorState onRetry={refetch} />;

  const items = tasks.data?.tasks ?? [];
  const handleAutofix = () => {
    if (!findingId.trim()) { toast.error("Enter a finding ID"); return; }
    autofix.mutate(findingId.trim());
  };

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="AutoFix" description="AI-powered automatic remediation generation" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <KpiCard title="Tasks" value={items.length} icon={Wrench} />
        <KpiCard title="Auto-Fixable" value={items.filter((t: Record<string, unknown>) => t.severity === "critical" || t.severity === "high").length} icon={Sparkles} />
        <KpiCard title="Critical" value={items.filter((t: Record<string, unknown>) => t.severity === "critical").length} icon={Sparkles} />
      </div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Generate AutoFix</CardTitle></CardHeader><CardContent>
        <div className="flex gap-3"><Input placeholder="Finding ID..." value={findingId} onChange={(e) => setFindingId(e.target.value)} className="flex-1 max-w-sm" /><Button onClick={handleAutofix} disabled={autofix.isPending}><Play className="mr-2 h-4 w-4" />{autofix.isPending ? "Generating..." : "Generate Fix"}</Button></div>
      </CardContent></Card>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Remediation Tasks ({items.length})</CardTitle></CardHeader><CardContent>
        <div className="space-y-2">{items.slice(0, 10).map((t: Record<string, unknown>, i: number) => (
          <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50">
            <div className="min-w-0 flex-1"><p className="font-medium text-sm truncate">{String(t.title)}</p><p className="text-xs text-muted-foreground">{String(t.assignee ?? "Unassigned")}</p></div>
            <div className="flex items-center gap-2"><Badge variant={t.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(t.severity)}</Badge><Button size="sm" variant="ghost" onClick={() => { setFindingId(String(t.task_id)); }}><Sparkles className="h-3 w-3" /></Button></div>
          </div>
        ))}{items.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">No tasks available for autofix.</p>}</div>
      </CardContent></Card>
    </div>
  );
}
