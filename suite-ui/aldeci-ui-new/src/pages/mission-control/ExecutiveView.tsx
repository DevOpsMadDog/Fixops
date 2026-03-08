import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Shield, TrendingUp, AlertTriangle, CheckCircle2, RefreshCw, Server, Activity } from "lucide-react";
import { useDashboardOverview, useDashboardCompliance, useNerveState, useNervePulse } from "@/hooks/use-api";

export default function ExecutiveView() {
  const overview = useDashboardOverview();
  const compliance = useDashboardCompliance();
  const nerveState = useNerveState();
  const pulse = useNervePulse();
  const isLoading = overview.isLoading || nerveState.isLoading;
  const refetch = useCallback(() => { overview.refetch(); compliance.refetch(); nerveState.refetch(); pulse.refetch(); }, [overview, compliance, nerveState, pulse]);

  if (isLoading) return <PageSkeleton />;
  if (overview.isError) return <ErrorState onRetry={refetch} />;

  const ov = overview.data ?? {};
  const comp = compliance.data ?? {};
  const state = nerveState.data ?? {};
  const p = pulse.data ?? {};
  const suites = state.suites ?? [];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Executive View" description="High-level security posture for leadership" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Open Findings" value={ov.open_findings ?? 0} icon={Shield} />
        <KpiCard title="Critical" value={ov.critical_findings ?? 0} icon={AlertTriangle} trend="up" />
        <KpiCard title="Threat Score" value={`${Number(p.score ?? 0).toFixed(1)}`} icon={Activity} />
        <KpiCard title="Compliance" value={`${Number(comp.compliance_score ?? 0).toFixed(0)}%`} icon={CheckCircle2} />
      </div>

      {/* Suite Health */}
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Platform Suite Health</CardTitle></CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {suites.length > 0 ? suites.map((s: Record<string, unknown>) => (
              <div key={String(s.suite)} className="flex items-center gap-3 rounded-lg border border-border/50 p-3">
                <Server className="h-5 w-5 text-muted-foreground" />
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm truncate">{String(s.suite)}</p>
                  <p className="text-xs text-muted-foreground">{Number(s.latency_ms ?? 0).toFixed(0)}ms latency</p>
                </div>
                <Badge variant={s.status === "healthy" ? "default" : "destructive"} className="capitalize">{String(s.status)}</Badge>
              </div>
            )) : <p className="text-sm text-muted-foreground col-span-full">No suite data available.</p>}
          </div>
        </CardContent>
      </Card>

      {/* Summary Cards */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Risk Summary</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm"><span>Total Findings</span><span className="font-mono">{ov.total_findings ?? 0}</span></div>
              <div className="flex justify-between text-sm"><span>Last 30 Days</span><span className="font-mono">{ov.recent_findings_30d ?? 0}</span></div>
              <div className="flex justify-between text-sm"><span>Active Incidents</span><span className="font-mono">{p.active_incidents ?? 0}</span></div>
              <div className="flex justify-between text-sm"><span>Auto-Blocked</span><span className="font-mono">{p.auto_blocked ?? 0}</span></div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Compliance Posture</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex justify-between text-sm"><span>Score</span><span className="font-mono">{Number(comp.compliance_score ?? 0).toFixed(1)}%</span></div>
              <Progress value={Number(comp.compliance_score ?? 0)} className="h-2" />
              <div className="flex justify-between text-sm"><span>Open Findings</span><span className="font-mono">{comp.open_findings ?? 0}</span></div>
              <div className="flex justify-between text-sm"><span>Critical Findings</span><span className="font-mono">{comp.critical_findings ?? 0}</span></div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
