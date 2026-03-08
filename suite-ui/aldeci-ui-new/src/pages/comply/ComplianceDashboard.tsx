import { useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { ShieldCheck, AlertTriangle, CheckCircle2, RefreshCw, FileText, Play } from "lucide-react";
import { useComplianceFrameworks, useComplianceGaps, useDashboardCompliance, useAssessCompliance } from "@/hooks/use-api";

export default function ComplianceDashboard() {
  const frameworks = useComplianceFrameworks();
  const gaps = useComplianceGaps();
  const compliance = useDashboardCompliance();
  const assess = useAssessCompliance();
  const refetch = useCallback(() => { frameworks.refetch(); gaps.refetch(); compliance.refetch(); }, [frameworks, gaps, compliance]);

  if (frameworks.isLoading) return <PageSkeleton />;
  if (frameworks.isError) return <ErrorState onRetry={refetch} />;

  const fwList = frameworks.data?.frameworks ?? [];
  const gapList = gaps.data?.gaps ?? [];
  const comp = compliance.data ?? {};

  const chartData = fwList.map((fw: Record<string, unknown>) => ({
    name: String(fw.framework ?? ""),
    total: Number(fw.total_controls ?? 0),
    automated: Number(fw.automated_controls ?? 0),
    fill: fw.enabled ? "#20808D" : "#6b7280",
  }));

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Compliance Dashboard" description="Continuous compliance monitoring and assessment"
        actions={<div className="flex gap-2"><Button variant="outline" size="sm" onClick={() => assess.mutate()} disabled={assess.isPending}><Play className="mr-2 h-4 w-4" />{assess.isPending ? "Assessing..." : "Run Assessment"}</Button><Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Frameworks" value={fwList.length} icon={ShieldCheck} />
        <KpiCard title="Compliance Score" value={`${Number(comp.compliance_score ?? 0).toFixed(0)}%`} icon={CheckCircle2} />
        <KpiCard title="Gaps" value={gapList.length} icon={AlertTriangle} trend={gapList.length > 0 ? "up" : "flat"} />
        <KpiCard title="Open Findings" value={comp.open_findings ?? 0} icon={FileText} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Framework Cards */}
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Frameworks ({fwList.length})</CardTitle></CardHeader>
          <CardContent>
            <div className="space-y-3">
              {fwList.map((fw: Record<string, unknown>, i: number) => {
                const pct = Number(fw.total_controls ?? 1) > 0 ? Math.round((Number(fw.automated_controls ?? 0) / Number(fw.total_controls ?? 1)) * 100) : 0;
                return (
                  <div key={i} className="space-y-2 rounded-lg border border-border/50 p-3">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm">{String(fw.framework)}</span>
                      <Badge variant={fw.enabled ? "default" : "outline"}>{fw.enabled ? "Active" : "Disabled"}</Badge>
                    </div>
                    <div className="flex justify-between text-xs text-muted-foreground">
                      <span>{fw.automated_controls}/{fw.total_controls} automated</span>
                      <span>{pct}%</span>
                    </div>
                    <Progress value={pct} className="h-1.5" />
                  </div>
                );
              })}
              {fwList.length === 0 && <p className="text-sm text-muted-foreground text-center py-4">No frameworks configured.</p>}
            </div>
          </CardContent>
        </Card>

        {/* Chart */}
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Control Coverage</CardTitle></CardHeader>
          <CardContent>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="name" tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                  <YAxis tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                  <Bar dataKey="total" fill="#374151" name="Total Controls" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="automated" fill="#20808D" name="Automated" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : <p className="text-center text-muted-foreground py-8 text-sm">No framework data</p>}
          </CardContent>
        </Card>
      </div>

      {/* Gaps */}
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Compliance Gaps ({gapList.length})</CardTitle></CardHeader>
        <CardContent>
          <div className="space-y-2">
            {gapList.slice(0, 15).map((g: Record<string, unknown>, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2"><span className="font-mono text-xs text-primary">{String(g.control_id)}</span><span className="font-medium text-sm">{String(g.title)}</span></div>
                  <p className="text-xs text-muted-foreground">{String(g.framework ?? "")} · {String(g.category ?? "")}</p>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={g.status === "not_satisfied" ? "destructive" : "outline"} className="capitalize text-[10px]">{String(g.status ?? "").replace(/_/g, " ")}</Badge>
                  <Badge variant="outline" className="text-[10px]">{String(g.gap_type ?? "").replace(/_/g, " ")}</Badge>
                </div>
              </div>
            ))}
            {gapList.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">No compliance gaps detected. Run an assessment to check.</p>}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
