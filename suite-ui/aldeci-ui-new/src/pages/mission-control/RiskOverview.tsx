import { useCallback } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Shield, AlertTriangle, TrendingUp, RefreshCw, Crosshair } from "lucide-react";
import { useDashboardOverview, useDashboardTopRisks, useDashboardTrends } from "@/hooks/use-api";

const SEV_COLORS: Record<string, string> = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

export default function RiskOverview() {
  const overview = useDashboardOverview();
  const topRisks = useDashboardTopRisks();
  const trends = useDashboardTrends();
  const refetch = useCallback(() => { overview.refetch(); topRisks.refetch(); trends.refetch(); }, [overview, topRisks, trends]);

  if (overview.isLoading) return <PageSkeleton />;
  if (overview.isError) return <ErrorState onRetry={refetch} />;

  const ov = overview.data ?? {};
  const risks = topRisks.data?.risks ?? [];
  const sevTotals = trends.data?.severity_totals ?? {};
  const sevData = Object.entries(sevTotals).map(([k, v]) => ({ name: k.charAt(0).toUpperCase() + k.slice(1), count: Number(v), fill: SEV_COLORS[k] ?? "#6b7280" }));

  const cols = [
    { key: "title", header: "Risk", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium truncate">{String(r.title)}</p><p className="text-xs text-muted-foreground">{String(r.source ?? "")} · CWE: {(r.metadata as Record<string, unknown>)?.cwe_id ?? "N/A"}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
    { key: "epss_score", header: "EPSS", render: (r: Record<string, unknown>) => <span className="font-mono">{r.epss_score != null ? (Number(r.epss_score) * 100).toFixed(0) + "%" : "—"}</span> },
    { key: "exploitable", header: "Exploitable", render: (r: Record<string, unknown>) => r.exploitable ? <Badge variant="destructive">Yes</Badge> : <Badge variant="outline">No</Badge> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Risk Overview" description="Comprehensive risk landscape analysis" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Total Risks" value={ov.total_findings ?? 0} icon={Shield} />
        <KpiCard title="Critical" value={ov.critical_findings ?? 0} icon={AlertTriangle} trend="up" />
        <KpiCard title="Exploitable" value={risks.filter((r: Record<string, unknown>) => r.exploitable).length} icon={Crosshair} />
        <KpiCard title="Open" value={ov.open_findings ?? 0} icon={TrendingUp} />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle className="text-sm font-medium">Risk Distribution</CardTitle></CardHeader>
          <CardContent>
            <DataTable columns={cols} data={risks} emptyMessage="No risks found. Run scans to populate." />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-sm font-medium">Severity Breakdown</CardTitle></CardHeader>
          <CardContent>{sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={sevData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                <YAxis tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>{sevData.map((e, i) => <Cell key={i} fill={e.fill} />)}</Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : <p className="text-center text-muted-foreground py-8 text-sm">No data</p>}</CardContent>
        </Card>
      </div>
    </div>
  );
}
