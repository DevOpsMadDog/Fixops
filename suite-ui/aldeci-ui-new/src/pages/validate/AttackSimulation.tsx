import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Crosshair, Shield, AlertTriangle, RefreshCw, Zap } from "lucide-react";
import { useFailScenarios } from "@/hooks/use-api";

export default function AttackSimulation() {
  const scenarios = useFailScenarios();
  const refetch = useCallback(() => scenarios.refetch(), [scenarios]);
  if (scenarios.isLoading) return <PageSkeleton />;
  if (scenarios.isError) return <ErrorState onRetry={refetch} />;

  const list = scenarios.data?.scenarios ?? [];
  const cols = [
    { key: "name", header: "Attack", render: (r: Record<string, unknown>) => <div className="max-w-sm"><p className="font-medium">{String(r.name)}</p><p className="text-xs text-muted-foreground">{((r.mitre_techniques as string[]) ?? []).join(", ")}</p></div> },
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "mitre_tactics", header: "MITRE Tactics", render: (r: Record<string, unknown>) => <div className="flex flex-wrap gap-1">{((r.mitre_tactics as string[]) ?? []).map((t: string) => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}</div> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Attack Simulation" description="MITRE ATT&CK-mapped attack scenarios" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <KpiCard title="Simulations" value={list.length} icon={Crosshair} />
        <KpiCard title="Critical" value={list.filter((s: Record<string, unknown>) => s.severity === "critical").length} icon={AlertTriangle} />
        <KpiCard title="Techniques" value={[...new Set(list.flatMap((s: Record<string, unknown>) => (s.mitre_techniques as string[]) ?? []))].length} icon={Zap} />
      </div>
      <Card><CardContent className="pt-6"><DataTable columns={cols} data={list} emptyMessage="No attack simulations available." /></CardContent></Card>
    </div>
  );
}
