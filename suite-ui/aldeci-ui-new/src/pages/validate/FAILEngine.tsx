import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Zap, Shield, AlertTriangle, Play, RefreshCw, Target, Clock } from "lucide-react";
import { useFailScenarios, useFailDrills, useFailReadiness, useInjectFail } from "@/hooks/use-api";
import { toast } from "sonner";

export default function FAILEngine() {
  const scenarios = useFailScenarios();
  const drills = useFailDrills();
  const readiness = useFailReadiness();
  const inject = useInjectFail();
  const refetch = useCallback(() => { scenarios.refetch(); drills.refetch(); readiness.refetch(); }, [scenarios, drills, readiness]);

  if (scenarios.isLoading) return <PageSkeleton />;
  if (scenarios.isError) return <ErrorState onRetry={refetch} />;

  const scenarioData = scenarios.data ?? {};
  const scenarioList = scenarioData.scenarios ?? [];
  const drillList = drills.data?.drills ?? [];

  const handleInject = (scenarioId: string) => {
    inject.mutate({ scenario_id: scenarioId, org_id: "default", target_app: "fixops-target-app" });
  };

  const scenarioCols = [
    { key: "name", header: "Scenario", render: (r: Record<string, unknown>) => (
      <div className="max-w-sm">
        <p className="font-medium">{String(r.name)}</p>
        <p className="text-xs text-muted-foreground truncate">{String(r.description ?? "").slice(0, 100)}</p>
      </div>
    )},
    { key: "severity", header: "Severity", render: (r: Record<string, unknown>) => <Badge variant={r.severity === "critical" ? "destructive" : "outline"} className="capitalize">{String(r.severity)}</Badge> },
    { key: "cvss_score", header: "CVSS", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.cvss_score ?? 0).toFixed(1)}</span> },
    { key: "expected_detection_minutes", header: "Detection SLA", render: (r: Record<string, unknown>) => <span className="text-sm">{r.expected_detection_minutes ?? "—"}m</span> },
    { key: "tags", header: "Tags", render: (r: Record<string, unknown>) => <div className="flex flex-wrap gap-1">{((r.tags as string[]) ?? []).slice(0, 3).map((t: string) => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}</div> },
    { key: "actions", header: "", render: (r: Record<string, unknown>) => <Button size="sm" variant="outline" onClick={() => handleInject(String(r.scenario_id))} disabled={inject.isPending}><Play className="mr-1 h-3 w-3" />Inject</Button> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="FAIL Engine" description="Focused Attack & Incident Learning — chaos engineering for security"
        badge={`${scenarioData.total ?? 0} SCENARIOS`}
        actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Scenarios" value={scenarioData.total ?? 0} icon={Zap} />
        <KpiCard title="Built-in" value={scenarioData.builtin_count ?? 0} icon={Shield} />
        <KpiCard title="Custom" value={scenarioData.custom_count ?? 0} icon={Target} />
        <KpiCard title="Drills Run" value={drillList.length} icon={Clock} />
      </div>

      <Tabs defaultValue="scenarios">
        <TabsList><TabsTrigger value="scenarios">Scenarios ({scenarioList.length})</TabsTrigger><TabsTrigger value="drills">Drills ({drillList.length})</TabsTrigger></TabsList>
        <TabsContent value="scenarios">
          <Card><CardContent className="pt-6"><DataTable columns={scenarioCols} data={scenarioList} emptyMessage="No FAIL scenarios available." /></CardContent></Card>
        </TabsContent>
        <TabsContent value="drills">
          <Card><CardContent className="pt-6">
            {drillList.length > 0 ? <DataTable columns={[
              { key: "id", header: "Drill", render: (r: Record<string, unknown>) => <span className="font-mono text-xs">{String(r.drill_id ?? r.id ?? "").slice(0, 12)}</span> },
              { key: "scenario", header: "Scenario", render: (r: Record<string, unknown>) => <span className="text-sm">{String(r.scenario_id ?? r.scenario ?? "")}</span> },
              { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status ?? "")}</Badge> },
            ]} data={drillList} /> : <p className="text-sm text-muted-foreground text-center py-8">No drills executed yet. Inject a scenario to start a drill.</p>}
          </CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
