import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Server, Activity, Database, Clock, RefreshCw, Cpu } from "lucide-react";
import { useSystemHealth, useSystemMetrics } from "@/hooks/use-api";

export default function SystemHealth() {
  const health = useSystemHealth();
  const metrics = useSystemMetrics();
  const refetch = useCallback(() => { health.refetch(); metrics.refetch(); }, [health, metrics]);
  if (health.isLoading) return <PageSkeleton />;
  if (health.isError) return <ErrorState onRetry={refetch} />;

  const h = health.data ?? {};
  const m = metrics.data ?? {};
  const subsystems = h.subsystems ?? {};
  const dbs = subsystems.databases?.details ?? {};

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="System Health" description="Real-time platform health monitoring" badge={String(h.status ?? "unknown").toUpperCase()}
        actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Status" value={String(h.status ?? "unknown").toUpperCase()} icon={Server} />
        <KpiCard title="Uptime" value={`${Math.round(Number(h.uptime_seconds ?? 0) / 3600)}h`} icon={Clock} />
        <KpiCard title="Version" value={String(h.version ?? "—")} icon={Activity} />
        <KpiCard title="Mode" value={String(subsystems.configuration?.mode ?? "—").toUpperCase()} icon={Cpu} />
      </div>

      {/* Subsystems */}
      <Card><CardHeader><CardTitle className="text-sm font-medium">Subsystems</CardTitle></CardHeader><CardContent>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Object.entries(subsystems).map(([name, sub]) => {
            const s = sub as Record<string, unknown>;
            return (
              <div key={name} className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                <div><p className="font-medium text-sm capitalize">{name}</p>{s.version && <p className="text-xs text-muted-foreground">v{String(s.version)}</p>}</div>
                <Badge variant={s.status === "healthy" ? "default" : "destructive"} className="capitalize">{String(s.status ?? "unknown")}</Badge>
              </div>
            );
          })}
        </div>
      </CardContent></Card>

      {/* Databases */}
      {Object.keys(dbs).length > 0 && (
        <Card><CardHeader><CardTitle className="text-sm font-medium">Databases ({Object.keys(dbs).length})</CardTitle></CardHeader><CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Object.entries(dbs).map(([name, db]) => {
              const d = db as Record<string, unknown>;
              return (
                <div key={name} className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                  <div><p className="font-medium text-sm">{name}</p><p className="text-xs text-muted-foreground">{d.size_mb ? `${Number(d.size_mb).toFixed(2)}MB` : "—"}</p></div>
                  <Badge variant={d.status === "healthy" ? "default" : "destructive"} className="capitalize">{String(d.status ?? "unknown")}</Badge>
                </div>
              );
            })}
          </div>
        </CardContent></Card>
      )}

      {/* Metrics */}
      <Card><CardHeader><CardTitle className="text-sm font-medium">System Metrics</CardTitle></CardHeader><CardContent>
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 text-sm">
          <div className="space-y-1"><span className="text-muted-foreground">PID</span><p className="font-mono">{(m.process as Record<string, unknown>)?.pid ?? "—"}</p></div>
          <div className="space-y-1"><span className="text-muted-foreground">CPU Time</span><p className="font-mono">{Number((m.process as Record<string, unknown>)?.user_cpu_seconds ?? 0).toFixed(1)}s</p></div>
          <div className="space-y-1"><span className="text-muted-foreground">DB Size</span><p className="font-mono">{Number((m.databases as Record<string, unknown>)?.total_size_mb ?? 0).toFixed(1)}MB</p></div>
          <div className="space-y-1"><span className="text-muted-foreground">Python</span><p className="font-mono">{String(m.python_version ?? "—")}</p></div>
        </div>
      </CardContent></Card>
    </div>
  );
}
