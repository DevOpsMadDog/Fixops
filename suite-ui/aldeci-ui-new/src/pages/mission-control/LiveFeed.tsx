import { useCallback } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Activity, Radio, Server, Clock, RefreshCw, Wifi, Zap } from "lucide-react";
import { useNervePulse, useNerveState, useIntelligenceMap } from "@/hooks/use-api";

export default function LiveFeed() {
  const pulse = useNervePulse();
  const state = useNerveState();
  const intel = useIntelligenceMap();
  const refetch = useCallback(() => { pulse.refetch(); state.refetch(); intel.refetch(); }, [pulse, state, intel]);

  if (pulse.isLoading || state.isLoading) return <PageSkeleton />;
  if (pulse.isError) return <ErrorState onRetry={refetch} />;

  const p = pulse.data ?? {};
  const suites = state.data?.suites ?? [];
  const nodes = intel.data?.nodes ?? [];
  const edges = intel.data?.edges ?? [];

  const pulseLevel = String(p.level ?? "info");
  const pulseColor = pulseLevel === "critical" ? "text-red-400" : pulseLevel === "warning" ? "text-yellow-400" : "text-green-400";

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Live Feed" description="Real-time system events and intelligence flow" badge="STREAMING"
        actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      {/* Pulse Banner */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
        className={`flex items-center gap-4 rounded-xl border p-4 ${pulseLevel === "critical" ? "border-red-500/50 bg-red-500/10" : "border-border/50 bg-card"}`}>
        <div className={`relative`}>
          <Radio className={`h-6 w-6 ${pulseColor}`} />
          <span className={`absolute -top-1 -right-1 h-3 w-3 rounded-full ${pulseLevel === "critical" ? "bg-red-500" : "bg-green-500"} animate-pulse`} />
        </div>
        <div className="flex-1">
          <p className="font-semibold">Threat Pulse: {Number(p.score ?? 0).toFixed(1)} / 10</p>
          <p className="text-sm text-muted-foreground">Level: <span className={`font-medium capitalize ${pulseColor}`}>{pulseLevel}</span> · {p.active_incidents ?? 0} active incidents · {p.pending_decisions ?? 0} pending decisions</p>
        </div>
        <Badge variant={pulseLevel === "critical" ? "destructive" : "default"} className="capitalize">{pulseLevel}</Badge>
      </motion.div>

      {/* Suite Status Grid */}
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Suite Health ({suites.length})</CardTitle></CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {suites.map((s: Record<string, unknown>, i: number) => (
              <motion.div key={String(s.suite)} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                className="flex items-center gap-3 rounded-lg border border-border/50 p-3 hover:bg-muted/30 transition-colors">
                <Server className="h-5 w-5 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm truncate">{String(s.suite)}</p>
                  <p className="text-xs text-muted-foreground">{Number(s.latency_ms ?? 0).toFixed(0)}ms · {s.active_tasks ?? 0} tasks</p>
                </div>
                <div className={`h-2.5 w-2.5 rounded-full ${s.status === "healthy" ? "bg-green-500" : "bg-red-500"}`} />
              </motion.div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Intelligence Map */}
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Intelligence Pipeline ({nodes.length} nodes)</CardTitle></CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {nodes.map((n: Record<string, unknown>) => (
              <div key={String(n.id)} className="rounded-lg border border-border/50 p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <Zap className="h-4 w-4 text-primary" />
                  <span className="font-medium text-sm">{String(n.label)}</span>
                </div>
                <p className="text-xs text-muted-foreground">{String(n.suite)} · {String(n.type)}</p>
                <div className="flex flex-wrap gap-1">
                  {(Array.isArray(n.apis) ? n.apis : []).map((api: string) => (
                    <Badge key={api} variant="outline" className="text-[10px]">{api}</Badge>
                  ))}
                </div>
              </div>
            ))}
          </div>
          {nodes.length === 0 && <p className="text-sm text-muted-foreground text-center py-8">Intelligence map initializing...</p>}
        </CardContent>
      </Card>
    </div>
  );
}
