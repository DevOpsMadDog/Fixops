/**
 * PipelineBOMPanel — tab "pipeline-bom" in SBOMProvenanceHub
 * Calls GET /api/v1/pbom/stats?org_id=default
 */
import { useEffect, useState } from "react";
import { Workflow, GitBranch, Package, Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { EmptyState } from "@/components/shared/EmptyState";
import { pbomApi } from "@/lib/api";

interface PBOMStats {
  total_runs?: number;
  runs_by_status?: Record<string, number>;
  total_steps?: number;
  total_artifacts?: number;
  total_deployments?: number;
  ci_providers?: Record<string, number>;
  artifact_types?: Record<string, number>;
  avg_steps_per_run?: number;
}

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
}

function StatCard({ label, value, icon: Icon, color }: StatCardProps) {
  return (
    <Card className="bg-card/60 border-border/50">
      <CardContent className="pt-4 pb-3">
        <div className="flex items-center gap-3">
          <div className={`rounded-lg p-2 ${color}`}>
            <Icon className="h-4 w-4" />
          </div>
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-xl font-semibold tabular-nums">{value}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function BreakdownTable({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) return null;
  const total = entries.reduce((s, [, v]) => s + v, 0);
  return (
    <Card className="bg-card/60 border-border/50">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {entries.map(([key, count]) => (
          <div key={key} className="flex items-center gap-2 text-xs">
            <span className="w-28 truncate text-muted-foreground capitalize">{key}</span>
            <div className="flex-1 h-1.5 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full rounded-full bg-indigo-500"
                style={{ width: `${Math.round((count / total) * 100)}%` }}
              />
            </div>
            <span className="w-8 text-right tabular-nums">{count}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export function PipelineBOMPanel() {
  const [stats, setStats] = useState<PBOMStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    pbomApi
      .stats()
      .then((res) => setStats(res.data ?? {}))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-24 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-4 rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
        {error}
      </div>
    );
  }

  if (!stats || stats.total_runs === 0) {
    return (
      <EmptyState
        icon={Workflow}
        title="No pipeline runs recorded"
        description="Send a POST /api/v1/pbom/run/start from your CI to track pipeline BOMs."
      />
    );
  }

  return (
    <div className="mt-4 space-y-4">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Runs" value={stats.total_runs ?? 0} icon={Activity} color="bg-indigo-500/20 text-indigo-400" />
        <StatCard label="Steps Recorded" value={stats.total_steps ?? 0} icon={GitBranch} color="bg-sky-500/20 text-sky-400" />
        <StatCard label="Artifacts" value={stats.total_artifacts ?? 0} icon={Package} color="bg-green-500/20 text-green-400" />
        <StatCard label="Deployments" value={stats.total_deployments ?? 0} icon={Workflow} color="bg-amber-500/20 text-amber-400" />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {stats.runs_by_status && Object.keys(stats.runs_by_status).length > 0 && (
          <BreakdownTable title="Runs by Status" data={stats.runs_by_status} />
        )}
        {stats.ci_providers && Object.keys(stats.ci_providers).length > 0 && (
          <BreakdownTable title="CI Providers" data={stats.ci_providers} />
        )}
        {stats.artifact_types && Object.keys(stats.artifact_types).length > 0 && (
          <BreakdownTable title="Artifact Types" data={stats.artifact_types} />
        )}
      </div>
    </div>
  );
}
