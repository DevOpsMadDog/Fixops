import { useEffect, useState } from "react";
import { Camera } from "lucide-react";
import { agentlessSnapshotApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface Snapshot {
  id: string;
  snapshot_id?: string;
  provider?: string;
  account_id?: string;
  scan_status?: string;
  findings_count?: number;
  created_at?: string;
  scanned_at?: string;
}

interface SnapshotStats {
  total_snapshots?: number;
  by_status?: Record<string, number>;
  by_provider?: Record<string, number>;
  total_findings?: number;
  critical_findings?: number;
  high_findings?: number;
}

const STATUS_COLOR: Record<string, string> = {
  completed: "bg-green-500/15 text-green-400 border-green-500/30",
  scanning: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  queued: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  failed: "bg-red-500/15 text-red-400 border-red-500/30",
  pending: "bg-muted/30 text-muted-foreground",
};

export function AgentlessSnapshotPanel() {
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [stats, setStats] = useState<SnapshotStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      agentlessSnapshotApi.listSnapshots().catch(() => ({ data: [] })),
      agentlessSnapshotApi.stats().catch(() => ({ data: {} })),
    ])
      .then(([snapRes, statsRes]) => {
        if (cancelled) return;
        const raw = snapRes.data;
        setSnapshots(Array.isArray(raw) ? raw : (raw?.snapshots ?? raw?.items ?? []));
        setStats(statsRes.data ?? {});
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message ?? "Failed to load snapshot data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="space-y-2 animate-pulse">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-12 rounded-lg bg-muted/50" />
        ))}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={Camera} title="Error loading snapshots" description={error} />;
  }

  if (snapshots.length === 0) {
    return (
      <EmptyState
        icon={Camera}
        title="No agentless snapshots"
        description="Enqueue cloud accounts to discover and scan workload snapshots without installing agents."
      />
    );
  }

  const byStatus = stats.by_status ?? {};

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Snapshots</p>
          <p className="text-2xl font-bold">{stats.total_snapshots ?? snapshots.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Completed</p>
          <p className="text-2xl font-bold text-green-400">
            {byStatus.completed ?? snapshots.filter((s) => s.scan_status === "completed").length}
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Findings</p>
          <p className="text-2xl font-bold text-orange-400">{stats.total_findings ?? "—"}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Critical</p>
          <p className="text-2xl font-bold text-red-400">{stats.critical_findings ?? "—"}</p>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="px-4 py-2 bg-muted/30 border-b border-border text-xs font-medium text-muted-foreground">
          Snapshots (top {Math.min(snapshots.length, 30)})
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/10">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Snapshot ID</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Provider</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Account</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Findings</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Scanned</th>
            </tr>
          </thead>
          <tbody>
            {snapshots.slice(0, 30).map((s, i) => (
              <tr
                key={s.id ?? i}
                className="border-b border-border/50 hover:bg-muted/20 transition-colors"
              >
                <td className="px-4 py-2.5 font-mono text-xs">{s.snapshot_id ?? s.id}</td>
                <td className="px-4 py-2.5 text-muted-foreground uppercase text-xs">{s.provider ?? "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground text-xs font-mono">{s.account_id ?? "—"}</td>
                <td className="px-4 py-2.5">
                  {s.scan_status ? (
                    <Badge className={`text-xs ${STATUS_COLOR[s.scan_status] ?? "bg-muted/30"}`}>
                      {s.scan_status}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="px-4 py-2.5 tabular-nums">{s.findings_count ?? "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground text-xs">
                  {s.scanned_at ? new Date(s.scanned_at).toLocaleDateString() : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
