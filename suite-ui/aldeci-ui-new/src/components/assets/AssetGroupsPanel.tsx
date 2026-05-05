import { useEffect, useState } from "react";
import { Layers } from "lucide-react";
import { assetGroupsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface AssetGroup {
  group_id: string;
  group_name: string;
  group_type: string;
  criticality: string;
  description: string;
  owner: string;
  member_count?: number;
}

interface GroupStats {
  total_groups?: number;
  total_members?: number;
  by_criticality?: Record<string, number>;
}

const CRIT_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/15 text-green-400 border-green-500/30",
};

export function AssetGroupsPanel() {
  const [groups, setGroups] = useState<AssetGroup[]>([]);
  const [stats, setStats] = useState<GroupStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      assetGroupsApi.list().catch(() => ({ data: [] })),
      assetGroupsApi.stats().catch(() => ({ data: {} })),
    ]).then(([groupsRes, statsRes]) => {
      if (cancelled) return;
      const raw = groupsRes.data;
      setGroups(Array.isArray(raw) ? raw : (raw?.groups ?? raw?.items ?? []));
      setStats(statsRes.data ?? {});
    }).catch(e => {
      if (!cancelled) setError(e?.message ?? "Failed to load groups");
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
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
    return <EmptyState icon={Layers} title="Error loading groups" description={error} />;
  }

  if (groups.length === 0) {
    return (
      <EmptyState
        icon={Layers}
        title="No asset groups"
        description="Create a group to organize assets by function, criticality, or ownership."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Groups</p>
          <p className="text-2xl font-bold">{stats.total_groups ?? groups.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Members</p>
          <p className="text-2xl font-bold">{stats.total_members ?? "—"}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Critical Groups</p>
          <p className="text-2xl font-bold text-red-400">
            {stats.by_criticality?.critical ?? groups.filter(g => g.criticality === "critical").length}
          </p>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Group</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Owner</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Criticality</th>
              <th className="text-right px-4 py-2 font-medium text-muted-foreground">Members</th>
            </tr>
          </thead>
          <tbody>
            {groups.map((g, i) => (
              <tr key={g.group_id ?? i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                <td className="px-4 py-2.5 font-medium">{g.group_name}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{g.group_type}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{g.owner || "—"}</td>
                <td className="px-4 py-2.5">
                  <Badge className={`text-xs ${CRIT_COLOR[g.criticality] ?? "bg-muted/30"}`}>
                    {g.criticality}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 text-right">{g.member_count ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
