import { useEffect, useState } from "react";
import { Database } from "lucide-react";
import { cmdbApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface CI {
  ci_id: string;
  name: string;
  ci_type: string;
  status: string;
  environment: string;
  owner: string;
  criticality: string;
  ip_address?: string;
  os?: string;
}

interface ChangeRecord {
  change_id: string;
  ci_id: string;
  change_type: string;
  description: string;
  changed_by: string;
  change_date?: string;
}

interface CMDBStats {
  total_cis?: number;
  by_type?: Record<string, number>;
  by_environment?: Record<string, number>;
  by_status?: Record<string, number>;
}

const STATUS_COLOR: Record<string, string> = {
  active: "bg-green-500/15 text-green-400 border-green-500/30",
  decommissioned: "bg-red-500/15 text-red-400 border-red-500/30",
  maintenance: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const ENV_COLOR: Record<string, string> = {
  prod: "bg-red-500/15 text-red-400",
  staging: "bg-yellow-500/15 text-yellow-400",
  dev: "bg-blue-500/15 text-blue-400",
  dr: "bg-purple-500/15 text-purple-400",
};

export function CMDBPanel() {
  const [cis, setCIs] = useState<CI[]>([]);
  const [changes, setChanges] = useState<ChangeRecord[]>([]);
  const [stats, setStats] = useState<CMDBStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      cmdbApi.listCIs().catch(() => ({ data: [] })),
      cmdbApi.listChanges().catch(() => ({ data: [] })),
      cmdbApi.stats().catch(() => ({ data: {} })),
    ]).then(([cisRes, changesRes, statsRes]) => {
      if (cancelled) return;
      const rawCIs = cisRes.data;
      const rawChanges = changesRes.data;
      setCIs(Array.isArray(rawCIs) ? rawCIs : (rawCIs?.cis ?? rawCIs?.items ?? []));
      setChanges(Array.isArray(rawChanges) ? rawChanges : (rawChanges?.changes ?? rawChanges?.items ?? []));
      setStats(statsRes.data ?? {});
    }).catch(e => {
      if (!cancelled) setError(e?.message ?? "Failed to load CMDB data");
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="space-y-2 animate-pulse">
        {[...Array(6)].map((_, i) => <div key={i} className="h-12 rounded-lg bg-muted/50" />)}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={Database} title="Error loading CMDB" description={error} />;
  }

  if (cis.length === 0) {
    return (
      <EmptyState
        icon={Database}
        title="No configuration items"
        description="Register your servers, VMs, containers, and cloud resources to build the CMDB."
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total CIs</p>
          <p className="text-2xl font-bold">{stats.total_cis ?? cis.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Active</p>
          <p className="text-2xl font-bold text-green-400">
            {stats.by_status?.active ?? cis.filter(c => c.status === "active").length}
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Recent Changes</p>
          <p className="text-2xl font-bold">{changes.length}</p>
        </div>
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="px-4 py-2 bg-muted/30 border-b border-border text-xs font-medium text-muted-foreground">
          Configuration Items
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/10">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Env</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Owner</th>
            </tr>
          </thead>
          <tbody>
            {cis.slice(0, 30).map((ci, i) => (
              <tr key={ci.ci_id ?? i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                <td className="px-4 py-2.5 font-medium">{ci.name}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{ci.ci_type}</td>
                <td className="px-4 py-2.5">
                  <span className={`text-xs px-1.5 py-0.5 rounded ${ENV_COLOR[ci.environment] ?? "bg-muted/30"}`}>
                    {ci.environment}
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  <Badge className={`text-xs ${STATUS_COLOR[ci.status] ?? "bg-muted/30"}`}>
                    {ci.status}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">{ci.owner || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {changes.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/30 border-b border-border text-xs font-medium text-muted-foreground">
            Recent Changes
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10">
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">CI</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Change Type</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Description</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">By</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Date</th>
              </tr>
            </thead>
            <tbody>
              {changes.slice(0, 10).map((ch, i) => (
                <tr key={ch.change_id ?? i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs">{ch.ci_id}</td>
                  <td className="px-4 py-2.5">{ch.change_type}</td>
                  <td className="px-4 py-2.5 text-muted-foreground max-w-xs truncate">{ch.description || "—"}</td>
                  <td className="px-4 py-2.5 text-muted-foreground">{ch.changed_by || "—"}</td>
                  <td className="px-4 py-2.5 text-muted-foreground text-xs">
                    {ch.change_date ? new Date(ch.change_date).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
