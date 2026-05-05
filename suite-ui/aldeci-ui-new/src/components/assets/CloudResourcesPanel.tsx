import { useEffect, useState } from "react";
import { Cloud } from "lucide-react";
import { cloudInventoryApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface CloudResource {
  id?: string;
  resource_id: string;
  resource_name?: string;
  provider: string;
  resource_type: string;
  region?: string;
  account_id?: string;
  resource_state?: string;
  compliance_status?: string;
  security_score?: number;
}

interface InventoryStats {
  total_resources?: number;
  by_provider?: Record<string, number>;
  by_type?: Record<string, number>;
  by_state?: Record<string, number>;
  avg_security_score?: number;
}

const PROVIDER_COLOR: Record<string, string> = {
  aws: "bg-orange-500/15 text-orange-400",
  azure: "bg-blue-500/15 text-blue-400",
  gcp: "bg-green-500/15 text-green-400",
  alibaba: "bg-red-500/15 text-red-400",
};

const COMPLIANCE_COLOR: Record<string, string> = {
  compliant: "bg-green-500/15 text-green-400 border-green-500/30",
  non_compliant: "bg-red-500/15 text-red-400 border-red-500/30",
  unknown: "bg-muted/30 text-muted-foreground",
  exempt: "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

export function CloudResourcesPanel() {
  const [resources, setResources] = useState<CloudResource[]>([]);
  const [stats, setStats] = useState<InventoryStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      cloudInventoryApi.listResources().catch(() => ({ data: { resources: [] } })),
      cloudInventoryApi.stats().catch(() => ({ data: {} })),
    ])
      .then(([resRes, statsRes]) => {
        if (cancelled) return;
        const raw = resRes.data;
        setResources(
          Array.isArray(raw) ? raw : (raw?.resources ?? raw?.items ?? [])
        );
        setStats(statsRes.data ?? {});
      })
      .catch((e) => {
        if (!cancelled) setError(e?.message ?? "Failed to load cloud resources");
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
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-12 rounded-lg bg-muted/50" />
        ))}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={Cloud} title="Error loading cloud resources" description={error} />;
  }

  if (resources.length === 0) {
    return (
      <EmptyState
        icon={Cloud}
        title="No cloud resources"
        description="Connect AWS, Azure, or GCP accounts to discover and inventory cloud resources."
      />
    );
  }

  const byProvider = stats.by_provider ?? {};
  const providers = Object.keys(byProvider).length
    ? Object.entries(byProvider)
    : (["aws", "azure", "gcp"] as const).map((p) => [
        p,
        resources.filter((r) => r.provider === p).length,
      ] as [string, number]);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Resources</p>
          <p className="text-2xl font-bold">{stats.total_resources ?? resources.length}</p>
        </div>
        {providers.slice(0, 3).map(([provider, count]) => (
          <div key={provider} className="rounded-lg border border-border bg-card p-3">
            <p className="text-xs text-muted-foreground uppercase">{provider}</p>
            <p className="text-2xl font-bold">{count as number}</p>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <div className="px-4 py-2 bg-muted/30 border-b border-border text-xs font-medium text-muted-foreground">
          Resources (top {Math.min(resources.length, 30)})
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/10">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Provider</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Region</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">State</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Compliance</th>
            </tr>
          </thead>
          <tbody>
            {resources.slice(0, 30).map((r, i) => (
              <tr
                key={r.id ?? r.resource_id ?? i}
                className="border-b border-border/50 hover:bg-muted/20 transition-colors"
              >
                <td className="px-4 py-2.5 font-medium">{r.resource_name || r.resource_id}</td>
                <td className="px-4 py-2.5">
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded uppercase ${
                      PROVIDER_COLOR[r.provider] ?? "bg-muted/30 text-muted-foreground"
                    }`}
                  >
                    {r.provider}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">{r.resource_type}</td>
                <td className="px-4 py-2.5 text-muted-foreground text-xs font-mono">{r.region || "—"}</td>
                <td className="px-4 py-2.5 text-muted-foreground capitalize">{r.resource_state ?? "—"}</td>
                <td className="px-4 py-2.5">
                  {r.compliance_status ? (
                    <Badge
                      className={`text-xs ${
                        COMPLIANCE_COLOR[r.compliance_status] ?? "bg-muted/30 text-muted-foreground"
                      }`}
                    >
                      {r.compliance_status.replace("_", " ")}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
