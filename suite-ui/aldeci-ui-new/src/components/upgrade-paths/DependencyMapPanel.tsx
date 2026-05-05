/**
 * DependencyMapPanel — dep-map tab for UpgradePathsHub.
 * Wired to /api/v1/network-topology: stats, nodes, segments, exposure.
 */

import { useEffect, useState } from "react";
import { Network, RefreshCw, ShieldAlert } from "lucide-react";

import { networkTopologyApi, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

interface TopoStats {
  node_count?: number;
  edge_count?: number;
  segment_count?: number;
  [key: string]: unknown;
}

interface TopoNode {
  id?: string;
  node_id?: string;
  hostname?: string;
  ip?: string;
  node_type?: string;
  criticality?: string;
  os?: string;
  location?: string;
  [key: string]: unknown;
}

interface ExposureItem {
  node_id?: string;
  hostname?: string;
  exposure_type?: string;
  risk?: string;
  [key: string]: unknown;
}

const CRITICALITY_COLOR: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-400 bg-orange-400/10",
  medium: "text-yellow-400 bg-yellow-400/10",
  low: "text-green-500 bg-green-500/10",
};

export function DependencyMapPanel() {
  const orgId = getStoredOrgId();

  const [stats, setStats] = useState<TopoStats | null>(null);
  const [nodes, setNodes] = useState<TopoNode[]>([]);
  const [exposure, setExposure] = useState<ExposureItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.all([
      networkTopologyApi.stats(orgId),
      networkTopologyApi.nodes(orgId),
      networkTopologyApi.exposure(orgId),
    ])
      .then(([statsRes, nodesRes, exposureRes]) => {
        setStats(statsRes.data as TopoStats);
        setNodes(
          Array.isArray(nodesRes.data)
            ? (nodesRes.data as TopoNode[])
            : ((nodesRes.data as { nodes?: TopoNode[] })?.nodes ?? [])
        );
        setExposure(
          Array.isArray(exposureRes.data)
            ? (exposureRes.data as ExposureItem[])
            : []
        );
      })
      .catch((e) =>
        setError(e?.response?.data?.detail ?? e?.message ?? "Failed to load topology")
      )
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, [orgId]);

  if (loading) return <PageSkeleton />;

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Nodes", value: stats?.node_count ?? nodes.length },
          { label: "Edges", value: stats?.edge_count ?? "—" },
          { label: "Segments", value: stats?.segment_count ?? "—" },
        ].map(({ label, value }) => (
          <div key={label} className="rounded-xl border border-border bg-card px-5 py-4 space-y-1">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-2xl font-semibold">{String(value)}</p>
          </div>
        ))}
      </div>

      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Network className="h-4 w-4 text-muted-foreground" />
          Network Nodes
        </h3>
        <button
          onClick={load}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
        >
          <RefreshCw className="h-3 w-3" />
          Refresh
        </button>
      </div>

      {nodes.length === 0 ? (
        <EmptyState
          icon={Network}
          title="No topology data"
          description="Nodes will appear after discovery scans or connectors push topology."
        />
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground">
                <th className="px-4 py-2.5">Hostname / IP</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5">OS</th>
                <th className="px-4 py-2.5">Location</th>
                <th className="px-4 py-2.5">Criticality</th>
              </tr>
            </thead>
            <tbody>
              {nodes.slice(0, 50).map((n, i) => {
                const key = n.id ?? n.node_id ?? String(i);
                const crit = (n.criticality ?? "medium").toLowerCase();
                return (
                  <tr key={key} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="px-4 py-2.5 font-mono text-xs">
                      {n.hostname || n.ip || "—"}
                    </td>
                    <td className="px-4 py-2.5 capitalize">{n.node_type ?? "—"}</td>
                    <td className="px-4 py-2.5">{n.os ?? "—"}</td>
                    <td className="px-4 py-2.5">{n.location ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-medium capitalize ${CRITICALITY_COLOR[crit] ?? "text-muted-foreground bg-muted/40"}`}
                      >
                        {crit}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {nodes.length > 50 && (
            <p className="px-4 py-2 text-xs text-muted-foreground border-t border-border">
              Showing 50 of {nodes.length} nodes
            </p>
          )}
        </div>
      )}

      {/* Exposure */}
      {exposure.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-red-500" />
            External Exposure ({exposure.length})
          </h3>
          <div className="rounded-xl border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/40 text-left text-xs text-muted-foreground">
                  <th className="px-4 py-2.5">Node</th>
                  <th className="px-4 py-2.5">Exposure Type</th>
                  <th className="px-4 py-2.5">Risk</th>
                </tr>
              </thead>
              <tbody>
                {exposure.map((e, i) => (
                  <tr key={e.node_id ?? i} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="px-4 py-2.5 font-mono text-xs">
                      {e.hostname ?? e.node_id ?? "—"}
                    </td>
                    <td className="px-4 py-2.5">{e.exposure_type ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      <span className="rounded-full px-2 py-0.5 text-xs font-medium text-red-400 bg-red-400/10">
                        {e.risk ?? "exposed"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
