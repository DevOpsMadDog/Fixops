/**
 * DeceptionAnalyticsPanel — wires GET /api/v1/deception-analytics/stats
 * and GET /api/v1/deception-analytics/assets → stat cards + asset table.
 * Used by DeceptionHub "analytics" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, BarChart2, Eye, Shield, Crosshair } from "lucide-react";
import { deceptionAnalyticsApi } from "@/lib/api";

interface DeceptionStats {
  total_assets: number;
  active_assets: number;
  total_interactions: number;
  unique_attacker_ips: number;
  total_campaigns: number;
  active_campaigns: number;
  hottest_asset?: string | null;
}

interface DeceptionAsset {
  id: string;
  asset_name: string;
  asset_type: string;
  location: string;
  decoy_category: string;
  active: boolean;
  interaction_count?: number;
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

const TYPE_BADGE: Record<string, string> = {
  honeypot: "bg-purple-500/15 text-purple-400",
  honeytoken: "bg-amber-500/15 text-amber-400",
  canary_file: "bg-sky-500/15 text-sky-400",
  canary_cred: "bg-red-500/15 text-red-400",
  fake_service: "bg-indigo-500/15 text-indigo-400",
  honey_user: "bg-pink-500/15 text-pink-400",
  lure_document: "bg-teal-500/15 text-teal-400",
  breadcrumb: "bg-orange-500/15 text-orange-400",
};

export function DeceptionAnalyticsPanel() {
  const [stats, setStats] = useState<DeceptionStats | null>(null);
  const [assets, setAssets] = useState<DeceptionAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      deceptionAnalyticsApi.stats("default"),
      deceptionAnalyticsApi.assets("default"),
    ])
      .then(([statsRes, assetsRes]) => {
        if (cancelled) return;
        setStats(statsRes.data as DeceptionStats);
        const raw = assetsRes.data;
        setAssets(
          Array.isArray(raw) ? raw : (raw as { assets?: DeceptionAsset[] }).assets ?? [],
        );
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load deception analytics");
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
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />
          ))}
        </div>
        <div className="h-48 rounded-xl border border-border/40 bg-muted/30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (!stats || stats.total_assets === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Eye className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No deception assets registered yet</p>
        <p className="text-xs opacity-70">
          Register a honeypot, honeytoken, or canary to start tracking attacker interactions.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Total Assets"
          value={stats.total_assets}
          icon={Shield}
          accent="text-indigo-400"
        />
        <StatCard
          label="Active Assets"
          value={stats.active_assets}
          icon={Eye}
          accent="text-green-400"
        />
        <StatCard
          label="Interactions"
          value={stats.total_interactions}
          icon={Crosshair}
          accent="text-red-400"
        />
        <StatCard
          label="Unique Attackers"
          value={stats.unique_attacker_ips}
          icon={BarChart2}
          accent="text-amber-400"
        />
      </div>

      {/* Asset table */}
      {assets.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Deception Assets
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/30 text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Name</th>
                  <th className="px-4 py-2 text-left font-medium">Type</th>
                  <th className="px-4 py-2 text-left font-medium">Category</th>
                  <th className="px-4 py-2 text-left font-medium">Location</th>
                  <th className="px-4 py-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {assets.slice(0, 50).map((a) => (
                  <tr
                    key={a.id}
                    className="border-b border-border/20 hover:bg-muted/20 transition-colors"
                  >
                    <td className="px-4 py-2 font-medium text-foreground truncate max-w-[180px]">
                      {a.asset_name}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${TYPE_BADGE[a.asset_type] ?? "bg-muted text-muted-foreground"}`}
                      >
                        {a.asset_type.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-muted-foreground text-xs">{a.decoy_category}</td>
                    <td className="px-4 py-2 text-muted-foreground font-mono text-xs truncate max-w-[140px]">
                      {a.location || "—"}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${a.active ? "bg-green-500/15 text-green-400" : "bg-muted text-muted-foreground"}`}
                      >
                        {a.active ? "Active" : "Inactive"}
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
