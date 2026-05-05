import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";
import { assetCriticalityApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface CriticalityAsset {
  asset_id: string;
  asset_name: string;
  asset_type: string;
  owner: string;
  criticality_score?: number;
  tier?: string;
  business_function?: string;
  data_classification?: string;
}

interface CriticalitySummary {
  total_assets?: number;
  tier_distribution?: Record<string, number>;
  avg_score?: number;
  critical_count?: number;
}

const TIER_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/15 text-green-400 border-green-500/30",
};

function scoreBar(score: number) {
  const pct = Math.min(100, Math.max(0, Math.round(score)));
  const color = pct >= 80 ? "bg-red-500" : pct >= 60 ? "bg-orange-500" : pct >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/50">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums w-7 text-right">{pct}</span>
    </div>
  );
}

export function AssetCriticalityPanel() {
  const [assets, setAssets] = useState<CriticalityAsset[]>([]);
  const [summary, setSummary] = useState<CriticalitySummary>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      assetCriticalityApi.list().catch(() => ({ data: [] })),
      assetCriticalityApi.summary().catch(() => ({ data: {} })),
    ]).then(([assetsRes, summaryRes]) => {
      if (cancelled) return;
      const raw = assetsRes.data;
      setAssets(Array.isArray(raw) ? raw : (raw?.assets ?? raw?.items ?? []));
      setSummary(summaryRes.data ?? {});
    }).catch(e => {
      if (!cancelled) setError(e?.message ?? "Failed to load criticality data");
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="space-y-2 animate-pulse">
        {[...Array(5)].map((_, i) => <div key={i} className="h-12 rounded-lg bg-muted/50" />)}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={AlertTriangle} title="Error loading criticality" description={error} />;
  }

  if (assets.length === 0) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="No criticality data"
        description="Register assets and score their criticality factors to see tier distribution."
      />
    );
  }

  const tierDist = summary.tier_distribution ?? {};
  const tiers = ["critical", "high", "medium", "low"];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-4 gap-3">
        {tiers.map(tier => (
          <div key={tier} className="rounded-lg border border-border bg-card p-3">
            <p className="text-xs text-muted-foreground capitalize">{tier}</p>
            <p className={`text-2xl font-bold ${TIER_COLOR[tier]?.split(" ")[1] ?? ""}`}>
              {tierDist[tier] ?? assets.filter(a => a.tier === tier).length}
            </p>
          </div>
        ))}
      </div>

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Asset</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Tier</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground w-40">Score</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Business Fn</th>
            </tr>
          </thead>
          <tbody>
            {assets.slice(0, 50).map((a, i) => (
              <tr key={a.asset_id ?? i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                <td className="px-4 py-2.5 font-medium">{a.asset_name}</td>
                <td className="px-4 py-2.5 text-muted-foreground">{a.asset_type}</td>
                <td className="px-4 py-2.5">
                  {a.tier && (
                    <Badge className={`text-xs ${TIER_COLOR[a.tier] ?? "bg-muted/30"}`}>
                      {a.tier}
                    </Badge>
                  )}
                </td>
                <td className="px-4 py-2.5 w-40">
                  {a.criticality_score != null ? scoreBar(a.criticality_score) : <span className="text-muted-foreground">—</span>}
                </td>
                <td className="px-4 py-2.5 text-muted-foreground">{a.business_function || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
