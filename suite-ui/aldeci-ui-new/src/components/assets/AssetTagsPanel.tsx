import { useEffect, useState } from "react";
import { Tag } from "lucide-react";
import { assetTagsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface AssetTag {
  tag_id: string;
  tag_key: string;
  tag_value: string;
  tag_category: string;
  description: string;
  asset_count?: number;
}

interface TagStats {
  total_tags?: number;
  total_assignments?: number;
  by_category?: Record<string, number>;
}

const CATEGORY_COLOR: Record<string, string> = {
  environment: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  criticality: "bg-red-500/15 text-red-400 border-red-500/30",
  data_classification: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  owner: "bg-green-500/15 text-green-400 border-green-500/30",
  compliance: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  technology: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  location: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  department: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
};

export function AssetTagsPanel() {
  const [tags, setTags] = useState<AssetTag[]>([]);
  const [stats, setStats] = useState<TagStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      assetTagsApi.listTags().catch(() => ({ data: [] })),
      assetTagsApi.stats().catch(() => ({ data: {} })),
    ]).then(([tagsRes, statsRes]) => {
      if (cancelled) return;
      const raw = tagsRes.data;
      setTags(Array.isArray(raw) ? raw : (raw?.tags ?? raw?.items ?? []));
      setStats(statsRes.data ?? {});
    }).catch(e => {
      if (!cancelled) setError(e?.message ?? "Failed to load tags");
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
    return <EmptyState icon={Tag} title="Error loading tags" description={error} />;
  }

  if (tags.length === 0) {
    return (
      <EmptyState
        icon={Tag}
        title="No asset tags"
        description="Create tags to classify assets by environment, owner, compliance scope, and more."
      />
    );
  }

  const byCategory = stats.by_category ?? {};
  const topCategories = Object.entries(byCategory).sort((a, b) => b[1] - a[1]).slice(0, 4);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Tags</p>
          <p className="text-2xl font-bold">{stats.total_tags ?? tags.length}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <p className="text-xs text-muted-foreground">Total Assignments</p>
          <p className="text-2xl font-bold">{stats.total_assignments ?? "—"}</p>
        </div>
      </div>

      {topCategories.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {topCategories.map(([cat, count]) => (
            <Badge key={cat} className={`text-xs ${CATEGORY_COLOR[cat] ?? "bg-muted/30"}`}>
              {cat}: {count}
            </Badge>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Key</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Value</th>
              <th className="text-left px-4 py-2 font-medium text-muted-foreground">Category</th>
              <th className="text-right px-4 py-2 font-medium text-muted-foreground">Assets</th>
            </tr>
          </thead>
          <tbody>
            {tags.map((t, i) => (
              <tr key={t.tag_id ?? i} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                <td className="px-4 py-2.5 font-mono text-xs font-medium">{t.tag_key}</td>
                <td className="px-4 py-2.5">{t.tag_value}</td>
                <td className="px-4 py-2.5">
                  <Badge className={`text-xs ${CATEGORY_COLOR[t.tag_category] ?? "bg-muted/30"}`}>
                    {t.tag_category}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 text-right">{t.asset_count ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
