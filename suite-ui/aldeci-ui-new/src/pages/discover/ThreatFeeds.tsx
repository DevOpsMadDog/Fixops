import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Shield, AlertTriangle, RefreshCw, Activity, Layers, Cloud, Container, Box, GitBranch, Radio, Globe } from "lucide-react";
import { useThreatFeeds, useThreatTrending } from "@/hooks/use-api";

export default function ThreatFeeds() {
  const feeds = useThreatFeeds();
  const trending = useThreatTrending();
  const refetch = useCallback(() => { feeds.refetch(); trending.refetch(); }, [feeds, trending]);
  if (feeds.isLoading) return <PageSkeleton />;
  if (feeds.isError) return <ErrorState onRetry={refetch} />;
  const feedItems = Array.isArray(feeds.data) ? feeds.data : feeds.data?.feeds ?? [];
  const trendingItems = Array.isArray(trending.data) ? trending.data : trending.data?.trending ?? [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Threat Feeds" description="External threat intelligence aggregation" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Feeds" value={feedItems.length} icon={Globe} /><KpiCard title="Trending" value={trendingItems.length} icon={Radio} /><KpiCard title="Active" value={feedItems.length} icon={Activity} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">Feed Sources</CardTitle></CardHeader><CardContent>
        {feedItems.length > 0 ? <div className="space-y-2">{feedItems.map((f: Record<string, unknown>, i: number) => <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50"><span className="font-medium text-sm">{String(f.name ?? f.id ?? "Feed " + i)}</span><Badge variant="outline">{String(f.type ?? "intel")}</Badge></div>)}</div>
        : <p className="text-sm text-muted-foreground text-center py-8">No threat feeds configured. Connect STIX/TAXII feeds or CVE sources.</p>}
      </CardContent></Card>
    </div>
  );
}
