import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Globe,
  Lock,
  Network,
  AlertTriangle,
  Search,
  Route,
  ChevronRight,
  RefreshCw,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { useFindings, useKnowledgeGraph } from "@/hooks/use-api";

const EXPOSURE_COLORS = {
  Internet: "#ef4444",
  Internal: "#22c55e",
  "Partially Exposed": "#f59e0b",
} as const;

function ExposureBadge({ exposure }: { exposure: string }) {
  const color = EXPOSURE_COLORS[exposure as keyof typeof EXPOSURE_COLORS] ?? "#6b7280";
  return (
    <Badge variant="outline" style={{ borderColor: color + "66", color }}>
      {exposure}
    </Badge>
  );
}

function RiskScoreBadge({ score }: { score: number }) {
  const color = score >= 8 ? "#ef4444" : score >= 5 ? "#f59e0b" : "#22c55e";
  return (
    <span className="font-semibold tabular-nums" style={{ color }}>
      {score.toFixed(1)}
    </span>
  );
}

function NetworkPathDialog({
  asset,
  paths,
  open,
  onClose,
}: {
  asset: Record<string, unknown> | null;
  paths: Record<string, unknown>[];
  open: boolean;
  onClose: () => void;
}) {
  if (!asset) return null;
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Route className="h-5 w-5 text-primary" />
            Network Paths — {(asset.asset as string) ?? "Unknown Asset"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Asset Type</p>
              <p>{(asset.type as string) ?? "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Exposure</p>
              <ExposureBadge exposure={(asset.exposure as string) ?? "Internal"} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Risk Score</p>
              <RiskScoreBadge score={(asset.risk_score as number) ?? 0} />
            </div>
          </div>
          <div>
            <p className="text-xs text-muted-foreground font-medium mb-3">Attack Paths</p>
            {paths.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No attack paths found for this asset
              </p>
            ) : (
              <div className="space-y-3">
                {paths.slice(0, 5).map((path, i) => (
                  <div key={i} className="bg-muted/30 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 flex-wrap text-xs">
                      {((path.nodes as string[]) ?? ["Internet", (asset.asset as string) ?? "Target"]).map(
                        (node, ni, arr) => (
                          <span key={ni} className="flex items-center gap-1">
                            <span className="px-2 py-0.5 bg-muted rounded font-mono">
                              {node}
                            </span>
                            {ni < arr.length - 1 && (
                              <ChevronRight className="h-3 w-3 text-muted-foreground" />
                            )}
                          </span>
                        )
                      )}
                    </div>
                    <div className="flex items-center gap-4 mt-2 text-[10px] text-muted-foreground">
                      <span>Hops: {(path.hops as number) ?? "—"}</span>
                      {!!path.risk && <span>Risk: {String(path.risk)}</span>}
                      {!!path.protocol && <span>Protocol: {String(path.protocol)}</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Reachability() {
  const findingsQuery = useFindings({ type: "reachability" });
  const graphQuery = useKnowledgeGraph({ type: "reachability" });

  const [search, setSearch] = useState("");
  const [exposureFilter, setExposureFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [selectedAsset, setSelectedAsset] = useState<Record<string, unknown> | null>(null);
  const [pathDialogOpen, setPathDialogOpen] = useState(false);

  const refetchAll = useCallback(() => {
    findingsQuery.refetch();
    graphQuery.refetch();
  }, [findingsQuery, graphQuery]);

  const isLoading = findingsQuery.isLoading || graphQuery.isLoading;
  const isError = findingsQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError)
    return <ErrorState message="Failed to load reachability data" onRetry={refetchAll} />;

  const findings: Record<string, unknown>[] =
    toArray(findingsQuery.data);
  const graphData = graphQuery.data?.data ?? graphQuery.data ?? {};
  const attackPaths: Record<string, unknown>[] =
    (graphData.paths as Record<string, unknown>[]) ?? [];
  const trendData: Record<string, unknown>[] =
    (graphData.trend as Record<string, unknown>[]) ?? [];

  // Derive reachable assets from findings
  const assets = findings.map((f, idx) => ({
    asset: (f.asset as string) ?? (f.title as string) ?? "—",
    type: (f.asset_type as string) ?? (f.type as string) ?? "Host",
    exposure: (f.exposure as string) ?? ((f.severity as string) === "critical" ? "Internet" : "Internal"),
    path_length: (f.path_length as number) ?? 1,
    risk_score: (f.risk_score as number) ?? (f.cvss_score as number) ?? 0,
    id: (f.id as string) ?? `finding-${idx}`,
  }));

  const internetReachable = assets.filter((a) => a.exposure === "Internet").length;
  const internalOnly = assets.filter((a) => a.exposure === "Internal").length;
  const attackSurface = assets.length;
  const avgPathLength =
    assets.length > 0
      ? (assets.reduce((a, c) => a + c.path_length, 0) / assets.length).toFixed(1)
      : "0";

  const filteredAssets = assets.filter((a) => {
    const matchSearch =
      !search ||
      a.asset.toLowerCase().includes(search.toLowerCase()) ||
      a.type.toLowerCase().includes(search.toLowerCase());
    const matchExposure = exposureFilter === "all" || a.exposure === exposureFilter;
    const matchType = typeFilter === "all" || a.type === typeFilter;
    return matchSearch && matchExposure && matchType;
  });

  const assetTypes = [...new Set(assets.map((a) => a.type))];

  const assetPaths = selectedAsset
    ? attackPaths.filter(
        (p) =>
          ((p.target as string) === (selectedAsset.asset as string)) ||
          ((p.asset as string) === (selectedAsset.asset as string))
      )
    : [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Reachability Analysis"
        description="Network exposure mapping — internet-reachable assets, attack surface, and path analysis"
      >
        <Button variant="outline" onClick={refetchAll}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Internet-Reachable"
          value={internetReachable}
          icon={<Globe className="h-4 w-4" />}
          trend="flat"
          trendLabel="exposed assets"
        />
        <KpiCard
          title="Internal Only"
          value={internalOnly}
          icon={<Lock className="h-4 w-4" />}
        />
        <KpiCard
          title="Attack Surface"
          value={attackSurface}
          icon={<AlertTriangle className="h-4 w-4" />}
        />
        <KpiCard
          title="Avg Path Length"
          value={avgPathLength}
          icon={<Network className="h-4 w-4" />}
        />
      </div>

      {/* Attack Surface Trend Chart */}
      {trendData.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Attack Surface Trend</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart
                data={trendData}
                margin={{ top: 4, right: 4, left: -16, bottom: 4 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                />
                <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                <Tooltip
                  contentStyle={{
                    background: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "8px",
                  }}
                />
                <Legend />
                <Area
                  type="monotone"
                  dataKey="internet"
                  name="Internet Reachable"
                  stroke="#ef4444"
                  fill="#ef444422"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="internal"
                  name="Internal Only"
                  stroke="#22c55e"
                  fill="#22c55e22"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Search assets..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <Select value={exposureFilter} onValueChange={setExposureFilter}>
              <SelectTrigger className="w-44">
                <SelectValue placeholder="Exposure" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Exposures</SelectItem>
                <SelectItem value="Internet">Internet</SelectItem>
                <SelectItem value="Internal">Internal</SelectItem>
                <SelectItem value="Partially Exposed">Partially Exposed</SelectItem>
              </SelectContent>
            </Select>
            <Select value={typeFilter} onValueChange={setTypeFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Asset Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                {assetTypes.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <span className="text-sm text-muted-foreground">
              {filteredAssets.length} asset{filteredAssets.length !== 1 ? "s" : ""}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Assets Table */}
      <Card>
        <CardHeader className="pb-0">
          <CardTitle className="text-sm font-medium">Reachable Assets</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Exposure</TableHead>
                <TableHead>Path Length</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead className="text-right">Network Paths</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAssets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                    No assets found
                  </TableCell>
                </TableRow>
              ) : (
                filteredAssets.map((asset, i) => (
                  <TableRow key={asset.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="font-mono text-sm">
                      {asset.asset}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">
                        {asset.type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <ExposureBadge exposure={asset.exposure} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className="flex gap-0.5">
                          {Array.from({ length: 7 }).map((_, idx) => (
                            <div
                              key={idx}
                              className="h-2 w-2 rounded-sm"
                              style={{
                                background:
                                  idx < asset.path_length
                                    ? asset.exposure === "Internet"
                                      ? "#ef4444"
                                      : "#6366f1"
                                    : "hsl(var(--muted))",
                              }}
                            />
                          ))}
                        </div>
                        <span className="text-xs text-muted-foreground tabular-nums">
                          {asset.path_length}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <RiskScoreBadge score={asset.risk_score} />
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedAsset(asset as unknown as Record<string, unknown>);
                          setPathDialogOpen(true);
                        }}
                      >
                        <Route className="h-3.5 w-3.5 mr-1" />
                        View Paths
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>

      <NetworkPathDialog
        asset={selectedAsset}
        paths={assetPaths}
        open={pathDialogOpen}
        onClose={() => setPathDialogOpen(false)}
      />
    </motion.div>
  );
}
