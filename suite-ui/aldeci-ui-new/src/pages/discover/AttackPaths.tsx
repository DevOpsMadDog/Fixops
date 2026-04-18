import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Target, RefreshCw, Download, AlertTriangle, Shield,
  ArrowRight, Zap, GitMerge, CheckCircle, Filter,
  MoreHorizontal, Eye, ChevronRight, Activity, Search,
  Loader2, Crosshair,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings } from "@/hooks/use-api";
import { useQuery, useMutation } from "@tanstack/react-query";
import { knowledgeGraphApi, mpteApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface AttackPath {
  id?: string;
  path_id?: string;
  name?: string;
  source?: string;
  target?: string;
  hops?: number;
  hop_count?: number;
  blast_radius?: number;
  likelihood?: number;
  impact?: string;
  severity?: string;
  mpte_verified?: boolean;
  verified?: boolean;
  steps?: AttackStep[];
  mitigations?: string[];
  description?: string;
  technique?: string;
  mitre_id?: string;
  created_at?: string;
}

interface AttackStep {
  step?: number;
  node?: string;
  action?: string;
  technique?: string;
  description?: string;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const map: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return <Badge className={cn("border text-xs font-semibold uppercase", map[s] || "bg-slate-500/15 text-slate-400 border-slate-500/20")}>{severity || "Unknown"}</Badge>;
}

function BlastRadiusBar({ radius }: { radius?: number }) {
  const r = Math.min(100, Math.max(0, (radius || 0) * 10));
  const color = r >= 80 ? "bg-red-500" : r >= 60 ? "bg-orange-500" : r >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden w-16">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${r}%` }} />
      </div>
      <span className="text-xs font-mono text-muted-foreground">{radius?.toFixed(1) || "—"}</span>
    </div>
  );
}

export default function AttackPaths() {
  const navigate = useNavigate();
  const [severityFilter, setSeverityFilter] = useState("all");
  const [verifiedFilter, setVerifiedFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [detailPath, setDetailPath] = useState<AttackPath | null>(null);
  const [blastSource, setBlastSource] = useState("");
  const [blastResult, setBlastResult] = useState<Record<string, unknown> | null>(null);

  // Use knowledge graph attack paths
  const attackPathsQuery = useQuery({
    queryKey: ["graph", "attack-paths"],
    queryFn: async () => {
      const { data } = await knowledgeGraphApi.attackPaths();
      return data;
    },
  });

  // Also get related findings
  const findingsQuery = useFindings({ limit: 50, type: "attack" });
  const refetch = useCallback(() => { attackPathsQuery.refetch(); findingsQuery.refetch(); }, [attackPathsQuery, findingsQuery]);

  // Blast radius mutation
  const blastMutation = useMutation({
    mutationFn: async (source: string) => {
      const { data } = await knowledgeGraphApi.blastRadius({ finding_id: source, max_depth: 5 });
      return data;
    },
    onSuccess: (data) => {
      setBlastResult(data as Record<string, unknown>);
      toast.success("Blast radius calculated");
    },
    onError: () => toast.error("Blast radius calculation failed"),
  });

  // MPTE scan mutation
  const mpteMutation = useMutation({
    mutationFn: async (path: AttackPath) => {
      const { data } = await mpteApi.verify({
        finding_id: path.id || path.path_id,
        attack_path: { source: path.source, target: path.target, steps: path.steps },
        scan_type: "attack_path_verification",
      });
      return data;
    },
    onSuccess: () => {
      toast.success("MPTE verification scan initiated");
      attackPathsQuery.refetch();
    },
    onError: () => toast.error("MPTE scan request failed"),
  });

  const allPaths: AttackPath[] = useMemo(() => {
    const d = attackPathsQuery.data;
    if (!d) return [];
    let raw: Record<string, unknown>[] = [];
    if (Array.isArray(d)) raw = d;
    else if (Array.isArray(d?.attack_paths)) raw = d.attack_paths;
    else if (Array.isArray(d?.paths)) raw = d.paths;
    else if (Array.isArray(d?.items)) raw = d.items;
    else if (Array.isArray(d?.data)) raw = d.data;
    // Normalize: derive source/target from steps[0].node and steps[-1].node if missing
    return raw.map((p: Record<string, unknown>) => {
      const steps = (p.steps || []) as AttackStep[];
      const source = (p.source as string) || steps[0]?.node || (p.name as string)?.split('→')[0]?.replace('→','').trim() || undefined;
      const target = (p.target as string) || steps[steps.length - 1]?.node || (p.name as string)?.split('→').pop()?.trim() || undefined;
      const hops = (p.hops as number) || (p.hop_count as number) || steps.length || 0;
      const likelihood = p.likelihood as number | undefined;
      return {
        ...p,
        source,
        target,
        hops,
        hop_count: hops,
        blast_radius: (p.blast_radius as number) ?? (likelihood != null ? likelihood * 10 : undefined),
        name: p.name as string | undefined,
      } as AttackPath;
    });
  }, [attackPathsQuery.data]);

  const filtered = useMemo(() => {
    let list = allPaths;
    if (severityFilter !== "all") list = list.filter((p) => p.severity?.toLowerCase() === severityFilter);
    if (verifiedFilter === "verified") list = list.filter((p) => p.mpte_verified || p.verified);
    if (verifiedFilter === "unverified") list = list.filter((p) => !p.mpte_verified && !p.verified);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((p) =>
        p.source?.toLowerCase().includes(q) ||
        p.target?.toLowerCase().includes(q) ||
        p.name?.toLowerCase().includes(q) ||
        p.technique?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [allPaths, severityFilter, verifiedFilter, searchQuery]);

  const stats = useMemo(() => {
    const critical = allPaths.filter((p) => p.severity?.toLowerCase() === "critical").length;
    const verified = allPaths.filter((p) => p.mpte_verified || p.verified).length;
    const avgBlast = allPaths.length > 0
      ? allPaths.reduce((sum, p) => sum + (p.blast_radius || 0), 0) / allPaths.length
      : 0;
    const maxHops = allPaths.reduce((max, p) => Math.max(max, p.hops || p.hop_count || 0), 0);
    return {
      total: allPaths.length,
      critical,
      verified,
      avgBlast: avgBlast.toFixed(1),
      maxHops,
    };
  }, [allPaths]);

  const isLoading = attackPathsQuery.isLoading;
  const isError = attackPathsQuery.isError;

  if (isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  if (isError) {
    return <ErrorState message="Failed to load attack paths." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Attack Paths" description="Visualized attack chains and blast radius analysis">
        <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        <Button variant="outline" size="sm" className="gap-2" onClick={() => {
          const blob = new Blob([JSON.stringify(allPaths, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "attack-paths-report.json"; a.click();
          URL.revokeObjectURL(url);
          toast.success(`Exported ${allPaths.length} attack paths`);
        }}>
          <Download className="h-4 w-4" /> Export Report
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <KpiCard title="Total Attack Paths" value={stats.total} icon={GitMerge} />
        <KpiCard title="Critical Paths" value={stats.critical} icon={AlertTriangle} className="border-red-500/20" onClick={() => setSeverityFilter(severityFilter === "critical" ? "all" : "critical")} />
        <KpiCard title="MPTE Verified" value={stats.verified} icon={CheckCircle} className="border-green-500/20" onClick={() => setVerifiedFilter(verifiedFilter === "verified" ? "all" : "verified")} />
        <KpiCard title="Avg Blast Radius" value={stats.avgBlast} icon={Crosshair} className="border-orange-500/20" />
        <KpiCard title="Max Hops" value={stats.maxHops} icon={ChevronRight} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Table */}
        <div className="lg:col-span-2 space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search source, target, technique..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={verifiedFilter} onValueChange={setVerifiedFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Verification" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="verified">MPTE Verified</SelectItem>
                <SelectItem value="unverified">Unverified</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">{filtered.length} attack paths</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Source → Target</TableHead>
                    <TableHead className="text-center w-16">Hops</TableHead>
                    <TableHead>Blast Radius</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead className="w-28">MPTE Verified</TableHead>
                    <TableHead className="w-10" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <Shield className="h-8 w-8 opacity-30 text-green-400" />
                          <p>No attack paths detected</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((path, idx) => {
                      const id = path.id || path.path_id || String(idx);
                      const isVerified = path.mpte_verified || path.verified;
                      const hops = path.hops || path.hop_count || 0;
                      return (
                        <TableRow
                          key={id}
                          className="cursor-pointer hover:bg-muted/40"
                          onClick={() => setDetailPath(path)}
                        >
                          <TableCell className="max-w-[280px]">
                            <div className="flex items-center gap-2 text-sm">
                              <span className="font-medium truncate max-w-[100px] text-blue-400">{path.source || "Unknown"}</span>
                              <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                              <span className="font-medium truncate max-w-[100px] text-red-400">{path.target || "Unknown"}</span>
                            </div>
                            {path.technique && (
                              <p className="text-xs text-muted-foreground mt-0.5">{path.technique}</p>
                            )}
                          </TableCell>
                          <TableCell className="text-center">
                            <span className="font-mono text-sm font-bold">{hops || "—"}</span>
                          </TableCell>
                          <TableCell>
                            <BlastRadiusBar radius={path.blast_radius} />
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={path.severity} />
                          </TableCell>
                          <TableCell>
                            {isVerified ? (
                              <div className="flex items-center gap-1">
                                <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                                <span className="text-xs text-green-400">Verified</span>
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">Pending</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="h-7 w-7" onClick={(e) => e.stopPropagation()}>
                                  <MoreHorizontal className="h-3.5 w-3.5" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => setDetailPath(path)}>
                                  <Eye className="h-3.5 w-3.5 mr-2" /> View Path
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => mpteMutation.mutate(path)}>
                                  <Target className="h-3.5 w-3.5 mr-2" /> Request MPTE Scan
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => navigate(`/remediate?search=${encodeURIComponent(path.target || path.source || "")}`)}>
                                  <Shield className="h-3.5 w-3.5 mr-2" /> Create Remediation
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Blast Radius Calculator */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Zap className="h-4 w-4 text-orange-400" />
                Blast Radius Calculator
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground">Source Node / Component</label>
                <Input
                  placeholder="Enter component name..."
                  value={blastSource}
                  onChange={(e) => setBlastSource(e.target.value)}
                  className="text-sm"
                />
              </div>
              <Button
                className="w-full gap-2"
                size="sm"
                disabled={!blastSource.trim() || blastMutation.isPending}
                onClick={() => blastMutation.mutate(blastSource)}
              >
                {blastMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
                {blastMutation.isPending ? "Calculating..." : "Calculate Blast Radius"}
              </Button>

              {/* Blast Radius Result */}
              {blastResult && (
                <div className="p-3 bg-orange-500/5 border border-orange-500/20 rounded-lg space-y-2">
                  <p className="text-xs font-semibold text-orange-400">Blast Radius Result</p>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Affected Nodes</span>
                      <p className="font-mono font-bold">{String(blastResult.affected_nodes ?? blastResult.affected_components ?? "—")}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Risk Multiplier</span>
                      <p className="font-mono font-bold">{String(blastResult.risk_multiplier ?? "—")}×</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Depth</span>
                      <p className="font-mono font-bold">{String(blastResult.depth ?? blastResult.max_depth ?? "—")}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Chained CVEs</span>
                      <p className="font-mono font-bold">{Array.isArray(blastResult.chained_cves) ? blastResult.chained_cves.length : "—"}</p>
                    </div>
                  </div>
                </div>
              )}

              <Separator />

              {/* Top affected paths */}
              <div>
                <p className="text-xs text-muted-foreground mb-2">Highest Blast Radius Paths</p>
                <div className="space-y-2">
                  {[...allPaths]
                    .sort((a, b) => (b.blast_radius || 0) - (a.blast_radius || 0))
                    .slice(0, 5)
                    .map((path, i) => (
                      <div
                        key={i}
                        className="p-2 bg-muted/30 rounded-md cursor-pointer hover:bg-muted/50 transition-colors"
                        onClick={() => setDetailPath(path)}
                      >
                        <div className="flex items-center gap-1 text-xs mb-1">
                          <span className="text-blue-400 truncate max-w-[70px]">{path.source || "—"}</span>
                          <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
                          <span className="text-red-400 truncate max-w-[70px]">{path.target || "—"}</span>
                        </div>
                        <BlastRadiusBar radius={path.blast_radius} />
                      </div>
                    ))}
                  {allPaths.length === 0 && (
                    <p className="text-xs text-muted-foreground text-center py-2">No paths available</p>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Stats breakdown */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Severity Breakdown</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                { label: "Critical", color: "bg-red-500/15 text-red-400 border-red-500/30", sev: "critical" },
                { label: "High", color: "bg-orange-500/15 text-orange-400 border-orange-500/30", sev: "high" },
                { label: "Medium", color: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", sev: "medium" },
                { label: "Low", color: "bg-blue-500/15 text-blue-400 border-blue-500/30", sev: "low" },
              ].map(({ label, color, sev }) => {
                const count = allPaths.filter((p) => p.severity?.toLowerCase() === sev).length;
                const pct = allPaths.length > 0 ? (count / allPaths.length) * 100 : 0;
                return (
                  <div key={label}>
                    <div className="flex justify-between items-center mb-1">
                      <Badge className={cn("border text-xs", color)}>{label}</Badge>
                      <span className="text-xs font-mono font-bold">{count}</span>
                    </div>
                    <div className="h-1 bg-muted rounded-full overflow-hidden">
                      <div
                        className={cn("h-full rounded-full", sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-orange-500" : sev === "medium" ? "bg-yellow-500" : "bg-blue-500")}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Path Detail Dialog */}
      <Dialog open={!!detailPath} onOpenChange={(open) => { if (!open) setDetailPath(null); }}>
        <DialogContent className="max-w-2xl max-h-[90vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <SeverityBadge severity={detailPath?.severity} />
              <span className="flex items-center gap-1 text-sm">
                <span className="text-blue-400">{detailPath?.source}</span>
                <ArrowRight className="h-4 w-4" />
                <span className="text-red-400">{detailPath?.target}</span>
              </span>
            </DialogTitle>
          </DialogHeader>
          {detailPath && (
            <ScrollArea className="max-h-[70vh]">
              <div className="space-y-4 pr-2">
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: "Hops", value: <span className="font-mono font-bold">{detailPath.hops || detailPath.hop_count || "—"}</span> },
                    { label: "Blast Radius", value: <span className="font-mono font-bold">{detailPath.blast_radius?.toFixed(1) || "—"}</span> },
                    { label: "MPTE Verified", value: (detailPath.mpte_verified || detailPath.verified) ? <span className="text-green-400">Yes</span> : <span className="text-muted-foreground">No</span> },
                    { label: "Technique", value: <code className="text-xs font-mono">{detailPath.technique || "—"}</code> },
                    { label: "MITRE ID", value: detailPath.mitre_id ? <Badge variant="outline" className="text-xs font-mono">{detailPath.mitre_id}</Badge> : "—" },
                  ].map(({ label, value }) => (
                    <div key={label}>
                      <p className="text-xs text-muted-foreground mb-1">{label}</p>
                      <div className="text-sm font-medium">{value}</div>
                    </div>
                  ))}
                </div>

                {detailPath.description && (
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Description</p>
                    <p className="text-sm">{detailPath.description}</p>
                  </div>
                )}

                <Separator />

                {/* Step-by-step chain */}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-3 uppercase tracking-wide">
                    Attack Chain Steps
                  </p>
                  {detailPath.steps && detailPath.steps.length > 0 ? (
                    <div className="space-y-2">
                      {detailPath.steps.map((step, i) => (
                        <div key={i} className="flex gap-3">
                          <div className="flex flex-col items-center">
                            <div className="w-6 h-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0">
                              <span className="text-xs font-bold text-primary">{i + 1}</span>
                            </div>
                            {i < (detailPath.steps?.length || 0) - 1 && (
                              <div className="w-px flex-1 bg-border/50 my-1" />
                            )}
                          </div>
                          <div className="pb-4">
                            <p className="text-sm font-medium">{step.node || `Step ${i + 1}`}</p>
                            {step.action && <p className="text-xs text-muted-foreground">{step.action}</p>}
                            {step.technique && (
                              <Badge variant="outline" className="text-xs mt-1">{step.technique}</Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {/* Auto-generate step display from source/target */}
                      {[
                        { step: 1, node: detailPath.source || "Entry Point", action: "Initial access or foothold established" },
                        { step: 2, node: "Lateral Movement", action: "Propagation through connected components" },
                        { step: detailPath.hops || 3, node: detailPath.target || "Target", action: "Target reached — potential data exfiltration or system compromise" },
                      ].map((step, i, arr) => (
                        <div key={i} className="flex gap-3">
                          <div className="flex flex-col items-center">
                            <div className="w-6 h-6 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0">
                              <span className="text-xs font-bold text-primary">{step.step}</span>
                            </div>
                            {i < arr.length - 1 && (
                              <div className="w-px flex-1 bg-border/50 my-1" />
                            )}
                          </div>
                          <div className="pb-4">
                            <p className="text-sm font-medium">{step.node}</p>
                            <p className="text-xs text-muted-foreground">{step.action}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button
                    size="sm"
                    className="gap-1"
                    disabled={mpteMutation.isPending}
                    onClick={() => { if (detailPath) mpteMutation.mutate(detailPath); }}
                  >
                    {mpteMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Target className="h-3 w-3" />}
                    {mpteMutation.isPending ? "Scanning..." : "Request MPTE Scan"}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1"
                    onClick={() => navigate(`/remediate?search=${encodeURIComponent(detailPath?.target || detailPath?.source || "")}`)}
                  >
                    <Filter className="h-3 w-3" /> Create Remediation
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    className="gap-1"
                    onClick={() => navigate(`/discover?search=${encodeURIComponent(detailPath?.source || "")}`)}
                  >
                    <Eye className="h-3 w-3" /> View Findings
                  </Button>
                </div>
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
