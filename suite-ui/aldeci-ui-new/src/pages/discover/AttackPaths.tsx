import { useState, useCallback, useMemo } from "react";
import { motion } from "framer-motion";
import {
  Target, RefreshCw, Download, AlertTriangle, Shield,
  ArrowRight, Zap, GitMerge, CheckCircle, Filter,
  MoreHorizontal, Eye, ChevronRight, Activity, Search,
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
import { useCases } from "@/hooks/use-api";
import { useQuery } from "@tanstack/react-query";
import { knowledgeGraphApi } from "@/lib/api";
import { cn } from "@/lib/utils";

interface AttackPath {
  id?: string;
  path_id?: string;
  source?: string;
  target?: string;
  hops?: number;
  hop_count?: number;
  blast_radius?: number;
  severity?: string;
  mpte_verified?: boolean;
  verified?: boolean;
  steps?: AttackStep[];
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
  const [severityFilter, setSeverityFilter] = useState("all");
  const [verifiedFilter, setVerifiedFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [detailPath, setDetailPath] = useState<AttackPath | null>(null);
  const [blastSource, setBlastSource] = useState("");

  // Use knowledge graph attack paths
  const attackPathsQuery = useQuery({
    queryKey: ["graph", "attack-paths"],
    queryFn: async () => {
      const { data } = await knowledgeGraphApi.attackPaths();
      return data;
    },
  });

  // Also get related findings
  const findingsQuery = useCases({ limit: 50, type: "attack" });
  const refetch = useCallback(() => { attackPathsQuery.refetch(); findingsQuery.refetch(); }, [attackPathsQuery, findingsQuery]);

  const allPaths: AttackPath[] = useMemo(() => {
    const d = attackPathsQuery.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.attack_paths)) return d.attack_paths;
    if (Array.isArray(d?.paths)) return d.paths;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
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
        p.technique?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [allPaths, severityFilter, verifiedFilter, searchQuery]);

  const stats = useMemo(() => {
    const critical = allPaths.filter((p) => p.severity?.toLowerCase() === "critical").length;
    const avgBlast = allPaths.length > 0
      ? allPaths.reduce((sum, p) => sum + (p.blast_radius || 0), 0) / allPaths.length
      : 0;
    const maxHops = allPaths.reduce((max, p) => Math.max(max, p.hops || p.hop_count || 0), 0);
    return {
      total: allPaths.length,
      critical,
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
        <Button variant="outline" size="sm" className="gap-2">
          <Download className="h-4 w-4" /> Export Report
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Attack Paths" value={stats.total} icon={GitMerge} />
        <KpiCard title="Critical Paths" value={stats.critical} icon={AlertTriangle} className="border-red-500/20" />
        <KpiCard title="Avg Blast Radius" value={stats.avgBlast} icon={Activity} className="border-orange-500/20" />
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
                                <DropdownMenuItem>
                                  <Target className="h-3.5 w-3.5 mr-2" /> Request MPTE Scan
                                </DropdownMenuItem>
                                <DropdownMenuItem>
                                  <Shield className="h-3.5 w-3.5 mr-2" /> Block Path
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
              <Button className="w-full gap-2" size="sm" disabled={!blastSource.trim()}>
                <Activity className="h-4 w-4" /> Calculate Blast Radius
              </Button>

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
                  <Button size="sm" className="gap-1">
                    <Target className="h-3 w-3" /> Request MPTE Scan
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1">
                    <Shield className="h-3 w-3" /> Block Path
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1">
                    <Filter className="h-3 w-3" /> Create Remediation
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
