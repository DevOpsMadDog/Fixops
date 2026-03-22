import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  Container, RefreshCw, Download, AlertTriangle, CheckCircle,
  Activity, Shield, Package, Image, Clock, Zap,
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
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings, useContainerStatus } from "@/hooks/use-api";
import { containerApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface ContainerFinding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  image_name?: string;
  image?: string;
  tag?: string;
  vulnerabilities?: { critical?: number; high?: number; medium?: number; low?: number };
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  cve?: string;
  last_scanned?: string;
  created_at?: string;
  base_image?: string;
  runtime_alert?: boolean;
  registry?: string;
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

function VulnCounts({ finding }: { finding: ContainerFinding }) {
  const vulns = finding.vulnerabilities;
  const c = vulns?.critical || finding.critical_count || 0;
  const h = vulns?.high || finding.high_count || 0;
  const m = vulns?.medium || finding.medium_count || 0;
  const l = vulns?.low || finding.low_count || 0;
  if (!c && !h && !m && !l) return <span className="text-muted-foreground text-xs">None</span>;
  return (
    <div className="flex gap-1 flex-wrap">
      {c > 0 && <span className="text-xs font-mono text-red-400 font-bold">{c}C</span>}
      {h > 0 && <span className="text-xs font-mono text-orange-400 font-bold">{h}H</span>}
      {m > 0 && <span className="text-xs font-mono text-yellow-400">{m}M</span>}
      {l > 0 && <span className="text-xs font-mono text-blue-400">{l}L</span>}
    </div>
  );
}

function StatusBadge({ status }: { status?: string }) {
  const s = (status || "").toLowerCase();
  const map: Record<string, string> = {
    clean: "bg-green-500/10 text-green-400 border-green-500/20",
    vulnerable: "bg-red-500/10 text-red-400 border-red-500/20",
    scanning: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    failed: "bg-red-500/10 text-red-400 border-red-500/20",
  };
  return <Badge className={cn("border text-xs", map[s] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>{status || "—"}</Badge>;
}

// Runtime protections derived from container status API capabilities

export default function ContainerSecurity() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [registryFilter, setRegistryFilter] = useState("all");
  const [detailFinding, setDetailFinding] = useState<ContainerFinding | null>(null);

  const params = useMemo(() => {
    const p: Record<string, unknown> = { limit: 200, type: "container" };
    if (statusFilter !== "all") p.status = statusFilter;
    return p;
  }, [statusFilter]);

  const query = useFindings(params);
  const containerStatusQuery = useContainerStatus();
  const refetch = useCallback(() => { query.refetch(); containerStatusQuery.refetch(); }, [query, containerStatusQuery]);

  // Derive runtime protections from container status capabilities
  const runtimeProtections = useMemo(() => {
    const caps: string[] = containerStatusQuery.data?.capabilities ?? [];
    const trivyAvail = containerStatusQuery.data?.trivy_available ?? false;
    const grypeAvail = containerStatusQuery.data?.grype_available ?? false;
    return [
      { name: "Dockerfile Analysis", active: caps.includes("dockerfile_analysis"), description: caps.includes("dockerfile_analysis") ? "Dockerfile misconfiguration scanning active" : "Dockerfile scanning not available" },
      { name: "Base Image Checks", active: caps.includes("base_image_check"), description: caps.includes("base_image_check") ? "Known-vulnerable base image detection active" : "Base image checks not configured" },
      { name: "Trivy Integration", active: trivyAvail, description: trivyAvail ? "Trivy container image scanning active" : "Trivy not available — install trivy CLI" },
      { name: "Grype Integration", active: grypeAvail, description: grypeAvail ? "Grype vulnerability scanning active" : "Grype not available — install grype CLI" },
      { name: "Read-only Root FS", active: caps.includes("dockerfile_analysis"), description: "Immutable container root filesystem checks" },
    ];
  }, [containerStatusQuery.data]);

  const allFindings: ContainerFinding[] = useMemo(() => {
    const d = query.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.findings)) return d.findings;
    if (Array.isArray(d?.cases)) return d.cases;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [query.data]);

  const filtered = useMemo(() => {
    let list = allFindings;
    if (registryFilter !== "all") list = list.filter((f) => f.registry === registryFilter);
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((f) =>
        (f.image_name || f.image || "").toLowerCase().includes(q) ||
        f.tag?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [allFindings, registryFilter, searchQuery]);

  const registries = useMemo(() =>
    Array.from(new Set(allFindings.map((f) => f.registry).filter(Boolean))),
    [allFindings]
  );

  const stats = useMemo(() => {
    let totalVulns = 0;
    let baseIssues = 0;
    let runtimeAlerts = 0;
    allFindings.forEach((f) => {
      const v = f.vulnerabilities;
      totalVulns += (v?.critical || f.critical_count || 0) +
        (v?.high || f.high_count || 0) +
        (v?.medium || f.medium_count || 0) +
        (v?.low || f.low_count || 0);
      if (f.base_image) baseIssues++;
      if (f.runtime_alert) runtimeAlerts++;
    });
    return {
      images: allFindings.length,
      vulnerabilities: totalVulns,
      baseIssues,
      runtimeAlerts,
    };
  }, [allFindings]);

  // Trend data from API (not fabricated - show actual current snapshot only)
  const trendData = useMemo(() => {
    const criticalCount = allFindings.filter((f) => f.severity?.toLowerCase() === "critical").length;
    const highCount = allFindings.filter((f) => f.severity?.toLowerCase() === "high").length;
    if (criticalCount === 0 && highCount === 0) return [];
    return [{ month: "Current", critical: criticalCount, high: highCount }];
  }, [allFindings]);

  if (query.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-56" />
        <Skeleton className="h-80" />
      </div>
    );
  }

  if (query.isError) {
    return <ErrorState message="Failed to load container security data." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Container Security" description="Image scanning, runtime protection, and registry monitoring">
        <Button variant="outline" size="sm" onClick={() => query.refetch()} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        <Button variant="outline" size="sm" className="gap-2" onClick={() => {
          const blob = new Blob([JSON.stringify(allFindings, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "container-findings.json"; a.click();
          URL.revokeObjectURL(url);
          toast.success(`Exported ${allFindings.length} container findings`);
        }}>
          <Download className="h-4 w-4" /> Export
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Images Scanned" value={stats.images} icon={Image} />
        <KpiCard title="Vulnerabilities" value={stats.vulnerabilities} icon={AlertTriangle} className="border-red-500/20" />
        <KpiCard title="Base Image Issues" value={stats.baseIssues} icon={Package} className="border-orange-500/20" />
        <KpiCard title="Runtime Alerts" value={stats.runtimeAlerts} icon={Activity} className="border-yellow-500/20" />
      </div>

      {/* Charts + Runtime Protection */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Vulnerability Trend */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              Vulnerability Trend
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={trendData} margin={{ top: 4, right: 8, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="critGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="highGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="month" tick={{ fontSize: 11 }} stroke="rgba(255,255,255,0.2)" />
                <YAxis tick={{ fontSize: 11 }} stroke="rgba(255,255,255,0.2)" />
                <Tooltip
                  contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critGradient)" strokeWidth={2} name="Critical" />
                <Area type="monotone" dataKey="high" stroke="#f97316" fill="url(#highGradient)" strokeWidth={2} name="High" />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Runtime Protection */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Runtime Protection
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {runtimeProtections.map((protection) => (
              <div key={protection.name} className="flex items-start gap-3">
                {protection.active ? (
                  <CheckCircle className="h-4 w-4 text-green-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
                )}
                <div>
                  <p className="text-xs font-semibold">{protection.name}</p>
                  <p className="text-xs text-muted-foreground">{protection.description}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Image Scan Results Table */}
      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between gap-4">
          <CardTitle className="text-sm">Image Scan Results</CardTitle>
          <div className="flex gap-3 flex-wrap">
            <div className="relative">
              <Container className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search image..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 w-48"
              />
            </div>
            {registries.length > 0 && (
              <Select value={registryFilter} onValueChange={setRegistryFilter}>
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="Registry" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Registries</SelectItem>
                  {registries.map((r) => (
                    <SelectItem key={r} value={r!}>{r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="clean">Clean</SelectItem>
                <SelectItem value="vulnerable">Vulnerable</SelectItem>
                <SelectItem value="scanning">Scanning</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Image Name</TableHead>
                <TableHead>Tag</TableHead>
                <TableHead>Vulnerabilities</TableHead>
                <TableHead>Base Image</TableHead>
                <TableHead>Registry</TableHead>
                <TableHead>Last Scanned</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12 text-muted-foreground">
                    <div className="flex flex-col items-center gap-2">
                      <Container className="h-8 w-8 opacity-30" />
                      <p>No container images found</p>
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((finding, idx) => {
                  const id = finding.id || finding.finding_id || String(idx);
                  return (
                    <TableRow
                      key={id}
                      className="cursor-pointer hover:bg-muted/40"
                      onClick={() => setDetailFinding(finding)}
                    >
                      <TableCell className="font-mono text-xs max-w-[200px]">
                        <div className="flex items-center gap-2">
                          <Image className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                          <span className="truncate">{finding.image_name || finding.image || finding.title || "—"}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {finding.tag || "latest"}
                      </TableCell>
                      <TableCell><VulnCounts finding={finding} /></TableCell>
                      <TableCell className="text-xs text-muted-foreground max-w-[150px]">
                        <span className="truncate block">{finding.base_image || "—"}</span>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {finding.registry || "—"}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                        <div className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {finding.last_scanned
                            ? new Date(finding.last_scanned).toLocaleDateString()
                            : finding.created_at
                              ? new Date(finding.created_at).toLocaleDateString()
                              : "—"}
                        </div>
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={finding.status} />
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

      {/* Registry Monitoring Summary */}
      {registries.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Package className="h-4 w-4 text-primary" />
              Registry Monitoring
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
              {registries.map((registry) => {
                const count = allFindings.filter((f) => f.registry === registry).length;
                const vulnCount = allFindings.filter((f) => f.registry === registry && f.status === "vulnerable").length;
                return (
                  <div key={registry} className="p-3 border rounded-lg space-y-1">
                    <p className="text-xs font-mono font-semibold truncate">{registry}</p>
                    <div className="flex gap-2 text-xs text-muted-foreground">
                      <span>{count} images</span>
                      {vulnCount > 0 && <span className="text-red-400">{vulnCount} vuln</span>}
                    </div>
                    <div className="flex items-center gap-1">
                      <Zap className="h-3 w-3 text-green-400" />
                      <span className="text-xs text-green-400">Monitoring active</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Detail Dialog */}
      <Dialog open={!!detailFinding} onOpenChange={(open) => { if (!open) setDetailFinding(null); }}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <Container className="h-5 w-5 text-primary" />
              <span className="truncate font-mono text-sm">
                {detailFinding?.image_name || detailFinding?.image || detailFinding?.title}
              </span>
            </DialogTitle>
          </DialogHeader>
          {detailFinding && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: "Tag", value: <code className="text-xs font-mono">{detailFinding.tag || "latest"}</code> },
                  { label: "Status", value: <StatusBadge status={detailFinding.status} /> },
                  { label: "Registry", value: detailFinding.registry || "—" },
                  { label: "Base Image", value: <code className="text-xs font-mono">{detailFinding.base_image || "—"}</code> },
                  { label: "Runtime Alert", value: detailFinding.runtime_alert ? <span className="text-red-400 text-xs">Yes</span> : <span className="text-muted-foreground text-xs">No</span> },
                  { label: "Last Scanned", value: detailFinding.last_scanned ? new Date(detailFinding.last_scanned).toLocaleDateString() : "—" },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-muted-foreground mb-1">{label}</p>
                    <div className="text-sm font-medium">{value}</div>
                  </div>
                ))}
              </div>
              <Separator />
              <div>
                <p className="text-xs font-semibold text-muted-foreground mb-2">Vulnerability Summary</p>
                <div className="flex gap-4">
                  {[
                    { label: "Critical", count: detailFinding.vulnerabilities?.critical || detailFinding.critical_count || 0, color: "text-red-400" },
                    { label: "High", count: detailFinding.vulnerabilities?.high || detailFinding.high_count || 0, color: "text-orange-400" },
                    { label: "Medium", count: detailFinding.vulnerabilities?.medium || detailFinding.medium_count || 0, color: "text-yellow-400" },
                    { label: "Low", count: detailFinding.vulnerabilities?.low || detailFinding.low_count || 0, color: "text-blue-400" },
                  ].map(({ label, count, color }) => (
                    <div key={label} className="text-center">
                      <p className={cn("text-2xl font-bold font-mono", color)}>{count}</p>
                      <p className="text-xs text-muted-foreground">{label}</p>
                    </div>
                  ))}
                </div>
              </div>
              {detailFinding.description && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1">Notes</p>
                  <p className="text-sm">{detailFinding.description}</p>
                </div>
              )}
              <div className="flex gap-2">
                <Button size="sm" onClick={async () => {
                  try {
                    const image = detailFinding.title || detailFinding.image || "unknown";
                    await containerApi.scanImage({ image });
                    toast.success(`Rescan initiated for ${image}`);
                    query.refetch();
                  } catch { toast.error("Rescan failed"); }
                }}>Rescan Image</Button>
                <Button size="sm" variant="outline" onClick={() => {
                  const id = detailFinding.id || detailFinding.finding_id;
                  if (id) navigate(`/discover/finding-explorer?search=${encodeURIComponent(id)}`);
                }}>View Full Report</Button>
                <Button size="sm" variant="outline" onClick={() => {
                  const title = detailFinding.title || detailFinding.cve || "Container vulnerability";
                  navigate(`/remediate/ticket-integration?title=${encodeURIComponent(title)}&source=container`);
                }}>Create Ticket</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
