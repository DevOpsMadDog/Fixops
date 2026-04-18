import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Package, RefreshCw, Download, AlertTriangle, CheckCircle,
  FileText, Layers, List, Scale, Server, ChevronRight, Search,
  Shield, Zap, ExternalLink, Eye, ShieldAlert, GitBranch,
  Activity, Ghost, Radio,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipTrigger, TooltipProvider } from "@/components/ui/tooltip";
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
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useApps } from "@/hooks/use-api";
import { sbomApi, threatFeedsApi, reachabilityApi } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface SbomPackage {
  id?: string;
  finding_id?: string;
  name?: string;
  version?: string;
  license?: string;
  licenses?: string[];
  vulnerabilities?: number;
  vuln_count?: number;
  ecosystem?: string;
  language?: string;
  outdated?: boolean;
  latest_version?: string;
  severity?: string;
  status?: string;
  cve_ids?: string[];
  reachable?: boolean;
  direct?: boolean;
  depth?: number;
  purl?: string;
  runtime_status?: "confirmed" | "sbom_only" | "shadow" | "unknown";
  risk_score?: number;
  epss_score?: number;
  is_kev?: boolean;
}

const LICENSE_RISK: Record<string, { level: string; color: string; label: string }> = {
  MIT: { level: "permissive", color: "text-green-400", label: "Permissive" },
  "Apache-2.0": { level: "permissive", color: "text-green-400", label: "Permissive" },
  BSD: { level: "permissive", color: "text-green-400", label: "Permissive" },
  ISC: { level: "permissive", color: "text-green-400", label: "Permissive" },
  LGPL: { level: "weak-copyleft", color: "text-yellow-400", label: "Weak Copyleft" },
  MPL: { level: "weak-copyleft", color: "text-yellow-400", label: "Weak Copyleft" },
  GPL: { level: "copyleft", color: "text-red-400", label: "Copyleft" },
  AGPL: { level: "copyleft", color: "text-red-400", label: "Strong Copyleft" },
  UNKNOWN: { level: "unknown", color: "text-slate-400", label: "Unknown Risk" },
};

function getLicenseRisk(license?: string): { level: string; color: string; label: string } {
  const l = (license || "").toUpperCase();
  const key = Object.keys(LICENSE_RISK).find((k) => l.includes(k.toUpperCase()));
  return key ? LICENSE_RISK[key] : LICENSE_RISK.UNKNOWN;
}

function VulnSeverityDot({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
  };
  if (!s || !colors[s]) return null;
  return (
    <span className={cn("inline-block h-2 w-2 rounded-full", colors[s])} title={`${severity} severity`} />
  );
}

function ReachBadge({ reachable, direct }: { reachable?: boolean; direct?: boolean }) {
  if (reachable === true) {
    return (
      <Badge className="bg-red-500/10 text-red-400 border-red-500/20 text-[10px] border gap-1">
        <Zap className="h-2.5 w-2.5" />
        {direct ? "Direct" : "Reachable"}
      </Badge>
    );
  }
  if (reachable === false) {
    return (
      <Badge className="bg-slate-500/10 text-slate-400 border-slate-500/20 text-[10px] border">
        Unreachable
      </Badge>
    );
  }
  return <span className="text-[10px] text-muted-foreground">—</span>;
}

function RuntimeStatusBadge({ status }: { status?: string }) {
  if (status === "confirmed") {
    return (
      <Badge className="bg-green-500/10 text-green-400 border-green-500/20 text-[10px] border gap-1">
        <Activity className="h-2.5 w-2.5" />
        Runtime
      </Badge>
    );
  }
  if (status === "shadow") {
    return (
      <Badge className="bg-purple-500/10 text-purple-400 border-purple-500/20 text-[10px] border gap-1">
        <Ghost className="h-2.5 w-2.5" />
        Shadow
      </Badge>
    );
  }
  if (status === "sbom_only") {
    return (
      <Badge className="bg-slate-500/10 text-slate-400 border-slate-500/20 text-[10px] border">
        SBOM Only
      </Badge>
    );
  }
  return <span className="text-[10px] text-muted-foreground">—</span>;
}

interface AssetItem {
  id?: string;
  name?: string;
  type?: string;
  owner?: string;
  last_scanned?: string;
  status?: string;
}

interface Dependency {
  name?: string;
  version?: string;
  children?: Dependency[];
  level?: number;
}

function LicenseBadge({ license }: { license?: string }) {
  const l = (license || "").toUpperCase();
  const map: Record<string, string> = {
    MIT: "bg-green-500/10 text-green-400 border-green-500/20",
    APACHE: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    "APACHE-2.0": "bg-blue-500/10 text-blue-400 border-blue-500/20",
    GPL: "bg-red-500/10 text-red-400 border-red-500/20",
    "GPL-2.0": "bg-red-500/10 text-red-400 border-red-500/20",
    "GPL-3.0": "bg-red-500/10 text-red-400 border-red-500/20",
    BSD: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    LGPL: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    UNKNOWN: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  };
  const key = Object.keys(map).find((k) => l.includes(k)) || "UNKNOWN";
  return <Badge className={cn("border text-xs", map[key])}>{license || "Unknown"}</Badge>;
}

function EcoBadge({ ecosystem }: { ecosystem?: string }) {
  const map: Record<string, string> = {
    npm: "bg-red-500/10 text-red-400 border-red-500/20",
    pypi: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    maven: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    nuget: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    go: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    cargo: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    rubygems: "bg-red-500/10 text-red-300 border-red-500/20",
  };
  const e = (ecosystem || "").toLowerCase();
  return <Badge className={cn("border text-xs", map[e] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>{ecosystem || "—"}</Badge>;
}

const LICENSE_COLORS = ["#22c55e", "#3b82f6", "#ef4444", "#8b5cf6", "#6b7280"];
const LICENSE_TYPES = ["MIT", "Apache-2.0", "GPL", "BSD", "Unknown"];

function DependencyTree({ deps, level = 0 }: { deps: Dependency[]; level?: number }) {
  return (
    <div>
      {deps.map((dep, i) => (
        <div key={i} style={{ paddingLeft: level * 16 }}>
          <div className="flex items-center gap-2 py-1 hover:bg-muted/30 rounded px-2">
            {level > 0 && <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />}
            {level === 0 && <Package className="h-3.5 w-3.5 text-primary shrink-0" />}
            <span className="text-xs font-mono font-medium">{dep.name}</span>
            {dep.version && (
              <span className="text-xs text-muted-foreground">{dep.version}</span>
            )}
          </div>
          {dep.children && dep.children.length > 0 && (
            <DependencyTree deps={dep.children} level={level + 1} />
          )}
        </div>
      ))}
    </div>
  );
}

export default function SBOMInventory() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("sbom");
  const [ecosystemFilter, setEcosystemFilter] = useState("all");
  const [licenseFilter, setLicenseFilter] = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");

  const query = useQuery({
    queryKey: ["sbom", "components", ecosystemFilter],
    queryFn: async () => {
      const params: Record<string, unknown> = { limit: 300 };
      if (ecosystemFilter !== "all") params.ecosystem = ecosystemFilter;
      const { data } = await sbomApi.components(params);
      return data;
    },
  });

  // Reachability enrichment
  const reachQuery = useQuery({
    queryKey: ["reachability", "analysis"],
    queryFn: async () => {
      const { data } = await reachabilityApi.analysis();
      return data;
    },
    staleTime: 120_000,
  });

  // License compliance from backend
  const licenseQuery = useQuery({
    queryKey: ["sbom", "licenses"],
    queryFn: async () => {
      const { data } = await sbomApi.licenses();
      return data;
    },
    staleTime: 120_000,
  });

  const appsQuery = useApps();
  const refetch = useCallback(() => { query.refetch(); appsQuery.refetch(); reachQuery.refetch(); licenseQuery.refetch(); }, [query, appsQuery, reachQuery, licenseQuery]);

  const allPackages: SbomPackage[] = useMemo(() => {
    const d = query.data;
    if (!d) return [];
    let pkgs: SbomPackage[] = [];
    if (Array.isArray(d)) pkgs = d;
    else {
      const obj = d as Record<string, unknown>;
      if (Array.isArray(obj?.components)) pkgs = obj.components as SbomPackage[];
      else if (Array.isArray(obj?.packages)) pkgs = obj.packages as SbomPackage[];
      else if (Array.isArray(obj?.items)) pkgs = obj.items as SbomPackage[];
    }

    // Merge reachability data
    const reachData = reachQuery.data as Record<string, unknown> | undefined;
    const reachComponents = (reachData?.components ?? reachData?.results ?? []) as Array<Record<string, unknown>>;
    if (reachComponents.length > 0) {
      const reachMap = new Map<string, Record<string, unknown>>();
      for (const rc of reachComponents) {
        const key = String(rc.name ?? rc.package ?? "").toLowerCase();
        if (key) reachMap.set(key, rc);
      }
      pkgs = pkgs.map((p) => {
        const key = (p.name ?? "").toLowerCase();
        const rc = reachMap.get(key);
        if (rc) {
          return {
            ...p,
            reachable: p.reachable ?? (rc.reachable === true),
            direct: p.direct ?? (rc.direct === true),
            runtime_status: p.runtime_status ?? (rc.runtime ? "confirmed" as const : (rc.shadow ? "shadow" as const : p.runtime_status)),
          };
        }
        return p;
      });
    }
    return pkgs;
  }, [query.data, reachQuery.data]);

  const assets: AssetItem[] = useMemo(() => {
    const d = appsQuery.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.apps)) return d.apps;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [appsQuery.data]);

  const filteredPackages = useMemo(() => {
    let list = allPackages;
    if (licenseFilter !== "all") {
      list = list.filter((p) => {
        const l = (p.license || "").toUpperCase();
        return l.includes(licenseFilter.toUpperCase());
      });
    }
    if (riskFilter === "reachable") list = list.filter((p) => p.reachable === true);
    else if (riskFilter === "vulnerable") list = list.filter((p) => (p.vulnerabilities || p.vuln_count || 0) > 0);
    else if (riskFilter === "shadow") list = list.filter((p) => p.runtime_status === "shadow");
    else if (riskFilter === "outdated") list = list.filter((p) => p.outdated);
    else if (riskFilter === "copyleft") list = list.filter((p) => {
      const l = (p.license || "").toUpperCase();
      return l.includes("GPL") || l.includes("AGPL");
    });
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((p) => p.name?.toLowerCase().includes(q) || p.version?.toLowerCase().includes(q));
    }
    return list;
  }, [allPackages, licenseFilter, riskFilter, searchQuery]);

  const ecosystems = useMemo(() =>
    Array.from(new Set(allPackages.map((p) => p.ecosystem || p.language).filter(Boolean))),
    [allPackages]
  );

  const stats = useMemo(() => {
    const outdated = allPackages.filter((p) => p.outdated).length;
    const withVulns = allPackages.filter((p) => (p.vulnerabilities || p.vuln_count || 0) > 0).length;
    const reachable = allPackages.filter((p) => p.reachable === true).length;
    const runtimeConfirmed = allPackages.filter((p) => p.runtime_status === "confirmed").length;
    const shadow = allPackages.filter((p) => p.runtime_status === "shadow").length;
    const copyleft = allPackages.filter((p) => {
      const l = (p.license || "").toUpperCase();
      return l.includes("GPL") || l.includes("AGPL");
    }).length;
    const licCounts = allPackages.reduce<Record<string, number>>((acc, p) => {
      const l = p.license || "Unknown";
      acc[l] = (acc[l] || 0) + 1;
      return acc;
    }, {});
    return { total: allPackages.length, outdated, withVulns, reachable, runtimeConfirmed, shadow, copyleft, licenses: Object.keys(licCounts).length };
  }, [allPackages]);

  const licenseChartData = useMemo(() => {
    const counts = allPackages.reduce<Record<string, number>>((acc, p) => {
      const l = p.license || "Unknown";
      const key = LICENSE_TYPES.find((t) => l.toUpperCase().includes(t.toUpperCase())) || "Unknown";
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    return LICENSE_TYPES.map((type, i) => ({
      name: type,
      value: counts[type] || 0,
      fill: LICENSE_COLORS[i],
    })).filter((d) => d.value > 0);
  }, [allPackages]);

  const outdatedPackages = useMemo(() => allPackages.filter((p) => p.outdated), [allPackages]);

  // Build a simple dep tree from packages
  const depTree = useMemo<Dependency[]>(() => {
    const ecosystemGroups = allPackages.reduce<Record<string, SbomPackage[]>>((acc, p) => {
      const eco = p.ecosystem || p.language || "unknown";
      if (!acc[eco]) acc[eco] = [];
      if (acc[eco].length < 5) acc[eco].push(p);
      return acc;
    }, {});
    return Object.entries(ecosystemGroups).slice(0, 5).map(([eco, pkgs]) => ({
      name: eco,
      version: `${pkgs.length} packages`,
      children: pkgs.slice(0, 4).map((p) => ({ name: p.name || "—", version: p.version })),
    }));
  }, [allPackages]);

  if (query.isLoading || appsQuery.isLoading) {
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

  if (query.isError) {
    return <ErrorState message="Failed to load SBOM data." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="XBOM — Extended Bill of Materials" description="Runtime-correlated SBOM with reachability analysis, shadow dependency detection, and license compliance">
        <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        <Button variant="outline" size="sm" className="gap-2">
          <Download className="h-4 w-4" /> Export SBOM
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-8 gap-3">
        <KpiCard title="Total Packages" value={stats.total} icon={Package} />
        <KpiCard title="Vulnerable" value={stats.withVulns} icon={ShieldAlert} className="border-red-500/20" onClick={() => setRiskFilter(riskFilter === "vulnerable" ? "all" : "vulnerable")} />
        <KpiCard title="Reachable" value={stats.reachable} icon={Zap} className="border-orange-500/20" onClick={() => setRiskFilter(riskFilter === "reachable" ? "all" : "reachable")} />
        <KpiCard title="Shadow Deps" value={stats.shadow} icon={Ghost} className="border-purple-500/20" onClick={() => setRiskFilter(riskFilter === "shadow" ? "all" : "shadow")} />
        <KpiCard title="Runtime Confirmed" value={stats.runtimeConfirmed} icon={Activity} className="border-green-500/20" />
        <KpiCard title="Copyleft Risk" value={stats.copyleft} icon={Scale} className="border-red-500/20" onClick={() => setRiskFilter(riskFilter === "copyleft" ? "all" : "copyleft")} />
        <KpiCard title="Outdated" value={stats.outdated} icon={AlertTriangle} className="border-yellow-500/20" onClick={() => setRiskFilter(riskFilter === "outdated" ? "all" : "outdated")} />
        <KpiCard title="Unique Licenses" value={stats.licenses} icon={FileText} />
      </div>

      {/* Shadow Dependency Alert */}
      {stats.shadow > 0 && (
        <Alert className="border-purple-500/30 bg-purple-500/5">
          <Ghost className="h-4 w-4 text-purple-400" />
          <AlertDescription className="text-sm">
            <span className="font-semibold text-purple-400">{stats.shadow} shadow dependencies</span> detected —
            packages running at runtime but NOT declared in your SBOM. This is a supply chain blind spot.{" "}
            <Button variant="link" className="h-auto p-0 text-purple-400 text-sm" onClick={() => setRiskFilter("shadow")}>View shadow deps →</Button>
          </AlertDescription>
        </Alert>
      )}

      {/* Outdated Alert */}
      {outdatedPackages.length > 0 && (
        <Alert className="border-yellow-500/30 bg-yellow-500/5">
          <AlertTriangle className="h-4 w-4 text-yellow-400" />
          <AlertDescription className="text-sm">
            <span className="font-semibold text-yellow-400">{outdatedPackages.length} outdated packages</span> detected.
            Outdated packages may contain known vulnerabilities.{" "}
            <Button variant="link" className="h-auto p-0 text-yellow-400 text-sm" onClick={() => setRiskFilter("outdated")}>View all →</Button>
          </AlertDescription>
        </Alert>
      )}

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="sbom" className="gap-1.5">
            <FileText className="h-3.5 w-3.5" /> SBOM
          </TabsTrigger>
          <TabsTrigger value="inventory" className="gap-1.5">
            <Server className="h-3.5 w-3.5" /> Asset Inventory
          </TabsTrigger>
          <TabsTrigger value="dependencies" className="gap-1.5">
            <Layers className="h-3.5 w-3.5" /> Dependencies
          </TabsTrigger>
          <TabsTrigger value="licenses" className="gap-1.5">
            <Scale className="h-3.5 w-3.5" /> Licenses
          </TabsTrigger>
        </TabsList>

        {/* SBOM Tab */}
        <TabsContent value="sbom" className="mt-4 space-y-4">
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search package name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={ecosystemFilter} onValueChange={setEcosystemFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Ecosystem" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Ecosystems</SelectItem>
                {ecosystems.map((e) => (
                  <SelectItem key={e} value={e!}>{e}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={licenseFilter} onValueChange={setLicenseFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="License" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Licenses</SelectItem>
                {LICENSE_TYPES.map((l) => (
                  <SelectItem key={l} value={l}>{l}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Risk Filter" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk Levels</SelectItem>
                <SelectItem value="vulnerable">Vulnerable</SelectItem>
                <SelectItem value="reachable">Reachable</SelectItem>
                <SelectItem value="shadow">Shadow Deps</SelectItem>
                <SelectItem value="copyleft">Copyleft</SelectItem>
                <SelectItem value="outdated">Outdated</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">{filteredPackages.length} packages</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Package</TableHead>
                    <TableHead>Version</TableHead>
                    <TableHead>Ecosystem</TableHead>
                    <TableHead>License</TableHead>
                    <TableHead className="text-center">Runtime</TableHead>
                    <TableHead className="text-center">Reachability</TableHead>
                    <TableHead className="text-right">Vulns</TableHead>
                    <TableHead className="text-center">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredPackages.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-12 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <Package className="h-8 w-8 opacity-30" />
                          <p>No packages found{riskFilter !== "all" ? ` matching "${riskFilter}" filter` : ""}</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredPackages.map((pkg, idx) => {
                      const vulnCount = pkg.vulnerabilities || pkg.vuln_count || 0;
                      return (
                        <TableRow key={pkg.id || String(idx)} className="hover:bg-muted/40">
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-semibold">{pkg.name || "—"}</span>
                              {pkg.depth !== undefined && pkg.depth > 0 && (
                                <TooltipProvider>
                                  <Tooltip>
                                    <TooltipTrigger>
                                      <Badge variant="outline" className="text-[9px] px-1">{`d${pkg.depth}`}</Badge>
                                    </TooltipTrigger>
                                    <TooltipContent>Transitive dependency (depth {pkg.depth})</TooltipContent>
                                  </Tooltip>
                                </TooltipProvider>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">{pkg.version || "—"}</TableCell>
                          <TableCell>
                            <EcoBadge ecosystem={pkg.ecosystem || pkg.language} />
                          </TableCell>
                          <TableCell>
                            <LicenseBadge license={pkg.license} />
                          </TableCell>
                          <TableCell className="text-center">
                            <RuntimeStatusBadge status={pkg.runtime_status} />
                          </TableCell>
                          <TableCell className="text-center">
                            <ReachBadge reachable={pkg.reachable} direct={pkg.direct} />
                          </TableCell>
                          <TableCell className="text-right">
                            {vulnCount > 0 ? (
                              <span
                                className="text-red-400 font-mono font-bold text-sm cursor-pointer hover:underline"
                                onClick={() => navigate(`/discover?search=${encodeURIComponent(pkg.name || "")}`)}
                                role="button"
                                tabIndex={0}
                                onKeyDown={(e) => e.key === "Enter" && navigate(`/discover?search=${encodeURIComponent(pkg.name || "")}`)}
                              >
                                {vulnCount}
                              </span>
                            ) : (
                              <span className="text-green-400 font-mono text-xs">0</span>
                            )}
                          </TableCell>
                          <TableCell className="text-center">
                            {pkg.outdated ? (
                              <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/20 text-[10px] border">
                                {pkg.latest_version ? `→ ${pkg.latest_version}` : "Outdated"}
                              </Badge>
                            ) : (
                              <CheckCircle className="h-3.5 w-3.5 text-green-400 mx-auto" />
                            )}
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
        </TabsContent>

        {/* Asset Inventory Tab */}
        <TabsContent value="inventory" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">{assets.length} assets</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead>Last Scanned</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-12 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <Server className="h-8 w-8 opacity-30" />
                          <p>No assets found</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    assets.map((asset, idx) => (
                      <TableRow key={asset.id || String(idx)} className="hover:bg-muted/40">
                        <TableCell className="font-medium text-sm">{asset.name || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">{asset.type || "—"}</Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{asset.owner || "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {asset.last_scanned ? new Date(asset.last_scanned).toLocaleDateString() : "—"}
                        </TableCell>
                        <TableCell>
                          <Badge className={cn("border text-xs",
                            asset.status === "active" ? "bg-green-500/10 text-green-400 border-green-500/20" : "bg-slate-500/10 text-slate-400 border-slate-500/20"
                          )}>{asset.status || "—"}</Badge>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Dependencies Tab */}
        <TabsContent value="dependencies" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-primary" />
                Dependency Tree
              </CardTitle>
            </CardHeader>
            <CardContent>
              {depTree.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Layers className="h-8 w-8 opacity-30 mx-auto mb-2" />
                  <p>No dependency data available</p>
                </div>
              ) : (
                <DependencyTree deps={depTree} />
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Licenses Tab */}
        <TabsContent value="licenses" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">License Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                {licenseChartData.length === 0 ? (
                  <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                    No license data available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={240}>
                    <PieChart>
                      <Pie
                        data={licenseChartData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={90}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={false}
                      >
                        {licenseChartData.map((entry, i) => (
                          <Cell key={i} fill={entry.fill} />
                        ))}
                      </Pie>
                      <RechartsTooltip
                        contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">License Summary</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {licenseChartData.map((entry) => (
                  <div key={entry.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full" style={{ background: entry.fill }} />
                      <LicenseBadge license={entry.name} />
                    </div>
                    <span className="font-mono text-sm font-bold">{entry.value}</span>
                  </div>
                ))}
                <Separator />
                {licenseChartData.some((e) => e.name.toUpperCase().includes("GPL")) && (
                  <div className="flex items-start gap-2 p-2 bg-red-500/5 border border-red-500/20 rounded-md">
                    <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                    <p className="text-xs text-red-400">
                      GPL-licensed packages detected. Review for license compliance implications.
                    </p>
                  </div>
                )}
                {licenseChartData.some((e) => e.name === "Unknown") && (
                  <div className="flex items-start gap-2 p-2 bg-yellow-500/5 border border-yellow-500/20 rounded-md">
                    <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
                    <p className="text-xs text-yellow-400">
                      Unknown licenses require manual review before distribution.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
