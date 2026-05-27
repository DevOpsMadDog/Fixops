import { useState, useCallback, useMemo } from "react";
import { motion } from "framer-motion";
import {
  Cloud, RefreshCw, Download, AlertTriangle, CheckCircle,
  Globe, Shield, Activity, Server, Cpu,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
// useFindings removed — CloudPosture now fetches /api/v1/cloud-posture/findings directly
import { buildApiUrl, getStoredAuthToken } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { cn } from "@/lib/utils";

// ── Compliance frameworks from real engine ────────────────────
interface ComplianceFramework {
  framework: string;
  enabled: boolean;
  total_controls: number;
  automated_controls: number;
}

async function fetchComplianceFrameworks(): Promise<ComplianceFramework[]> {
  const url = buildApiUrl("/api/v1/compliance-engine/frameworks");
  const key = getStoredAuthToken();
  const r = await fetch(url, { headers: { "X-API-Key": key } });
  if (!r.ok) throw new Error(`${r.status}`);
  const d = await r.json() as { frameworks?: ComplianceFramework[] } | ComplianceFramework[];
  return Array.isArray(d) ? d : (d.frameworks ?? []);
}

// ── Cloud posture findings from dedicated endpoint ────────────
interface CloudPostureFinding {
  id: string;
  resource_id: string;
  resource_type: string;
  provider: string;
  severity: string;
  title: string;
  status: string;
  detected_at: string;
  cloud_account_id?: string;
}

async function fetchCloudPostureFindings(provider?: string, severity?: string): Promise<CloudPostureFinding[]> {
  const params: Record<string, string> = { org_id: "default" };
  if (provider && provider !== "all") params.provider = provider;
  if (severity && severity !== "all") params.severity = severity;
  const url = buildApiUrl("/api/v1/cloud-posture/findings", params);
  const key = getStoredAuthToken();
  const r = await fetch(url, { headers: { "X-API-Key": key } });
  if (!r.ok) throw new Error(`${r.status}`);
  const d = await r.json() as CloudPostureFinding[] | { findings?: CloudPostureFinding[] };
  return Array.isArray(d) ? d : (d.findings ?? []);
}
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface CloudResource {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  resource_type?: string;
  resource?: string;
  region?: string;
  provider?: string;
  cloud?: string;
  compliance_status?: string;
  risk_score?: number;
  last_scanned?: string;
  created_at?: string;
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

function ComplianceBadge({ status }: { status?: string }) {
  const s = (status || "").toLowerCase();
  const map: Record<string, string> = {
    compliant: "bg-green-500/10 text-green-400 border-green-500/20",
    non_compliant: "bg-red-500/10 text-red-400 border-red-500/20",
    partial: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    unknown: "bg-slate-500/10 text-slate-400 border-slate-500/20",
  };
  return <Badge className={cn("border text-xs", map[s] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>{status || "Unknown"}</Badge>;
}

function CloudProviderBadge({ provider }: { provider?: string }) {
  const map: Record<string, string> = {
    aws: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    azure: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    gcp: "bg-green-500/10 text-green-400 border-green-500/20",
  };
  const p = (provider || "").toLowerCase();
  return <Badge className={cn("border text-xs font-semibold", map[p] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>{provider?.toUpperCase() || "—"}</Badge>;
}

function RiskScore({ score }: { score?: number }) {
  if (!score) return <span className="text-muted-foreground text-xs">—</span>;
  const color = score >= 8 ? "text-red-400" : score >= 6 ? "text-orange-400" : score >= 4 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono font-bold text-sm", color)}>{score.toFixed(1)}</span>;
}

const REGION_COLORS = ["#3b82f6", "#8b5cf6", "#10b981", "#f59e0b", "#ef4444", "#06b6d4"];

// FRAMEWORK_DATA removed — compliance framework list is now built from
// the real /api/v1/analytics/dashboard/compliance-status response.
// Fallback display names for known framework keys (purely cosmetic).
const FRAMEWORK_DISPLAY_NAMES: Record<string, string> = {
  cis_aws:   "CIS AWS",
  cis_azure: "CIS Azure",
  cis_gcp:   "CIS GCP",
  nist:      "NIST 800-53",
  pci:       "PCI DSS",
  pci_dss:   "PCI DSS",
  soc2:      "SOC 2",
  hipaa:     "HIPAA",
  iso27001:  "ISO 27001",
};

export default function CloudPosture() {
  const [cloudTab, setCloudTab] = useState("all");
  const [regionFilter, setRegionFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");

  // ── Real cloud-posture findings ───────────────────────────
  const findingsQ = useQuery<CloudPostureFinding[]>({
    queryKey: ["cloud-posture-findings", cloudTab, severityFilter],
    queryFn: () => fetchCloudPostureFindings(
      cloudTab !== "all" ? cloudTab : undefined,
      severityFilter !== "all" ? severityFilter : undefined,
    ),
    staleTime: 30_000,
  });

  // ── Real compliance frameworks ────────────────────────────
  const frameworksQ = useQuery<ComplianceFramework[]>({
    queryKey: ["compliance-engine-frameworks"],
    queryFn: fetchComplianceFrameworks,
    staleTime: 60_000,
  });

  const refetch = useCallback(() => {
    findingsQ.refetch();
    frameworksQ.refetch();
  }, [findingsQ, frameworksQ]);

  const allResources: CloudResource[] = useMemo(() => {
    const raw = findingsQ.data ?? [];
    // Map CloudPostureFinding → CloudResource shape
    return raw.map(f => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      status: f.status,
      resource_type: f.resource_type,
      resource: f.resource_id,
      provider: f.provider,
      compliance_status: f.status === "open" ? "non_compliant" : "compliant",
      created_at: f.detected_at,
    }));
  }, [findingsQ.data]);

  const filtered = useMemo(() => {
    let list = allResources;
    if (regionFilter !== "all") list = list.filter((r) => r.region === regionFilter);
    return list;
  }, [allResources, regionFilter]);

  const regions = useMemo(() =>
    Array.from(new Set(allResources.map((r) => r.region).filter(Boolean))),
    [allResources]
  );

  const stats = useMemo(() => {
    const compliant = allResources.filter((r) => r.compliance_status?.toLowerCase() === "compliant").length;
    const pct = allResources.length > 0 ? Math.round((compliant / allResources.length) * 100) : 0;
    const critical = allResources.filter((r) => r.severity?.toLowerCase() === "critical").length;
    const regionSet = new Set(allResources.map((r) => r.region).filter(Boolean));
    return {
      total: allResources.length,
      compliantPct: pct,
      critical,
      regions: regionSet.size,
    };
  }, [allResources]);

  const regionChartData = useMemo(() => {
    // Group by provider since cloud-posture findings don't have region field
    const byProvider = allResources.reduce<Record<string, number>>((acc, r) => {
      const key = (r.provider || r.cloud || "unknown").toUpperCase();
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(byProvider).map(([region, count], i) => ({
      region,
      count,
      fill: REGION_COLORS[i % REGION_COLORS.length],
    }));
  }, [allResources]);

  // Compliance chart: built from real /api/v1/compliance-engine/frameworks
  // Shows automated_controls / total_controls as coverage %, not 0% hardcoded
  const complianceData = useMemo(() => {
    const frameworks = frameworksQ.data ?? [];
    return frameworks
      .filter(fw => fw.enabled)
      .map(fw => ({
        framework: fw.framework,
        name: FRAMEWORK_DISPLAY_NAMES[fw.framework.toLowerCase().replace(/[^a-z0-9]/g, "_")]
          ?? fw.framework.replace(/_/g, " "),
        pct: fw.total_controls > 0
          ? Math.round((fw.automated_controls / fw.total_controls) * 100)
          : 0,
      }))
      .sort((a, b) => b.pct - a.pct);
  }, [frameworksQ.data]);

  if (findingsQ.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <div className="grid grid-cols-3 gap-4">
          <Skeleton className="h-64 col-span-2" />
          <Skeleton className="h-64" />
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  if (findingsQ.isError) {
    return <ErrorState message="Failed to load cloud posture data." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Cloud Posture" description="Multi-cloud security posture management and compliance">
        <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        <Button variant="outline" size="sm" className="gap-2">
          <Download className="h-4 w-4" /> Report
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Resources Scanned" value={stats.total} icon={Server} />
        <KpiCard title="Compliant %" value={`${stats.compliantPct}%`} icon={CheckCircle} className="border-green-500/20" />
        <KpiCard title="Critical Misconfigs" value={stats.critical} icon={AlertTriangle} className="border-red-500/20" />
        <KpiCard title="Regions Monitored" value={stats.regions} icon={Globe} />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Risk by Region */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              Risk by Region
            </CardTitle>
          </CardHeader>
          <CardContent>
            {regionChartData.length === 0 ? (
              <div className="h-44 flex items-center justify-center text-muted-foreground text-sm">
                No region data available
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={regionChartData} layout="vertical" margin={{ left: 8, right: 8, top: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10 }} stroke="rgba(255,255,255,0.2)" />
                  <YAxis dataKey="region" type="category" tick={{ fontSize: 10 }} stroke="rgba(255,255,255,0.2)" width={80} />
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                    cursor={{ fill: "rgba(255,255,255,0.04)" }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {regionChartData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Compliance by Framework */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              Compliance by Framework
            </CardTitle>
            <p className="text-[10px] text-muted-foreground mt-0.5">
              Source: /api/v1/compliance-engine/frameworks — automated control coverage
            </p>
          </CardHeader>
          <CardContent className="space-y-3">
            {frameworksQ.isLoading ? (
              <div className="space-y-2">
                {[1, 2, 3, 4].map(i => <div key={i} className="h-8 rounded bg-muted/30 animate-pulse" />)}
              </div>
            ) : complianceData.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-8 text-muted-foreground">
                <CheckCircle className="h-6 w-6 opacity-30" />
                <p className="text-sm">No compliance framework data</p>
              </div>
            ) : (
              complianceData.map((fw) => (
                <div key={fw.framework}>
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-xs font-medium">{fw.name}</span>
                    <span className={cn(
                      "text-xs font-bold font-mono",
                      fw.pct >= 80 ? "text-green-400" : fw.pct >= 60 ? "text-yellow-400" : "text-red-400"
                    )}>{fw.pct}%</span>
                  </div>
                  <Progress value={fw.pct} className="h-1.5" />
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      {/* Multi-cloud Tabs + Resource Table */}
      <Tabs value={cloudTab} onValueChange={setCloudTab}>
        <div className="flex items-center justify-between flex-wrap gap-3">
          <TabsList>
            <TabsTrigger value="all" className="gap-1.5">
              <Cloud className="h-3.5 w-3.5" /> All
            </TabsTrigger>
            <TabsTrigger value="aws" className="gap-1.5">
              <Cpu className="h-3.5 w-3.5" /> AWS
            </TabsTrigger>
            <TabsTrigger value="azure" className="gap-1.5">
              <Cloud className="h-3.5 w-3.5" /> Azure
            </TabsTrigger>
            <TabsTrigger value="gcp" className="gap-1.5">
              <Activity className="h-3.5 w-3.5" /> GCP
            </TabsTrigger>
          </TabsList>
          <div className="flex gap-3">
            {regions.length > 0 && (
              <Select value={regionFilter} onValueChange={setRegionFilter}>
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="Region" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Regions</SelectItem>
                  {regions.map((r) => (
                    <SelectItem key={r} value={r!}>{r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {["all", "aws", "azure", "gcp"].map((tab) => (
          <TabsContent key={tab} value={tab} className="mt-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-muted-foreground">{filtered.length} resources</CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead>Resource Type</TableHead>
                      <TableHead>Resource</TableHead>
                      <TableHead>Provider</TableHead>
                      <TableHead>Region</TableHead>
                      <TableHead>Compliance</TableHead>
                      <TableHead>Risk Score</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Last Scanned</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filtered.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-12 text-muted-foreground">
                          <div className="flex flex-col items-center gap-2">
                            <CheckCircle className="h-8 w-8 opacity-30 text-green-400" />
                            <p>No cloud resources found</p>
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : (
                      filtered.map((resource, idx) => {
                        const id = resource.id || resource.finding_id || String(idx);
                        return (
                          <TableRow key={id} className="hover:bg-muted/40">
                            <TableCell className="text-xs font-medium">
                              {resource.resource_type || "—"}
                            </TableCell>
                            <TableCell className="font-mono text-xs max-w-[180px]">
                              <span className="truncate block">{resource.resource || resource.title || "—"}</span>
                            </TableCell>
                            <TableCell>
                              <CloudProviderBadge provider={resource.provider || resource.cloud} />
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {resource.region || "—"}
                            </TableCell>
                            <TableCell>
                              <ComplianceBadge status={resource.compliance_status || resource.status} />
                            </TableCell>
                            <TableCell>
                              <RiskScore score={resource.risk_score} />
                            </TableCell>
                            <TableCell>
                              <SeverityBadge severity={resource.severity} />
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                              {resource.last_scanned
                                ? new Date(resource.last_scanned).toLocaleDateString()
                                : resource.created_at
                                  ? new Date(resource.created_at).toLocaleDateString()
                                  : "—"}
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
        ))}
      </Tabs>
    </motion.div>
  );
}
