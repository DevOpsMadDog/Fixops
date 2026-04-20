/**
 * Supply Chain Security Dashboard
 *
 * SBOM analysis, dependency risk, license compliance, transitive dependencies.
 * Route: /supply-chain
 *
 * API: GET /api/v1/supply-chain/risk-summary
 *      GET /api/v1/supply-chain/dependencies
 * Falls back to mock data on failure.
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Package,
  AlertTriangle,
  TrendingUp,
  Shield,
  FileText,
  Filter,
  Search,
  ChevronRight,
  Clock,
  GitBranch,
  Lock,
  ExternalLink,
  Zap,
  Eye,
  X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type RiskLevel = "critical" | "high" | "medium" | "low";
type Ecosystem = "npm" | "PyPI" | "Maven" | "RubyGems" | "NuGet" | "Composer";
type LicenseStatus = "permissive" | "commercial" | "restricted" | "unknown";

interface Dependency {
  id: string;
  package: string;
  version: string;
  ecosystem: Ecosystem;
  critical_vulns: number;
  high_vulns: number;
  license: string;
  license_status: LicenseStatus;
  source: string;
  risk_score: number;
  last_updated: string;
  transitive_deps: number;
  maintainer_trust: "high" | "medium" | "low" | "unknown";
}

interface TransitiveDep {
  name: string;
  version: string;
  depth: number;
}

interface SupplyChainSummary {
  total_dependencies: number;
  critical_vulns: number;
  untrusted_sources: number;
  license_issues: number;
  sbom_format: string;
  last_scan_date: string;
  components_scanned: number;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_SUMMARY: SupplyChainSummary = {
  total_dependencies: 842,
  critical_vulns: 7,
  untrusted_sources: 3,
  license_issues: 12,
  sbom_format: "SPDX 2.3 + CycloneDX 1.4",
  last_scan_date: "2 hours ago",
  components_scanned: 1247,
};

const MOCK_DEPENDENCIES: Dependency[] = [
  {
    id: "d1",
    package: "log4j-core",
    version: "2.14.1",
    ecosystem: "Maven",
    critical_vulns: 3,
    high_vulns: 2,
    license: "Apache 2.0",
    license_status: "permissive",
    source: "Maven Central",
    risk_score: 92,
    last_updated: "2024-01-15",
    transitive_deps: 8,
    maintainer_trust: "high",
  },
  {
    id: "d2",
    package: "lodash",
    version: "4.17.20",
    ecosystem: "npm",
    critical_vulns: 2,
    high_vulns: 4,
    license: "MIT",
    license_status: "permissive",
    source: "npm",
    risk_score: 85,
    last_updated: "2023-06-12",
    transitive_deps: 0,
    maintainer_trust: "high",
  },
  {
    id: "d3",
    package: "jackson-databind",
    version: "2.13.0",
    ecosystem: "Maven",
    critical_vulns: 1,
    high_vulns: 3,
    license: "Apache 2.0",
    license_status: "permissive",
    source: "Maven Central",
    risk_score: 79,
    last_updated: "2024-02-20",
    transitive_deps: 12,
    maintainer_trust: "high",
  },
  {
    id: "d4",
    package: "requests",
    version: "2.25.1",
    ecosystem: "PyPI",
    critical_vulns: 0,
    high_vulns: 1,
    license: "Apache 2.0",
    license_status: "permissive",
    source: "PyPI",
    risk_score: 42,
    last_updated: "2024-03-01",
    transitive_deps: 4,
    maintainer_trust: "high",
  },
  {
    id: "d5",
    package: "underscore",
    version: "1.13.2",
    ecosystem: "npm",
    critical_vulns: 1,
    high_vulns: 0,
    license: "MIT",
    license_status: "permissive",
    source: "npm",
    risk_score: 38,
    last_updated: "2024-01-08",
    transitive_deps: 0,
    maintainer_trust: "high",
  },
  {
    id: "d6",
    package: "ckeditor-malware-pkg",
    version: "1.0.0",
    ecosystem: "npm",
    critical_vulns: 2,
    high_vulns: 1,
    license: "Unknown",
    license_status: "unknown",
    source: "typosquat/malicious npm",
    risk_score: 88,
    last_updated: "2024-04-10",
    transitive_deps: 1,
    maintainer_trust: "low",
  },
  {
    id: "d7",
    package: "pycryptodome",
    version: "3.17.0",
    ecosystem: "PyPI",
    critical_vulns: 0,
    high_vulns: 2,
    license: "BSD 2-Clause",
    license_status: "restricted",
    source: "PyPI",
    risk_score: 52,
    last_updated: "2024-03-15",
    transitive_deps: 3,
    maintainer_trust: "high",
  },
  {
    id: "d8",
    package: "moment",
    version: "2.29.1",
    ecosystem: "npm",
    critical_vulns: 0,
    high_vulns: 0,
    license: "MIT",
    license_status: "permissive",
    source: "npm",
    risk_score: 18,
    last_updated: "2024-03-20",
    transitive_deps: 0,
    maintainer_trust: "high",
  },
];

const MOCK_TREE: TransitiveDep[] = [
  { name: "flask", version: "2.3.0", depth: 0 },
  { name: "werkzeug", version: "2.3.0", depth: 1 },
  { name: "click", version: "8.1.0", depth: 2 },
  { name: "itsdangerous", version: "2.1.0", depth: 2 },
  { name: "jinja2", version: "3.1.0", depth: 1 },
  { name: "markupsafe", version: "2.1.0", depth: 2 },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function riskColor(score: number): string {
  if (score >= 80) return "text-red-400 bg-red-500/10";
  if (score >= 60) return "text-orange-400 bg-orange-500/10";
  if (score >= 40) return "text-yellow-400 bg-yellow-500/10";
  return "text-green-400 bg-green-500/10";
}

function riskLabel(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

function licenseColor(status: LicenseStatus): string {
  switch (status) {
    case "permissive":
      return "text-green-400 bg-green-500/10";
    case "commercial":
      return "text-blue-400 bg-blue-500/10";
    case "restricted":
      return "text-orange-400 bg-orange-500/10";
    default:
      return "text-muted-foreground bg-muted";
  }
}

// ═══════════════════════════════════════════════════════════
// Dependency Risk Heatmap
// ═══════════════════════════════════════════════════════════

function DependencyHeatmap({ deps }: { deps: Dependency[] }) {
  const grid = deps.slice(0, 12);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Package className="w-4 h-4" />
          Dependency Risk Heatmap
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-6 gap-1.5">
          {grid.map((dep) => (
            <motion.div
              key={dep.id}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              whileHover={{ scale: 1.05 }}
              className={cn(
                "h-12 rounded flex items-center justify-center cursor-pointer transition-all",
                "border border-border/50 hover:border-border",
                dep.risk_score >= 80
                  ? "bg-red-500/20"
                  : dep.risk_score >= 60
                  ? "bg-orange-500/20"
                  : dep.risk_score >= 40
                  ? "bg-yellow-500/20"
                  : "bg-green-500/20"
              )}
              title={`${dep.package} (${dep.risk_score})`}
            >
              <span className="text-xs font-bold text-center">{dep.risk_score}</span>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// High Risk Dependencies Table
// ═══════════════════════════════════════════════════════════

function DependenciesTable({ deps, onSelectDep }: { deps: Dependency[]; onSelectDep: (dep: Dependency) => void }) {
  const [search, setSearch] = useState("");
  const [ecosystem, setEcosystem] = useState<Ecosystem | "all">("all");

  const filtered = useMemo(() => {
    return deps.filter((d) => {
      const matchSearch =
        d.package.toLowerCase().includes(search.toLowerCase()) ||
        d.license.toLowerCase().includes(search.toLowerCase());
      const matchEcosystem = ecosystem === "all" || d.ecosystem === ecosystem;
      return matchSearch && matchEcosystem;
    });
  }, [deps, search, ecosystem]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            High Risk Dependencies
          </CardTitle>
          <Badge variant="secondary">{filtered.length} items</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Search & Filter */}
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search packages..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8"
            />
          </div>
          <Select value={ecosystem} onValueChange={(v) => setEcosystem(v as Ecosystem | "all")}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="npm">npm</SelectItem>
              <SelectItem value="PyPI">PyPI</SelectItem>
              <SelectItem value="Maven">Maven</SelectItem>
              <SelectItem value="RubyGems">RubyGems</SelectItem>
              <SelectItem value="NuGet">NuGet</SelectItem>
              <SelectItem value="Composer">Composer</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Table */}
        <ScrollArea className="border rounded-lg">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/50 bg-muted/30">
                <th className="px-4 py-2 text-left font-semibold">Package</th>
                <th className="px-4 py-2 text-left font-semibold">Ecosystem</th>
                <th className="px-4 py-2 text-center font-semibold">Vulns</th>
                <th className="px-4 py-2 text-left font-semibold">License</th>
                <th className="px-4 py-2 text-left font-semibold">Source</th>
                <th className="px-4 py-2 text-left font-semibold">Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((dep) => (
                <motion.tr
                  key={dep.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="border-b border-border/30 hover:bg-muted/40 transition-colors cursor-pointer"
                  onClick={() => onSelectDep(dep)}
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Package className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <div>
                        <p className="font-medium">{dep.package}</p>
                        <p className="text-xs text-muted-foreground">{dep.version}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className="text-xs">
                      {dep.ecosystem}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <div className="flex gap-1 justify-center">
                      {dep.critical_vulns > 0 && (
                        <Badge variant="critical" className="text-[10px]">
                          {dep.critical_vulns}C
                        </Badge>
                      )}
                      {dep.high_vulns > 0 && (
                        <Badge variant="high" className="text-[10px]">
                          {dep.high_vulns}H
                        </Badge>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge className={cn("text-xs", licenseColor(dep.license_status))}>
                      {dep.license}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn("text-xs", dep.source.includes("malicious") ? "text-red-400" : "text-muted-foreground")}>
                      {dep.source.length > 20 ? `${dep.source.slice(0, 17)}...` : dep.source}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-12 rounded-full bg-muted overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${dep.risk_score}%` }}
                          transition={{ delay: 0.1, duration: 0.5 }}
                          className={cn(
                            "h-full rounded-full",
                            dep.risk_score >= 80
                              ? "bg-red-400"
                              : dep.risk_score >= 60
                              ? "bg-orange-400"
                              : dep.risk_score >= 40
                              ? "bg-yellow-400"
                              : "bg-green-400"
                          )}
                        />
                      </div>
                      <span className={cn("text-xs font-semibold", riskColor(dep.risk_score).split(" ")[0])}>
                        {dep.risk_score}
                      </span>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// SBOM Overview
// ═══════════════════════════════════════════════════════════

function SBOMOverview({ summary }: { summary: SupplyChainSummary }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="w-4 h-4" />
          SBOM Overview
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-3 rounded border border-border/50 bg-muted/20">
            <div>
              <p className="text-xs text-muted-foreground font-medium">Components Scanned</p>
              <p className="text-2xl font-bold">{summary.components_scanned.toLocaleString()}</p>
            </div>
            <Package className="w-8 h-8 text-muted-foreground" />
          </div>
          <div className="flex items-center justify-between p-3 rounded border border-border/50 bg-muted/20">
            <div>
              <p className="text-xs text-muted-foreground font-medium">Last Scan</p>
              <p className="text-lg font-semibold">{summary.last_scan_date}</p>
            </div>
            <Clock className="w-8 h-8 text-muted-foreground" />
          </div>
        </div>
        <Separator />
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-2">Formats Supported</p>
          <div className="flex flex-wrap gap-2">
            {summary.sbom_format.split("+").map((fmt) => (
              <Badge key={fmt} variant="secondary" className="text-xs">
                {fmt.trim()}
              </Badge>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Transitive Dependency Tree
// ═══════════════════════════════════════════════════════════

function TransitiveDependencyTree() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <GitBranch className="w-4 h-4" />
          Transitive Dependency Tree
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-64">
          <div className="space-y-1 pr-4 font-mono text-sm">
            {MOCK_TREE.map((dep, idx) => (
              <motion.div
                key={`${dep.name}-${idx}`}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.05 }}
                className="text-muted-foreground"
              >
                <span style={{ marginLeft: `${dep.depth * 24}px` }}>
                  {dep.depth > 0 ? "├── " : ""}
                  <span className="text-foreground">{dep.name}</span>
                  <span className="text-xs ml-1">@{dep.version}</span>
                </span>
              </motion.div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// License Compliance Donut
// ═══════════════════════════════════════════════════════════

function LicenseCompliance({ deps }: { deps: Dependency[] }) {
  const permissive = deps.filter((d) => d.license_status === "permissive").length;
  const commercial = deps.filter((d) => d.license_status === "commercial").length;
  const restricted = deps.filter((d) => d.license_status === "restricted").length;
  const unknown = deps.filter((d) => d.license_status === "unknown").length;
  const total = deps.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lock className="w-4 h-4" />
          License Compliance
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-center h-40">
          {/* Simple colored donut representation */}
          <div className="relative w-32 h-32">
            <div className="absolute inset-0 rounded-full border-8 border-green-500/20" />
            <div
              className="absolute inset-0 rounded-full border-8"
              style={{
                background: `conic-gradient(
                  rgb(34, 197, 94) 0deg ${(permissive / total) * 360}deg,
                  rgb(59, 130, 246) ${(permissive / total) * 360}deg ${((permissive + commercial) / total) * 360}deg,
                  rgb(249, 115, 22) ${((permissive + commercial) / total) * 360}deg ${((permissive + commercial + restricted) / total) * 360}deg,
                  rgb(107, 114, 128) ${((permissive + commercial + restricted) / total) * 360}deg 360deg
                )`,
              }}
            >
              <div className="absolute inset-2 rounded-full bg-card flex items-center justify-center">
                <span className="text-xs font-bold text-center">{total}</span>
              </div>
            </div>
          </div>
        </div>
        <Separator />
        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500" />
            <span>Permissive: {permissive}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-blue-500" />
            <span>Commercial: {commercial}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-orange-500" />
            <span>Restricted: {restricted}</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-gray-500" />
            <span>Unknown: {unknown}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Recent Supply Chain Events
// ═══════════════════════════════════════════════════════════

const EVENTS = [
  { time: "2 hours ago", event: "Log4j v2.17.1 critical CVE disclosed", type: "critical", icon: AlertTriangle },
  { time: "5 hours ago", event: "License violation detected in 3 deps", type: "warning", icon: AlertTriangle },
  { time: "12 hours ago", event: "Typosquatting attack: ckeditor-malware-pkg added to npm", type: "critical", icon: Shield },
  { time: "1 day ago", event: "Jackson-databind updated to v2.15.2", type: "info", icon: TrendingUp },
  { time: "2 days ago", event: "Supply chain audit completed (7 deps flagged)", type: "warning", icon: FileText },
];

function RecentEvents() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Zap className="w-4 h-4" />
          Recent Supply Chain Events
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-64">
          <div className="space-y-3 pr-4">
            {EVENTS.map((item, idx) => {
              const EventIcon = item.icon;
              const bgColor =
                item.type === "critical"
                  ? "bg-red-500/10 border-red-500/30"
                  : item.type === "warning"
                  ? "bg-orange-500/10 border-orange-500/30"
                  : "bg-blue-500/10 border-blue-500/30";

              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  className={cn("p-3 rounded border", bgColor)}
                >
                  <div className="flex gap-3">
                    <EventIcon className={cn(
                      "w-4 h-4 mt-0.5 shrink-0",
                      item.type === "critical" ? "text-red-400" : item.type === "warning" ? "text-orange-400" : "text-blue-400"
                    )} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">{item.event}</p>
                      <p className="text-xs text-muted-foreground mt-1">{item.time}</p>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function SupplyChainSecurity() {
  const [selectedDep, setSelectedDep] = useState<Dependency | null>(null);

  // Fetch from API (falls back to mock)
  const { data: summary = MOCK_SUMMARY } = useQuery({
    queryKey: ["supply-chain-summary"],
    queryFn: async () => {
      try {
        const res = await fetch(`${API}/api/v1/supply-chain/risk-summary?org_id=default`);
        if (!res.ok) throw new Error("Failed to fetch");
        return res.json();
      } catch {
        return MOCK_SUMMARY;
      }
    },
    staleTime: 5 * 60 * 1000,
  });

  const { data: dependencies = MOCK_DEPENDENCIES } = useQuery({
    queryKey: ["supply-chain-dependencies"],
    queryFn: async () => {
      try {
        const res = await fetch(`${API}/api/v1/supply-chain/dependencies?org_id=default`);
        if (!res.ok) throw new Error("Failed to fetch");
        return res.json();
      } catch {
        return MOCK_DEPENDENCIES;
      }
    },
    staleTime: 5 * 60 * 1000,
  });

  const sortedDeps = [...dependencies].sort((a, b) => b.risk_score - a.risk_score);

  return (
    <div className="flex h-full overflow-hidden">
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <PageHeader
          title="Supply Chain Security"
          subtitle="SBOM analysis and dependency risk"
          icon={Package}
        />

        {/* Content */}
        <ScrollArea className="flex-1">
          <div className="p-6 space-y-6">
            {/* KPI Stats */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <KpiCard
                icon={Package}
                title="Total Dependencies"
                value={summary.total_dependencies}
                trend={{ value: 12, direction: "up" }}
              />
              <KpiCard
                icon={AlertTriangle}
                title="Critical Vulns in Deps"
                value={summary.critical_vulns}
                valueColor="text-red-400"
              />
              <KpiCard
                icon={Shield}
                title="Untrusted Sources"
                value={summary.untrusted_sources}
                valueColor="text-orange-400"
              />
              <KpiCard
                icon={Lock}
                title="License Issues"
                value={summary.license_issues}
                valueColor="text-yellow-400"
              />
            </div>

            {/* Heatmap */}
            <DependencyHeatmap deps={sortedDeps} />

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Dependencies Table (2 columns) */}
              <div className="lg:col-span-2">
                <DependenciesTable deps={sortedDeps} onSelectDep={setSelectedDep} />
              </div>

              {/* Right Sidebar */}
              <div className="space-y-6">
                <SBOMOverview summary={summary} />
                <LicenseCompliance deps={dependencies} />
              </div>
            </div>

            {/* Tree + Events */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <TransitiveDependencyTree />
              <RecentEvents />
            </div>
          </div>
        </ScrollArea>
      </div>

      {/* Detail Panel */}
      <AnimatePresence>
        {selectedDep && (
          <motion.div
            initial={{ opacity: 0, x: 32 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 32 }}
            transition={{ duration: 0.25 }}
            className="w-80 shrink-0 border-l border-border bg-card flex flex-col overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="min-w-0">
                <p className="text-sm font-semibold truncate">{selectedDep.package}</p>
                <p className="text-xs text-muted-foreground">{selectedDep.ecosystem}</p>
              </div>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 w-7 p-0 shrink-0"
                onClick={() => setSelectedDep(null)}
              >
                <X className="w-4 h-4" />
              </Button>
            </div>

            <ScrollArea className="flex-1">
              <div className="px-5 py-4 space-y-5">
                {/* Risk Score */}
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2">
                    Risk Score
                  </p>
                  <div className="flex items-center gap-3">
                    <span className={cn("text-3xl font-bold", riskColor(selectedDep.risk_score).split(" ")[0])}>
                      {selectedDep.risk_score}
                    </span>
                    <Badge className={cn("text-xs border-0", riskColor(selectedDep.risk_score))}>
                      {riskLabel(selectedDep.risk_score)}
                    </Badge>
                  </div>
                  <div className="mt-2 h-1.5 rounded-full bg-muted overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${selectedDep.risk_score}%` }}
                      transition={{ delay: 0.1, duration: 0.5 }}
                      className={cn(
                        "h-full rounded-full",
                        selectedDep.risk_score >= 80
                          ? "bg-red-400"
                          : selectedDep.risk_score >= 60
                          ? "bg-orange-400"
                          : selectedDep.risk_score >= 40
                          ? "bg-yellow-400"
                          : "bg-green-400"
                      )}
                    />
                  </div>
                </div>

                <Separator />

                {/* Vulnerabilities */}
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2.5">
                    Vulnerabilities
                  </p>
                  <dl className="space-y-2">
                    <div className="flex items-center justify-between">
                      <dt className="text-xs text-muted-foreground">Critical</dt>
                      <dd className={cn("text-xs font-bold", selectedDep.critical_vulns > 0 ? "text-red-400" : "text-green-400")}>
                        {selectedDep.critical_vulns}
                      </dd>
                    </div>
                    <div className="flex items-center justify-between">
                      <dt className="text-xs text-muted-foreground">High</dt>
                      <dd className={cn("text-xs font-bold", selectedDep.high_vulns > 0 ? "text-orange-400" : "text-green-400")}>
                        {selectedDep.high_vulns}
                      </dd>
                    </div>
                  </dl>
                </div>

                <Separator />

                {/* Details */}
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-2.5">
                    Details
                  </p>
                  <dl className="space-y-2">
                    {[
                      { label: "Version", value: selectedDep.version },
                      { label: "License", value: selectedDep.license },
                      { label: "Source", value: selectedDep.source },
                      { label: "Last Updated", value: selectedDep.last_updated },
                      { label: "Transitive Deps", value: selectedDep.transitive_deps.toString() },
                      { label: "Maintainer Trust", value: selectedDep.maintainer_trust },
                    ].map(({ label, value }) => (
                      <div key={label} className="flex items-start justify-between gap-2">
                        <dt className="text-xs text-muted-foreground shrink-0">{label}</dt>
                        <dd className="text-xs text-right font-medium truncate">{value}</dd>
                      </div>
                    ))}
                  </dl>
                </div>

                <Separator />

                {/* Actions */}
                <div className="space-y-2">
                  <Button className="w-full" variant="outline" size="sm" onClick={() => window.open("https://registry.npmjs.org", "_blank", "noopener,noreferrer")}>
                    <ExternalLink className="w-3.5 h-3.5 mr-2" />
                    View on Source Registry
                  </Button>
                  <Button className="w-full" variant="outline" size="sm" onClick={() => alert("Security issue report submitted.")}>
                    <AlertTriangle className="w-3.5 h-3.5 mr-2" />
                    Report Security Issue
                  </Button>
                </div>
              </div>
            </ScrollArea>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
