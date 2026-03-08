import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Package, Shield, AlertTriangle, FileText, ChevronRight,
  ChevronDown, RefreshCw, Download, CheckCircle2, XCircle,
  Scale, Database, Layers
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { findingsApi, scannerApi } from "@/lib/api";
import { toast } from "sonner";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend
} from "recharts";

// ── Mock Data ──────────────────────────────────────────────────────────────────
interface SBOMPackage {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  license: string;
  licenseStatus: "approved" | "review" | "blocked";
  cveCount: number;
  criticalCVEs: number;
  app: string;
  directDep: boolean;
  transitiveDeps: SBOMDep[];
}

interface SBOMDep {
  name: string;
  version: string;
  ecosystem: string;
  cveCount: number;
}

const MOCK_SBOM: SBOMPackage[] = [
  { id: "PKG-001", name: "express", version: "4.18.2", ecosystem: "npm", license: "MIT", licenseStatus: "approved", cveCount: 0, criticalCVEs: 0, app: "payment-service", directDep: true, transitiveDeps: [
    { name: "body-parser", version: "1.20.2", ecosystem: "npm", cveCount: 0 },
    { name: "accepts", version: "1.3.8", ecosystem: "npm", cveCount: 0 },
  ]},
  { id: "PKG-002", name: "log4j-core", version: "2.14.1", ecosystem: "maven", license: "Apache-2.0", licenseStatus: "approved", cveCount: 3, criticalCVEs: 2, app: "analytics-service", directDep: true, transitiveDeps: [
    { name: "log4j-api", version: "2.14.1", ecosystem: "maven", cveCount: 3 },
  ]},
  { id: "PKG-003", name: "lodash", version: "4.17.19", ecosystem: "npm", license: "MIT", licenseStatus: "approved", cveCount: 1, criticalCVEs: 0, app: "dashboard-frontend", directDep: false, transitiveDeps: [] },
  { id: "PKG-004", name: "openssl", version: "1.1.1q", ecosystem: "os", license: "OpenSSL", licenseStatus: "approved", cveCount: 4, criticalCVEs: 2, app: "auth-service", directDep: true, transitiveDeps: [] },
  { id: "PKG-005", name: "django", version: "3.2.18", ecosystem: "pypi", license: "BSD-3-Clause", licenseStatus: "approved", cveCount: 1, criticalCVEs: 0, app: "reporting-api", directDep: true, transitiveDeps: [
    { name: "sqlparse", version: "0.4.2", ecosystem: "pypi", cveCount: 0 },
    { name: "asgiref", version: "3.6.0", ecosystem: "pypi", cveCount: 0 },
  ]},
  { id: "PKG-006", name: "commons-text", version: "1.9", ecosystem: "maven", license: "Apache-2.0", licenseStatus: "approved", cveCount: 1, criticalCVEs: 1, app: "order-processor", directDep: true, transitiveDeps: [
    { name: "commons-lang3", version: "3.12.0", ecosystem: "maven", cveCount: 0 },
  ]},
  { id: "PKG-007", name: "react", version: "18.2.0", ecosystem: "npm", license: "MIT", licenseStatus: "approved", cveCount: 0, criticalCVEs: 0, app: "dashboard-frontend", directDep: true, transitiveDeps: [] },
  { id: "PKG-008", name: "libc", version: "2.31", ecosystem: "os", license: "LGPL-2.1", licenseStatus: "review", cveCount: 2, criticalCVEs: 0, app: "auth-service", directDep: false, transitiveDeps: [] },
  { id: "PKG-009", name: "ffmpeg", version: "4.4.2", ecosystem: "os", license: "GPL-2.0", licenseStatus: "blocked", cveCount: 7, criticalCVEs: 3, app: "media-processor", directDep: true, transitiveDeps: [] },
  { id: "PKG-010", name: "requests", version: "2.28.2", ecosystem: "pypi", license: "Apache-2.0", licenseStatus: "approved", cveCount: 0, criticalCVEs: 0, app: "reporting-api", directDep: true, transitiveDeps: [
    { name: "urllib3", version: "1.26.14", ecosystem: "pypi", cveCount: 1 },
    { name: "certifi", version: "2022.12.7", ecosystem: "pypi", cveCount: 0 },
  ]},
];

const LICENSE_BREAKDOWN = [
  { name: "MIT", value: 284, color: "#10b981" },
  { name: "Apache-2.0", value: 196, color: "#3b82f6" },
  { name: "BSD-3", value: 89, color: "#8b5cf6" },
  { name: "GPL-2.0", value: 23, color: "#ef4444" },
  { name: "LGPL", value: 31, color: "#f59e0b" },
  { name: "Other", value: 47, color: "#6b7280" },
];

const ASSET_INVENTORY = [
  { app: "payment-service", packages: 412, vulnerable: 14, critical: 3, ecosystem: "Node.js" },
  { app: "analytics-service", packages: 287, vulnerable: 22, critical: 5, ecosystem: "Java" },
  { app: "auth-service", packages: 156, vulnerable: 8, critical: 2, ecosystem: "Node.js" },
  { app: "reporting-api", packages: 198, vulnerable: 6, critical: 0, ecosystem: "Python" },
  { app: "order-processor", packages: 341, vulnerable: 18, critical: 4, ecosystem: "Java" },
  { app: "media-processor", packages: 94, vulnerable: 21, critical: 7, ecosystem: "C/C++" },
];

const ECOSYSTEM_ICONS: Record<string, string> = {
  npm: "⬡",
  maven: "☕",
  pypi: "🐍",
  os: "⬛",
};

export default function SBOMInventory() {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const { data: findingsData } = useQuery({
    queryKey: ["findings", "sbom"],
    queryFn: () => findingsApi.list({ type: "sbom", limit: 100 }),
  });

  const { data: scannerData } = useQuery({
    queryKey: ["scanners", "sbom"],
    queryFn: () => scannerApi.list(),
  });

  void scannerData;

  const packages: SBOMPackage[] = findingsData?.data ?? MOCK_SBOM;

  const filtered = packages.filter(
    (p) => !search || p.name.toLowerCase().includes(search.toLowerCase()) || p.app.toLowerCase().includes(search.toLowerCase())
  );

  const totalPackages = ASSET_INVENTORY.reduce((a, b) => a + b.packages, 0);
  const vulnerableCount = packages.filter((p) => p.cveCount > 0).length;
  const criticalCount = packages.filter((p) => p.criticalCVEs > 0).length;
  const blockedLicenses = packages.filter((p) => p.licenseStatus === "blocked").length;

  const licenseStatusConfig = {
    approved: { variant: "success" as const, icon: CheckCircle2, color: "text-green-400" },
    review:   { variant: "warning" as const, icon: AlertTriangle, color: "text-yellow-400" },
    blocked:  { variant: "destructive" as const, icon: XCircle, color: "text-red-400" },
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="SBOM Inventory"
        description="Software Bill of Materials — complete dependency graph with vulnerability and license compliance tracking"
        badge="SBOM"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => toast.success("SBOM exported as CycloneDX JSON")}><Download className="h-4 w-4 mr-1.5" />Export SBOM</Button>
            <Button size="sm" onClick={() => toast.success("SBOM scan queued for all apps")}><RefreshCw className="h-4 w-4 mr-1.5" />Regenerate</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Packages" value={totalPackages} change={42} trend="up" icon={Package} />
        <KpiCard title="Vulnerable Packages" value={vulnerableCount} change={-3} trend="down" icon={AlertTriangle} />
        <KpiCard title="Critical CVEs" value={criticalCount} change={1} trend="up" icon={Shield} />
        <KpiCard title="Blocked Licenses" value={blockedLicenses} trend="flat" icon={Scale} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Main SBOM table */}
        <div className="lg:col-span-3">
          <Tabs defaultValue="packages">
            <TabsList>
              <TabsTrigger value="packages">Package Tree</TabsTrigger>
              <TabsTrigger value="licenses">License Compliance</TabsTrigger>
            </TabsList>

            <TabsContent value="packages" className="mt-4 space-y-3">
              <div className="relative">
                <Package className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input placeholder="Search packages or apps..." className="pl-9" value={search} onChange={(e) => setSearch(e.target.value)} />
              </div>

              <div className="rounded-lg border border-border/50 overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/50 bg-muted/30">
                      {["Package", "Version", "Ecosystem", "License", "CVEs", "App", ""].map((h) => (
                        <th key={h} className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((pkg) => (
                      <>
                        <tr
                          key={pkg.id}
                          className="border-b border-border/30 hover:bg-muted/20 transition-colors cursor-pointer"
                          onClick={() => setExpanded(expanded === pkg.id ? null : pkg.id)}
                        >
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              {pkg.transitiveDeps.length > 0 ? (
                                expanded === pkg.id ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                              ) : <span className="w-3.5" />}
                              <span className="font-mono text-sm font-medium">{pkg.name}</span>
                              {!pkg.directDep && <Badge variant="secondary" className="text-xs">transitive</Badge>}
                            </div>
                          </td>
                          <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{pkg.version}</td>
                          <td className="px-4 py-3">
                            <span className="text-xs">
                              {ECOSYSTEM_ICONS[pkg.ecosystem] ?? "●"} {pkg.ecosystem}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-1.5">
                              <Badge variant={licenseStatusConfig[pkg.licenseStatus].variant}>
                                {pkg.license}
                              </Badge>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {pkg.cveCount > 0 ? (
                              <div className="flex items-center gap-2">
                                {pkg.criticalCVEs > 0 && <span className="text-xs font-bold text-red-400">{pkg.criticalCVEs}C</span>}
                                <span className="text-xs text-orange-400">{pkg.cveCount} total</span>
                              </div>
                            ) : (
                              <CheckCircle2 className="h-4 w-4 text-green-400" />
                            )}
                          </td>
                          <td className="px-4 py-3 text-sm">{pkg.app}</td>
                          <td className="px-4 py-3">
                            {pkg.cveCount > 0 && (
                              <Button size="sm" variant="ghost" className="text-xs" onClick={(e) => { e.stopPropagation(); toast.success(`Fix initiated for ${pkg.name}`); }}>
                                Fix
                              </Button>
                            )}
                          </td>
                        </tr>
                        {expanded === pkg.id && pkg.transitiveDeps.map((dep, di) => (
                          <tr key={`${pkg.id}-dep-${di}`} className="border-b border-border/20 bg-muted/10">
                            <td className="px-4 py-2 pl-12">
                              <span className="font-mono text-xs text-muted-foreground">↳ {dep.name}</span>
                            </td>
                            <td className="px-4 py-2 font-mono text-xs text-muted-foreground">{dep.version}</td>
                            <td className="px-4 py-2 text-xs text-muted-foreground">{dep.ecosystem}</td>
                            <td className="px-4 py-2" />
                            <td className="px-4 py-2">
                              {dep.cveCount > 0
                                ? <span className="text-xs text-orange-400">{dep.cveCount} CVEs</span>
                                : <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
                              }
                            </td>
                            <td colSpan={2} />
                          </tr>
                        ))}
                      </>
                    ))}
                  </tbody>
                </table>
              </div>
            </TabsContent>

            <TabsContent value="licenses" className="mt-4 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card>
                  <CardHeader><CardTitle className="text-base">License Distribution</CardTitle></CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie data={LICENSE_BREAKDOWN} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} paddingAngle={2}>
                          {LICENSE_BREAKDOWN.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                        <Legend iconType="circle" iconSize={8} />
                      </PieChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader><CardTitle className="text-base">License Policy Violations</CardTitle></CardHeader>
                  <CardContent className="space-y-3">
                    {packages.filter((p) => p.licenseStatus !== "approved").map((pkg) => {
                      const cfg = licenseStatusConfig[pkg.licenseStatus];
                      const Icon = cfg.icon;
                      return (
                        <div key={pkg.id} className="flex items-center justify-between p-2.5 rounded-md bg-muted/20">
                          <div className="flex items-center gap-2">
                            <Icon className={`h-4 w-4 ${cfg.color}`} />
                            <div>
                              <p className="font-mono text-sm font-medium">{pkg.name}@{pkg.version}</p>
                              <p className="text-xs text-muted-foreground">{pkg.license} · {pkg.app}</p>
                            </div>
                          </div>
                          <Badge variant={cfg.variant}>{pkg.licenseStatus}</Badge>
                        </div>
                      );
                    })}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>

        {/* Asset inventory sidebar */}
        <div>
          <Card className="sticky top-6">
            <CardHeader className="pb-3">
              <CardTitle className="text-base flex items-center gap-2">
                <Database className="h-4 w-4 text-primary" />
                Asset Inventory
              </CardTitle>
              <CardDescription>Packages per application</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {ASSET_INVENTORY.map((asset) => (
                <div key={asset.app} className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-medium">{asset.app}</p>
                      <p className="text-xs text-muted-foreground">{asset.ecosystem}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-sm font-bold">{asset.packages}</p>
                      {asset.critical > 0 && (
                        <p className="text-xs text-red-400">{asset.critical} critical</p>
                      )}
                    </div>
                  </div>
                  <div className="h-1 rounded-full bg-muted/30 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary/60"
                      style={{ width: `${(asset.packages / 412) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
              <Button size="sm" variant="outline" className="w-full mt-2" onClick={() => toast.success("Full SBOM report generated")}>
                <FileText className="h-3.5 w-3.5 mr-1.5" />View Full Report
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
