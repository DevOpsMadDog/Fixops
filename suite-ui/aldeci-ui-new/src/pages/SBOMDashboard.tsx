/**
 * SBOM Dashboard
 *
 * Software Bill of Materials — CycloneDX / SPDX lifecycle management.
 *   1. KPIs: Total Assets, Total Components, Vulnerable Components, High License Risk
 *   2. Assets table (8 rows) with export buttons (CycloneDX | SPDX)
 *   3. Vulnerability exposure panel — by severity breakdown
 *   4. License risk summary — bar chart of risk levels
 *   5. Component list for selected SBOM
 *
 * API: GET /api/v1/sbom, /api/v1/sbom/{id}/components,
 *      /api/v1/sbom/{id}/vulnerabilities, /api/v1/sbom/{id}/licenses,
 *      /api/v1/sbom/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Package, AlertTriangle, Shield, FileWarning,
  RefreshCw, Download, ChevronRight, X, BarChart3,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SBOMS = [
  { id: "SBOM-001", project_name: "ALDECI API Gateway",       asset_type: "service",       version: "v3.2.1", component_count: 312, vuln_count: 8,  last_scan: "2026-04-16 08:00", format: "cyclonedx" },
  { id: "SBOM-002", project_name: "ALDECI UI (React 19)",     asset_type: "frontend",      version: "v2.1.0", component_count: 487, vuln_count: 3,  last_scan: "2026-04-16 08:05", format: "cyclonedx" },
  { id: "SBOM-003", project_name: "TrustGraph MCP Server",    asset_type: "service",       version: "v1.4.2", component_count: 143, vuln_count: 12, last_scan: "2026-04-15 22:00", format: "spdx" },
  { id: "SBOM-004", project_name: "Suite-Core Engine",        asset_type: "library",       version: "v4.0.0", component_count: 229, vuln_count: 5,  last_scan: "2026-04-16 07:30", format: "cyclonedx" },
  { id: "SBOM-005", project_name: "Suite-Feeds (28 sources)", asset_type: "service",       version: "v1.9.3", component_count: 97,  vuln_count: 2,  last_scan: "2026-04-16 06:00", format: "spdx" },
  { id: "SBOM-006", project_name: "SwarmClaw Orchestrator",   asset_type: "infrastructure",version: "v2.3.0", component_count: 178, vuln_count: 7,  last_scan: "2026-04-15 20:00", format: "cyclonedx" },
  { id: "SBOM-007", project_name: "Docker Compose Stack",     asset_type: "container",     version: "v1.0.0", component_count: 62,  vuln_count: 19, last_scan: "2026-04-14 12:00", format: "cyclonedx" },
  { id: "SBOM-008", project_name: "Suite-Attack (MPTE)",      asset_type: "service",       version: "v1.2.1", component_count: 88,  vuln_count: 4,  last_scan: "2026-04-16 07:00", format: "spdx" },
];

const MOCK_VULN_BREAKDOWN = [
  { severity: "critical", count: 8,  color: "bg-red-500",    pct: 13 },
  { severity: "high",     count: 18, color: "bg-amber-500",  pct: 30 },
  { severity: "medium",   count: 22, color: "bg-yellow-400", pct: 37 },
  { severity: "low",      count: 12, color: "bg-blue-400",   pct: 20 },
];

const MOCK_LICENSE_BREAKDOWN = [
  { risk: "permissive", label: "Permissive (MIT/Apache/BSD)", count: 892, pct: 70, color: "bg-green-500" },
  { risk: "copyleft",   label: "Copyleft (GPL/LGPL)",         count: 178, pct: 14, color: "bg-amber-500" },
  { risk: "unknown",    label: "Unknown / No License",         count: 89,  pct: 7,  color: "bg-red-500" },
  { risk: "commercial", label: "Commercial / Proprietary",     count: 38,  pct: 3,  color: "bg-purple-500" },
  { risk: "dual",       label: "Dual-Licensed",                count: 72,  pct: 6,  color: "bg-blue-500" },
];

const MOCK_COMPONENTS: Record<string, any[]> = {
  "SBOM-001": [
    { name: "fastapi",          version: "0.110.0", license: "MIT",     vuln_count: 0, risk: "permissive" },
    { name: "pydantic",         version: "2.6.1",   license: "MIT",     vuln_count: 0, risk: "permissive" },
    { name: "uvicorn",          version: "0.27.1",  license: "BSD",     vuln_count: 0, risk: "permissive" },
    { name: "cryptography",     version: "41.0.7",  license: "Apache",  vuln_count: 3, risk: "permissive" },
    { name: "paramiko",         version: "3.4.0",   license: "LGPL",    vuln_count: 2, risk: "copyleft" },
    { name: "requests",         version: "2.31.0",  license: "Apache",  vuln_count: 1, risk: "permissive" },
    { name: "sqlalchemy",       version: "2.0.25",  license: "MIT",     vuln_count: 0, risk: "permissive" },
    { name: "python-jose",      version: "3.3.0",   license: "MIT",     vuln_count: 2, risk: "permissive" },
  ],
  "SBOM-007": [
    { name: "redis",            version: "7.2.4",   license: "BSD",     vuln_count: 4, risk: "permissive" },
    { name: "postgres",         version: "15.6",    license: "PostgreSQL", vuln_count: 1, risk: "permissive" },
    { name: "nginx",            version: "1.24.0",  license: "BSD",     vuln_count: 7, risk: "permissive" },
    { name: "python",           version: "3.11.8",  license: "PSF",     vuln_count: 3, risk: "permissive" },
    { name: "node",             version: "20.11.1", license: "MIT",     vuln_count: 4, risk: "permissive" },
  ],
};

const MOCK_STATS = {
  total_assets: 8,
  total_components: 1596,
  vulnerable_components: 60,
  high_license_risk: 127,
};

// ── Helpers ────────────────────────────────────────────────────

function AssetTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    service:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    frontend:       "border-purple-500/30 text-purple-400 bg-purple-500/10",
    library:        "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    infrastructure: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    container:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>
      {type}
    </Badge>
  );
}

function LicenseRiskBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    permissive: "border-green-500/30 text-green-400 bg-green-500/10",
    copyleft:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    unknown:    "border-red-500/30 text-red-400 bg-red-500/10",
    commercial: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    dual:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[risk] ?? "border-border")}>
      {risk}
    </Badge>
  );
}

function VulnCount({ count }: { count: number }) {
  if (count === 0) return <span className="text-xs text-green-400 font-medium">0</span>;
  const cls = count >= 10 ? "text-red-400" : count >= 5 ? "text-amber-400" : "text-yellow-400";
  return <span className={cn("text-xs font-bold tabular-nums", cls)}>{count}</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function SBOMDashboard() {
  const [sboms, setSboms] = useState<any[]>(MOCK_SBOMS);
  const [stats, setStats] = useState<any>({});
  const [selectedSbom, setSelectedSbom] = useState<any | null>(null);
  const [components, setComponents] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);

  const ORG_ID = "aldeci-demo";

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/sbom/assets?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/sbom/stats?org_id=${ORG_ID}`),
    ]).then(([assetsResult, statsResult]) => {
      if (assetsResult.status === "fulfilled") {
        const data = assetsResult.value;
        if (Array.isArray(data) && data.length > 0) setSboms(data);
        else if (Array.isArray(data?.assets) && data.assets.length > 0) setSboms(data.assets);
      }
      if (statsResult.status === "fulfilled") {
        const s = statsResult.value;
        setStats((prev) => ({
          ...prev,
          total_assets: s.total_assets ?? prev.total_assets,
          total_components: s.total_components ?? s.total_deps ?? prev.total_components,
          vulnerable_components: s.vulnerable_components ?? prev.vulnerable_components,
          high_license_risk: s.high_license_risk ?? prev.high_license_risk,
        }));
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const loadComponents = (sbom: any) => {
    setSelectedSbom(sbom);
    const mockComps = MOCK_COMPONENTS[sbom.id] || [];
    setComponents(mockComps);

    apiFetch(`/api/v1/sbom/assets/${sbom.id}/components?org_id=${ORG_ID}`).then((data) => {
      if (Array.isArray(data) && data.length > 0) setComponents(data);
      else if (Array.isArray(data?.components) && data.components.length > 0) setComponents(data.components);
    }).catch(() => {});
  };

  const handleExport = async (sbomId: string, format: string) => {
    setExporting(`${sbomId}-${format}`);
    try {
      // Use correct per-format export endpoints: /assets/{id}/export/cyclonedx or /spdx
      const endpoint = `/api/v1/sbom/assets/${sbomId}/export/${format}?org_id=${ORG_ID}`;
      const data = await apiFetch(endpoint);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sbom-${sbomId}-${format}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // Silently fail — API may not be connected
    } finally {
      setExporting(null);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const totalVulns = MOCK_VULN_BREAKDOWN.reduce((sum, v) => sum + v.count, 0);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="SBOM Dashboard"
        description="Software Bill of Materials — CycloneDX & SPDX lifecycle tracking, vulnerability exposure, and license compliance"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"          value={stats.total_assets}          icon={Package}      trend="up" />
        <KpiCard title="Total Components"      value={stats.total_components.toLocaleString()} icon={BarChart3} trend="up" className="border-blue-500/20" />
        <KpiCard title="Vulnerable Components" value={stats.vulnerable_components} icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="High License Risk"     value={stats.high_license_risk}     icon={FileWarning}  trend="down" className="border-red-500/20" />
      </div>

      {/* Assets table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Package className="h-4 w-4 text-blue-400" />
            SBOM Asset Inventory
          </CardTitle>
          <CardDescription className="text-xs">
            Click a row to view components. Use export buttons to download CycloneDX or SPDX JSON.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Components</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Vulns</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scan</TableHead>
                  <TableHead className="text-[11px] h-8">Export</TableHead>
                  <TableHead className="text-[11px] h-8 w-8"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sboms.slice(0, 8).map((s) => (
                  <TableRow
                    key={s.id}
                    className={cn("hover:bg-muted/30 cursor-pointer", selectedSbom?.id === s.id && "bg-muted/40")}
                    onClick={() => loadComponents(s)}
                  >
                    <TableCell className="py-2 text-xs font-medium max-w-[200px] truncate">{s.project_name}</TableCell>
                    <TableCell className="py-2"><AssetTypeBadge type={s.asset_type ?? s.format ?? "service"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{s.version ?? s.spec_version ?? "—"}</TableCell>
                    <TableCell className="py-2 text-center text-xs font-medium tabular-nums">{(s.component_count ?? 0).toLocaleString()}</TableCell>
                    <TableCell className="py-2 text-center"><VulnCount count={s.vuln_count ?? 0} /></TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{s.last_scan ?? s.created_at ?? "—"}</TableCell>
                    <TableCell className="py-2">
                      <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-6 px-2 text-[10px] border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                          disabled={exporting === `${s.id}-cyclonedx`}
                          onClick={() => handleExport(s.id, "cyclonedx")}
                        >
                          <Download className="h-3 w-3 mr-1" />
                          CycloneDX
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-6 px-2 text-[10px] border-purple-500/30 text-purple-400 hover:bg-purple-500/10"
                          disabled={exporting === `${s.id}-spdx`}
                          onClick={() => handleExport(s.id, "spdx")}
                        >
                          <Download className="h-3 w-3 mr-1" />
                          SPDX
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerability exposure + License risk */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Vulnerability breakdown */}
        <Card className="border-amber-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Vulnerability Exposure
            </CardTitle>
            <CardDescription className="text-xs">
              {totalVulns} vulnerable components across all SBOMs by severity
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {MOCK_VULN_BREAKDOWN.map(({ severity, count, color, pct }) => (
              <div key={severity} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="capitalize text-muted-foreground">{severity}</span>
                  <div className="flex items-center gap-2">
                    <span className="font-bold tabular-nums">{count}</span>
                    <span className="text-muted-foreground text-[10px]">({pct}%)</span>
                  </div>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.7 }}
                    className={cn("h-full rounded-full", color)}
                  />
                </div>
              </div>
            ))}

            <div className="pt-2 border-t border-border">
              <div className="flex items-center gap-3">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <div className="text-[11px] text-muted-foreground">
                  Prioritize <span className="text-red-400 font-semibold">critical</span> and <span className="text-amber-400 font-semibold">high</span> severity vulnerabilities first — {8 + 18} findings require immediate remediation
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* License risk summary */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileWarning className="h-4 w-4 text-red-400" />
              License Risk Summary
            </CardTitle>
            <CardDescription className="text-xs">
              License distribution across {stats.total_components.toLocaleString()} components
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {MOCK_LICENSE_BREAKDOWN.map(({ risk, label, count, pct, color }) => (
              <div key={risk} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground truncate max-w-[200px]">{label}</span>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="font-bold tabular-nums">{count}</span>
                    <span className="text-muted-foreground text-[10px]">({pct}%)</span>
                  </div>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.7 }}
                    className={cn("h-full rounded-full", color)}
                  />
                </div>
              </div>
            ))}

            <div className="pt-2 border-t border-border flex flex-wrap gap-2">
              {[
                { risk: "copyleft", label: "Copyleft Risk" },
                { risk: "unknown",  label: "Unknown Risk" },
              ].map(({ risk, label }) => (
                <LicenseRiskBadge key={risk} risk={risk} />
              ))}
              <span className="text-[11px] text-muted-foreground self-center">
                require legal review before distribution
              </span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Component list for selected SBOM */}
      {selectedSbom && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <Card className="border-blue-500/20">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
                  <Package className="h-4 w-4" />
                  Components — {selectedSbom.project_name}
                </CardTitle>
                <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setSelectedSbom(null)}>
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
              <CardDescription className="text-xs">
                {components.length} components listed — showing license type and vulnerability count
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Package</TableHead>
                      <TableHead className="text-[11px] h-8">Version</TableHead>
                      <TableHead className="text-[11px] h-8">License</TableHead>
                      <TableHead className="text-[11px] h-8">License Risk</TableHead>
                      <TableHead className="text-[11px] h-8 text-right">Vulns</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {components.map((c, i) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="py-2 font-mono text-xs font-medium">{c.name}</TableCell>
                        <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{c.version ?? "—"}</TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground">{c.license ?? c.licenses?.[0] ?? "Unknown"}</TableCell>
                        <TableCell className="py-2"><LicenseRiskBadge risk={c.risk ?? "permissive"} /></TableCell>
                        <TableCell className="py-2 text-right"><VulnCount count={c.vuln_count ?? 0} /></TableCell>
                      </TableRow>
                    ))}
                    {components.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={5} className="py-6 text-center text-xs text-muted-foreground">
                          No component data available for this SBOM.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}
    </motion.div>
  );
}
