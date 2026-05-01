// FOLDED into SupplyChainHub at /discover/supply-chain?tab=risk — kept as redirect-only stub
// (Phase 3 UX consolidation, 2026-05-02 — preserve for git history)
/**
 * Supply Chain Risk Dashboard
 *
 * Third-party vendor and component risk management — detailed view.
 * (SupplyChainSecurity.tsx exists at /supply-chain; this is /supply-chain-risk
 *  → both now redirect into /discover/supply-chain hub)
 *   1. KPIs: Suppliers, Critical Tier, EOL Components, Open Risks
 *   2. Supplier table (12 rows)
 *   3. Component risk table (10 rows)
 *   4. Risk breakdown: 6 risk type cards
 *   5. SBOM summary panel
 *
 * API stubs: GET /api/v1/supply-chain/suppliers, /api/v1/supply-chain/components, /api/v1/sbom/summary
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Package, AlertTriangle, Shield, RefreshCw, Upload, BarChart3, Globe } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

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
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import { EntityLink } from "@/components/EntityLink";

// ── Mock data ──────────────────────────────────────────────────

const SUPPLIERS = [
  { name: "AWS",              category: "cloud",    country: "US",  tier: "High",     score: 91, assessed: "2026-04-10", risks: 3  },
  { name: "Datadog",          category: "software", country: "US",  tier: "High",     score: 83, assessed: "2026-04-08", risks: 5  },
  { name: "Stripe",           category: "service",  country: "US",  tier: "Critical", score: 78, assessed: "2026-04-01", risks: 8  },
  { name: "Okta",             category: "software", country: "US",  tier: "Critical", score: 85, assessed: "2026-03-28", risks: 6  },
  { name: "Crowdstrike",      category: "software", country: "US",  tier: "High",     score: 88, assessed: "2026-04-05", risks: 4  },
  { name: "Lenovo",           category: "hardware", country: "CN",  tier: "Critical", score: 62, assessed: "2026-03-15", risks: 12 },
  { name: "Cloudflare",       category: "cloud",    country: "US",  tier: "High",     score: 92, assessed: "2026-04-11", risks: 2  },
  { name: "Twilio",           category: "service",  country: "US",  tier: "Medium",   score: 77, assessed: "2026-03-22", risks: 7  },
  { name: "Dell Technologies",category: "hardware", country: "US",  tier: "Medium",   score: 80, assessed: "2026-03-30", risks: 5  },
  { name: "MongoDB Atlas",    category: "cloud",    country: "US",  tier: "High",     score: 86, assessed: "2026-04-07", risks: 4  },
  { name: "SendGrid",         category: "service",  country: "US",  tier: "Low",      score: 94, assessed: "2026-04-12", risks: 1  },
  { name: "npm Registry",     category: "software", country: "US",  tier: "Critical", score: 55, assessed: "2026-03-10", risks: 18 },
];

const COMPONENTS = [
  { name: "openssl",        version: "1.0.2k",  supplier: "OpenSSL",   license: "OpenSSL",  cves: 14, eol: true,  purl: "pkg:generic/openssl@1.0.2k" },
  { name: "log4j-core",     version: "2.14.1",  supplier: "Apache",    license: "Apache-2", cves: 3,  eol: false, purl: "pkg:maven/log4j-core@2.14.1" },
  { name: "lodash",         version: "4.17.20", supplier: "npm",       license: "MIT",      cves: 2,  eol: false, purl: "pkg:npm/lodash@4.17.20"      },
  { name: "python",         version: "3.8.18",  supplier: "PSF",       license: "PSF",      cves: 5,  eol: true,  purl: "pkg:generic/python@3.8.18"   },
  { name: "redis",          version: "6.2.14",  supplier: "Redis Ltd", license: "BSD-3",    cves: 0,  eol: false, purl: "pkg:generic/redis@6.2.14"    },
  { name: "moment",         version: "2.29.4",  supplier: "npm",       license: "MIT",      cves: 1,  eol: true,  purl: "pkg:npm/moment@2.29.4"       },
  { name: "pyjwt",          version: "1.7.1",   supplier: "PyPI",      license: "MIT",      cves: 4,  eol: false, purl: "pkg:pypi/pyjwt@1.7.1"        },
  { name: "nginx",          version: "1.18.0",  supplier: "F5",        license: "BSD-2",    cves: 7,  eol: true,  purl: "pkg:generic/nginx@1.18.0"    },
  { name: "react",          version: "17.0.2",  supplier: "Meta",      license: "MIT",      cves: 0,  eol: false, purl: "pkg:npm/react@17.0.2"        },
  { name: "cryptography",   version: "3.4.8",   supplier: "PyPI",      license: "Apache-2", cves: 2,  eol: false, purl: "pkg:pypi/cryptography@3.4.8" },
];

const RISK_BREAKDOWN = [
  { type: "single_source",   label: "Single Source",    count: 12, severity: "Critical", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30"    },
  { type: "eol",             label: "EOL / Deprecated", count: 34, severity: "High",     color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/30"  },
  { type: "geo_political",   label: "Geo-Political",    count: 8,  severity: "High",     color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/30"  },
  { type: "breach_history",  label: "Breach History",   count: 5,  severity: "Critical", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30"    },
  { type: "no_audit",        label: "No Recent Audit",  count: 21, severity: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  { type: "license",         label: "License Issues",   count: 9,  severity: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
];

// ── Helpers ────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: string }) {
  const cls =
    tier === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    tier === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    tier === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{tier}</Badge>;
}

function CategoryBadge({ cat }: { cat: string }) {
  const cls =
    cat === "cloud"    ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    cat === "software" ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    cat === "hardware" ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                         "border-border text-muted-foreground bg-muted/20";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{cat}</Badge>;
}

function ScoreBar({ value }: { value: number }) {
  const color = value >= 85 ? "bg-green-500" : value >= 70 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-20 rounded-full bg-muted/30 overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${value}%` }} />
      </div>
      <span className="text-[10px] tabular-nums text-muted-foreground">{value}</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SupplyChainDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/supply-chain/vendors?org_id=${ORG_ID}&limit=30`),
      apiFetch(`/api/v1/supply-chain/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/supply-chain/components?org_id=${ORG_ID}`),
    ]).then(([vendorsResult, statsResult, componentsResult]) => {
      const vendors    = vendorsResult.status    === "fulfilled" ? vendorsResult.value    : null;
      const stats      = statsResult.status      === "fulfilled" ? statsResult.value      : null;
      const components = componentsResult.status === "fulfilled" ? componentsResult.value : null;
      if (vendors || stats || components) {
        setLiveData({ risks: null, vendors, components, stats });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derived values — prefer live data (stats endpoint), fall back to mock constants
  const totalComponents = liveData?.stats?.total_components ?? liveData?.risks?.total_components ?? 1_847;
  const eolCount        = liveData?.stats?.eol_components   ?? liveData?.risks?.eol_components   ?? 34;
  const cveAffected     = liveData?.stats?.cve_affected     ?? liveData?.risks?.cve_affected     ?? 112;
  const licenseIssues   = liveData?.stats?.license_issues   ?? liveData?.risks?.license_issues   ?? 9;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Supply Chain Risk"
        description="Third-party vendor and component risk management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Suppliers"        value={liveData?.stats?.total_suppliers ?? liveData?.vendors?.length ?? 142}  icon={Globe}         />
        <KpiCard title="Critical Tier"    value={liveData?.stats?.critical_suppliers ?? liveData?.risks?.critical_components ?? 18}   icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="EOL Components"   value={eolCount}   icon={Package}       trend="up" className="border-amber-500/20" />
        <KpiCard title="Open Risks"       value={liveData?.stats?.open_risks ?? liveData?.risks?.open_risks ?? 67}   icon={Shield}        trend="up" className="border-yellow-500/20" />
      </div>

      {/* Supplier table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Globe className="h-4 w-4 text-blue-400" />
            Supplier Registry
          </CardTitle>
          <CardDescription className="text-xs">All tracked vendors with compliance scores and risk tier</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Supplier</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Country</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Tier</TableHead>
                  <TableHead className="text-[11px] h-8">Compliance Score</TableHead>
                  <TableHead className="text-[11px] h-8">Last Assessed</TableHead>
                  <TableHead className="text-[11px] h-8">Risks</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.vendors ?? SUPPLIERS).map((s: any) => {
                  const name     = s.name ?? s.vendor_name ?? "—";
                  const category = s.category ?? s.vendor_url ?? "service";
                  const country  = s.country ?? "—";
                  const tier     = s.tier ?? "Medium";
                  const score    = s.score ?? s.security_score ?? 0;
                  const assessed = s.assessed ?? s.last_assessed ?? s.assessment_date ?? "—";
                  const risks    = s.risks ?? s.known_breaches ?? 0;
                  return (
                  <TableRow key={name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">
                      <EntityLink type="component" id={encodeURIComponent(name)}>
                        {name}
                      </EntityLink>
                    </TableCell>
                    <TableCell className="py-2.5"><CategoryBadge cat={category} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{country}</TableCell>
                    <TableCell className="py-2.5"><TierBadge tier={tier} /></TableCell>
                    <TableCell className="py-2.5"><ScoreBar value={score} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{assessed}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums py-2.5 font-bold", risks >= 10 ? "text-red-400" : risks >= 5 ? "text-amber-400" : "text-muted-foreground")}>{risks}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">View</Button>
                    </TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Component risk table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Package className="h-4 w-4 text-orange-400" />
            Component Risk Registry
          </CardTitle>
          <CardDescription className="text-xs">Software components with CVE counts, EOL status, and PURL</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Component</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Supplier</TableHead>
                  <TableHead className="text-[11px] h-8">License</TableHead>
                  <TableHead className="text-[11px] h-8">CVEs</TableHead>
                  <TableHead className="text-[11px] h-8">EOL</TableHead>
                  <TableHead className="text-[11px] h-8">PURL</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.components ?? COMPONENTS).map((c: any, idx: number) => {
                  const name     = c.name ?? c.component_name ?? "—";
                  const version  = c.version ?? "—";
                  const supplier = c.supplier ?? c.publisher ?? "—";
                  const license  = c.license ?? c.license_id ?? "—";
                  const cves     = c.cves ?? c.cve_count ?? 0;
                  const eol      = c.eol ?? c.is_eol ?? false;
                  const purl     = c.purl ?? c.package_url ?? "—";
                  return (
                  <TableRow key={`${name}-${version}-${idx}`} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium font-mono py-2.5">
                      <EntityLink type="component" id={encodeURIComponent(name)}>
                        {name}
                      </EntityLink>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{version}</TableCell>
                    <TableCell className="text-xs py-2.5">{supplier}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{license}</TableCell>
                    <TableCell className="py-2.5">
                      {cves > 0 ? (
                        <Badge className={cn("text-[10px] border", cves >= 5 ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-amber-500/30 text-amber-400 bg-amber-500/10")}>
                          {cves} CVE{cves !== 1 ? "s" : ""}
                        </Badge>
                      ) : (
                        <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Clean</Badge>
                      )}
                    </TableCell>
                    <TableCell className="py-2.5">
                      {eol ? (
                        <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">EOL</Badge>
                      ) : (
                        <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Active</Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground max-w-[160px] truncate" title={purl}>{purl}</TableCell>
                  </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Risk breakdown + SBOM summary */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Risk breakdown cards */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-red-400" />
              Risk Breakdown by Type
            </CardTitle>
            <CardDescription className="text-xs">Open risks grouped by risk category</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              {RISK_BREAKDOWN.map((r) => (
                <div
                  key={r.type}
                  className={cn("rounded-lg border p-3 flex flex-col gap-1", r.border, r.bg)}
                >
                  <span className={cn("text-[10px] font-medium uppercase tracking-wide", r.color)}>{r.severity}</span>
                  <span className={cn("text-2xl font-bold tabular-nums", r.color)}>{r.count}</span>
                  <span className="text-[11px] text-muted-foreground">{r.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* SBOM summary */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Shield className="h-4 w-4 text-green-400" />
                  SBOM Summary
                </CardTitle>
                <CardDescription className="text-xs">Software bill of materials overview</CardDescription>
              </div>
              <Button variant="outline" size="sm" className="h-7 text-xs gap-1">
                <Upload className="h-3 w-3" />
                Import SBOM
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { label: "Total Components",   value: totalComponents.toLocaleString(), color: "text-foreground",  pct: null },
              { label: "EOL Components",      value: eolCount,                         color: "text-red-400",     pct: Math.round((eolCount / totalComponents) * 100) },
              { label: "CVE-Affected",        value: cveAffected,                      color: "text-amber-400",   pct: Math.round((cveAffected / totalComponents) * 100) },
              { label: "License Issues",      value: licenseIssues,                    color: "text-yellow-400",  pct: Math.round((licenseIssues / totalComponents) * 100) },
            ].map((item) => (
              <div key={item.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{item.label}</span>
                  <span className={cn("font-bold tabular-nums", item.color)}>{item.value}</span>
                </div>
                {item.pct !== null && (
                  <Progress value={item.pct} className="h-1.5" />
                )}
              </div>
            ))}
            <div className="pt-2 border-t border-border/50 text-[10px] text-muted-foreground">
              Last SBOM import: 2026-04-15 22:14 UTC &nbsp;·&nbsp; Format: CycloneDX 1.4
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
