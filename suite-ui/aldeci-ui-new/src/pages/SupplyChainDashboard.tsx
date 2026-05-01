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
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Package, AlertTriangle, Shield, RefreshCw, Globe } from "lucide-react";

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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";
import { EntityLink } from "@/components/EntityLink";

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

  // Derived values — prefer live data (stats endpoint). null when no data.
  const totalComponents = liveData?.stats?.total_components ?? liveData?.risks?.total_components ?? null;
  const eolCount        = liveData?.stats?.eol_components   ?? liveData?.risks?.eol_components   ?? null;
  const totalSuppliers  = liveData?.stats?.total_suppliers  ?? (Array.isArray(liveData?.vendors) ? liveData.vendors.length : null);
  const criticalTier    = liveData?.stats?.critical_suppliers ?? liveData?.risks?.critical_components ?? null;
  const openRisks       = liveData?.stats?.open_risks       ?? liveData?.risks?.open_risks       ?? null;
  const vendors         = Array.isArray(liveData?.vendors) ? liveData.vendors : [];
  const components      = Array.isArray(liveData?.components) ? liveData.components : [];

  const hasAnyData =
    totalComponents != null ||
    eolCount != null ||
    totalSuppliers != null ||
    criticalTier != null ||
    openRisks != null ||
    vendors.length > 0 ||
    components.length > 0;

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Supply Chain Risk"
        description="Third-party vendor and component risk management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />
      <EmptyState
        icon={Package}
        title="No supply chain data yet"
        description="Connect an SBOM importer or vendor registry to populate this view."
        action={
          <Link to="/onboarding" className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500">
            Start onboarding
          </Link>
        }
      />
    </motion.div>
  );

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
        <KpiCard title="Suppliers"        value={totalSuppliers ?? "—"}  icon={Globe}         />
        <KpiCard title="Critical Tier"    value={criticalTier ?? "—"}    icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="EOL Components"   value={eolCount ?? "—"}        icon={Package}       trend="up" className="border-amber-500/20" />
        <KpiCard title="Open Risks"       value={openRisks ?? "—"}       icon={Shield}        trend="up" className="border-yellow-500/20" />
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
                {vendors.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={8} className="p-0">
                      <EmptyState
                        icon={Globe}
                        title="No suppliers tracked"
                        description="Vendors registered via the supply-chain importer will appear here."
                      />
                    </TableCell>
                  </TableRow>
                )}
                {vendors.map((s: any) => {
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
                {components.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={7} className="p-0">
                      <EmptyState
                        icon={Package}
                        title="No components tracked"
                        description="Components ingested from SBOM imports will appear here."
                      />
                    </TableCell>
                  </TableRow>
                )}
                {components.map((c: any, idx: number) => {
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

    </motion.div>
  );
}
