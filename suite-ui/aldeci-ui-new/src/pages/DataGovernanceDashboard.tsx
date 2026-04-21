/**
 * Data Governance Dashboard
 *
 * Data classification, policies, and compliance.
 *   1. KPIs: Total Assets, Policy Violations, Classified Assets %, Cross-Border Flows
 *   2. Asset table — 10 rows with classification color coding
 *   3. Policies table — 8 rows with enforcement and status badges
 *   4. Violations panel — 5 open violations
 *   5. Data flow map — 6 flows with source → destination
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Database, AlertTriangle, Shield, Globe, RefreshCw, CheckCircle, XCircle } from "lucide-react";

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
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const ASSETS = [
  { name: "customer_records_db", type: "Database", classification: "restricted", categories: "PII, Financial", encrypted: true, owner: "DataOps" },
  { name: "marketing_analytics", type: "Data Warehouse", classification: "internal", categories: "Behavioral", encrypted: true, owner: "Marketing" },
  { name: "public_api_docs", type: "Object Store", classification: "public", categories: "Documentation", encrypted: false, owner: "DevRel" },
  { name: "hr_employee_data", type: "Database", classification: "secret", categories: "PII, HR", encrypted: true, owner: "HR Ops" },
  { name: "audit_logs_archive", type: "Data Lake", classification: "confidential", categories: "Compliance", encrypted: true, owner: "SecOps" },
  { name: "product_telemetry", type: "Stream", classification: "internal", categories: "Usage Analytics", encrypted: true, owner: "Platform" },
  { name: "partner_api_exports", type: "Object Store", classification: "confidential", categories: "B2B, Contracts", encrypted: true, owner: "Partnerships" },
  { name: "cdn_static_assets", type: "CDN", classification: "public", categories: "Media, UI", encrypted: false, owner: "Frontend" },
  { name: "payment_processor_db", type: "Database", classification: "secret", categories: "PCI, Financial", encrypted: true, owner: "Payments" },
  { name: "dev_test_snapshots", type: "Object Store", classification: "internal", categories: "Dev Data", encrypted: false, owner: "Engineering" },
];

const POLICIES = [
  { name: "PCI-DSS Data Handling", type: "Regulatory", enforcement: "blocking", status: "active" },
  { name: "GDPR Personal Data Policy", type: "Regulatory", enforcement: "blocking", status: "active" },
  { name: "Cross-Border Transfer Policy", type: "Geographic", enforcement: "alerting", status: "active" },
  { name: "Data Retention Policy", type: "Lifecycle", enforcement: "automated", status: "active" },
  { name: "Encryption at Rest Policy", type: "Technical", enforcement: "blocking", status: "active" },
  { name: "Data Minimization Policy", type: "Privacy", enforcement: "alerting", status: "review" },
  { name: "Third-Party Data Sharing", type: "Contractual", enforcement: "manual", status: "active" },
  { name: "Dev Data Masking Policy", type: "Technical", enforcement: "automated", status: "draft" },
];

const VIOLATIONS = [
  { id: "DGV-001", asset: "dev_test_snapshots", policy: "Encryption at Rest Policy", severity: "high", daysOpen: 4 },
  { id: "DGV-002", asset: "cdn_static_assets", policy: "Data Classification Policy", severity: "medium", daysOpen: 7 },
  { id: "DGV-003", asset: "partner_api_exports", policy: "Cross-Border Transfer Policy", severity: "high", daysOpen: 2 },
  { id: "DGV-004", asset: "product_telemetry", policy: "Data Minimization Policy", severity: "low", daysOpen: 14 },
  { id: "DGV-005", asset: "marketing_analytics", policy: "GDPR Personal Data Policy", severity: "critical", daysOpen: 1 },
];

const FLOWS = [
  { source: "customer_records_db", destination: "payment_processor_db", type: "internal", encrypted: true, approved: true },
  { source: "hr_employee_data", destination: "EU HR Portal", type: "cross-border", encrypted: true, approved: true },
  { source: "audit_logs_archive", destination: "SIEM Platform", type: "internal", encrypted: true, approved: true },
  { source: "product_telemetry", destination: "US Analytics SaaS", type: "cross-border", encrypted: true, approved: false },
  { source: "partner_api_exports", destination: "Partner Portal", type: "external", encrypted: true, approved: true },
  { source: "dev_test_snapshots", destination: "CI/CD Pipeline", type: "internal", encrypted: false, approved: false },
];

// ── Helpers ────────────────────────────────────────────────────

function ClassificationBadge({ cls }: { cls: string }) {
  const styles: Record<string, string> = {
    public:       "border-gray-500/30 text-gray-400 bg-gray-500/10",
    internal:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    confidential: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    restricted:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    secret:       "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", styles[cls] ?? "border-border text-muted-foreground")}>
      {cls}
    </Badge>
  );
}

function TypeBadge({ label, color }: { label: string; color?: string }) {
  return (
    <Badge className={cn("text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10", color)}>
      {label}
    </Badge>
  );
}

function SeverityDot({ sev }: { sev: string }) {
  const color =
    sev === "critical" ? "bg-red-500" :
    sev === "high"     ? "bg-amber-500" :
    sev === "medium"   ? "bg-yellow-500" : "bg-green-500";
  return <span className={cn("inline-block w-2 h-2 rounded-full", color)} />;
}

function EnforcementBadge({ val }: { val: string }) {
  const styles: Record<string, string> = {
    blocking:  "border-red-500/30 text-red-400 bg-red-500/10",
    alerting:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    automated: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    manual:    "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", styles[val] ?? "border-border text-muted-foreground")}>
      {val}
    </Badge>
  );
}

function StatusBadge({ val }: { val: string }) {
  const styles: Record<string, string> = {
    active: "border-green-500/30 text-green-400 bg-green-500/10",
    review: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    draft:  "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", styles[val] ?? "border-border text-muted-foreground")}>
      {val}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function DataGovernanceDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/data-governance/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/data-governance/assets?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/data-governance/violations?org_id=${ORG_ID}&resolved=false`),
      apiFetch(`/api/v1/data-governance/policies?org_id=${ORG_ID}`),
    ]).then(([statsResult, assetsResult, violationsResult, policiesResult]) => {
      const stats      = statsResult.status      === "fulfilled" ? statsResult.value      : null;
      const assets     = assetsResult.status     === "fulfilled" ? assetsResult.value     : null;
      const violations = violationsResult.status === "fulfilled" ? violationsResult.value : null;
      const policies   = policiesResult.status   === "fulfilled" ? policiesResult.value   : null;
      if (stats || assets || violations || policies) {
        setLiveData({ stats, assets, violations, policies });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Data Governance"
        description="Data classification, policies, and compliance"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"      value={liveData?.stats?.total_assets ?? "847"}   icon={Database} />
        <KpiCard title="Policy Violations" value={liveData?.stats?.open_violations ?? liveData?.stats?.total_violations ?? 12}    icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="Classified Assets" value={liveData?.stats?.classified_pct != null ? `${liveData.stats.classified_pct}%` : "94.2%"} icon={Shield}    trend="up" className="border-green-500/20" />
        <KpiCard title="Cross-Border Flows" value={liveData?.stats?.cross_border_flows ?? 34}   icon={Globe} />
      </div>

      {/* Asset table + Violations panel */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Asset table — spans 2 cols */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Database className="h-4 w-4 text-blue-400" />
              Data Assets
            </CardTitle>
            <CardDescription className="text-xs">All classified data assets and their encryption status</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Asset Name</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Classification</TableHead>
                    <TableHead className="text-[11px] h-8">Categories</TableHead>
                    <TableHead className="text-[11px] h-8">Encrypted</TableHead>
                    <TableHead className="text-[11px] h-8">Owner</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.assets ?? ASSETS).map((row: any) => (
                    <TableRow key={row.name} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono py-2.5 max-w-[160px] truncate">{row.name}</TableCell>
                      <TableCell className="py-2.5">
                        <TypeBadge label={row.type} />
                      </TableCell>
                      <TableCell className="py-2.5">
                        <ClassificationBadge cls={row.classification} />
                      </TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{row.categories}</TableCell>
                      <TableCell className="py-2.5">
                        {row.encrypted
                          ? <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                          : <XCircle className="h-3.5 w-3.5 text-red-400" />}
                      </TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Violations panel */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
                <AlertTriangle className="h-4 w-4" />
                Open Violations
              </CardTitle>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {(liveData?.violations ?? VIOLATIONS).length}
              </Badge>
            </div>
            <CardDescription className="text-xs">Active policy violations requiring remediation</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {(liveData?.violations ?? VIOLATIONS).map((v: any) => (
              <div key={v.id} className="flex items-start gap-3 rounded-lg border border-border p-2.5 bg-muted/20">
                <SeverityDot sev={v.severity} />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium truncate">{v.asset}</div>
                  <div className="text-[10px] text-muted-foreground truncate">{v.policy}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{v.daysOpen}d open · {v.id}</div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Policies table + Data Flow map */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Policies table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-purple-400" />
              Data Policies
            </CardTitle>
            <CardDescription className="text-xs">Governance policies with enforcement mode and status</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Policy Name</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Enforcement</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.policies ?? POLICIES).map((p: any) => (
                    <TableRow key={p.name} className="hover:bg-muted/30">
                      <TableCell className="text-xs py-2.5 max-w-[180px] truncate font-medium">{p.name}</TableCell>
                      <TableCell className="py-2.5">
                        <TypeBadge label={p.type} />
                      </TableCell>
                      <TableCell className="py-2.5">
                        <EnforcementBadge val={p.enforcement} />
                      </TableCell>
                      <TableCell className="py-2.5">
                        <StatusBadge val={p.status} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Data flow map */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-cyan-400" />
              Data Flow Map
            </CardTitle>
            <CardDescription className="text-xs">Active data flows with encryption and approval status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {FLOWS.map((flow, i) => (
              <div key={i} className="flex items-center gap-3 rounded-lg border border-border p-2.5 bg-muted/20">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="truncate text-blue-400">{flow.source}</span>
                    <span className="text-muted-foreground shrink-0">→</span>
                    <span className="truncate text-cyan-400">{flow.destination}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge className={cn(
                      "text-[10px] border",
                      flow.type === "cross-border" ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                      flow.type === "external"     ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                                                     "border-blue-500/30 text-blue-400 bg-blue-500/10"
                    )}>
                      {flow.type}
                    </Badge>
                    {flow.encrypted
                      ? <span className="text-[10px] text-green-400 flex items-center gap-0.5"><CheckCircle className="h-3 w-3" />encrypted</span>
                      : <span className="text-[10px] text-red-400 flex items-center gap-0.5"><XCircle className="h-3 w-3" />unencrypted</span>}
                    {flow.approved
                      ? <span className="text-[10px] text-green-400">approved</span>
                      : <span className="text-[10px] text-amber-400">unapproved</span>}
                  </div>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
