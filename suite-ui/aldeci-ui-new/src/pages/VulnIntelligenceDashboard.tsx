/**
 * Vulnerability Intelligence Dashboard
 *
 * Wired to: /api/v1/vuln-intel
 *   GET /api/v1/vuln-intel/stats
 *   GET /api/v1/vuln-intel/cves
 *   GET /api/v1/vuln-intel/advisories
 *   GET /api/v1/vuln-intel/subscriptions
 *
 * Sections:
 *   1. KPI cards: Total CVEs, Critical CVEs, KEV Listed, EPSS High
 *   2. CVE intelligence table
 *   3. Vendor Advisories section
 *   4. Subscriptions management
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  TrendingUp,
  RefreshCw,
  ExternalLink,
  BookOpen,
  Bell,
  CheckCircle,
  XCircle,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == API helpers ==================================================
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ====================================================

const MOCK_STATS = {
  total_cves: 1_847,
  critical_cves: 143,
  kev_listed: 38,
  epss_high: 212,
  exploit_available: 319,
  patch_available: 1_412,
  advisories_new: 7,
};

const MOCK_CVES = [
  {
    cve_id: "CVE-2024-3400",  severity: "critical", cvss_score: 10.0, epss_score: 0.972, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "active",
    affected_products: ["PAN-OS < 11.1.2", "GlobalProtect"],
    title: "PAN-OS Command Injection in GlobalProtect Gateway",
  },
  {
    cve_id: "CVE-2024-21762", severity: "critical", cvss_score: 9.8,  epss_score: 0.944, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "active",
    affected_products: ["FortiOS < 7.4.3", "FortiProxy"],
    title: "Fortinet FortiOS Out-of-Bound Write RCE",
  },
  {
    cve_id: "CVE-2024-1709",  severity: "critical", cvss_score: 10.0, epss_score: 0.977, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "patched",
    affected_products: ["ConnectWise ScreenConnect < 23.9.8"],
    title: "ConnectWise ScreenConnect Authentication Bypass",
  },
  {
    cve_id: "CVE-2023-46805", severity: "critical", cvss_score: 8.8,  epss_score: 0.958, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "investigating",
    affected_products: ["Ivanti Connect Secure", "Ivanti Policy Secure"],
    title: "Ivanti Authentication Bypass",
  },
  {
    cve_id: "CVE-2024-27198", severity: "critical", cvss_score: 9.8,  epss_score: 0.731, kev_listed: false,
    exploit_available: true,  patch_available: true,  status: "active",
    affected_products: ["JetBrains TeamCity < 2023.11.4"],
    title: "JetBrains TeamCity Auth Bypass leading to RCE",
  },
  {
    cve_id: "CVE-2024-6387",  severity: "critical", cvss_score: 8.1,  epss_score: 0.035, kev_listed: false,
    exploit_available: false, patch_available: true,  status: "active",
    affected_products: ["OpenSSH < 9.8p1 (glibc Linux)"],
    title: "regreSSHion: OpenSSH Remote Code Execution",
  },
  {
    cve_id: "CVE-2024-4577",  severity: "critical", cvss_score: 9.8,  epss_score: 0.888, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "active",
    affected_products: ["PHP 8.x on Windows", "XAMPP"],
    title: "PHP CGI Argument Injection on Windows",
  },
  {
    cve_id: "CVE-2024-23897", severity: "high",     cvss_score: 9.8,  epss_score: 0.773, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "patched",
    affected_products: ["Jenkins < 2.442", "Jenkins LTS < 2.426.3"],
    title: "Jenkins Arbitrary File Read via CLI",
  },
  {
    cve_id: "CVE-2024-29895", severity: "high",     cvss_score: 8.8,  epss_score: 0.124, kev_listed: false,
    exploit_available: false, patch_available: true,  status: "active",
    affected_products: ["Cacti < 1.2.27"],
    title: "Cacti Command Injection in Data Input Methods",
  },
  {
    cve_id: "CVE-2024-37085",  severity: "high",    cvss_score: 6.8,  epss_score: 0.042, kev_listed: false,
    exploit_available: false, patch_available: true,  status: "new",
    affected_products: ["VMware ESXi"],
    title: "VMware ESXi Authentication Bypass in AD Integration",
  },
  {
    cve_id: "CVE-2024-0204",  severity: "critical", cvss_score: 9.8,  epss_score: 0.894, kev_listed: true,
    exploit_available: true,  patch_available: true,  status: "patched",
    affected_products: ["Fortra GoAnywhere MFT < 7.4.1"],
    title: "GoAnywhere MFT Authentication Bypass",
  },
  {
    cve_id: "CVE-2024-26234", severity: "medium",   cvss_score: 6.7,  epss_score: 0.017, kev_listed: false,
    exploit_available: false, patch_available: false, status: "new",
    affected_products: ["Windows Proxy Driver"],
    title: "Microsoft Proxy Driver Spoofing Vulnerability",
  },
];

const MOCK_ADVISORIES = [
  { id: "MSFT-2024-04", vendor: "Microsoft",    product: "Windows Server 2022", severity: "critical", cves_covered: ["CVE-2024-26234", "CVE-2024-21334"], release_date: "2024-04-09", patch_version: "KB5036909", status: "new",     advisory_url: "https://msrc.microsoft.com" },
  { id: "CISCO-24-019", vendor: "Cisco",         product: "IOS XE",              severity: "high",     cves_covered: ["CVE-2024-20399"],                   release_date: "2024-04-17", patch_version: "17.12.1",  status: "new",     advisory_url: "https://sec.cloudapps.cisco.com" },
  { id: "VMSA-2024-0012",vendor: "VMware",       product: "vCenter Server",      severity: "critical", cves_covered: ["CVE-2024-22275"],                   release_date: "2024-05-21", patch_version: "8.0U2c",   status: "applied", advisory_url: "https://www.vmware.com/security" },
  { id: "RHSA-2024-3043", vendor: "Red Hat",     product: "RHEL 9",              severity: "high",     cves_covered: ["CVE-2024-6387"],                    release_date: "2024-07-01", patch_version: "openssh-8.7p1-38", status: "new", advisory_url: "https://access.redhat.com" },
  { id: "APSB24-14",      vendor: "Adobe",       product: "ColdFusion",          severity: "critical", cves_covered: ["CVE-2024-20767"],                   release_date: "2024-03-12", patch_version: "2023.0.0.330468", status: "applied", advisory_url: "https://helpx.adobe.com" },
  { id: "FORTIOS-24-001", vendor: "Fortinet",   product: "FortiOS 7.4",         severity: "critical", cves_covered: ["CVE-2024-21762", "CVE-2024-23113"], release_date: "2024-02-08", patch_version: "7.4.3",    status: "new",     advisory_url: "https://www.fortiguard.com" },
];

const MOCK_SUBSCRIPTIONS = [
  { id: "sub-001", subscription_type: "vendor",   subscription_value: "Microsoft",  notify_severity_min: "high",     active: true  },
  { id: "sub-002", subscription_type: "vendor",   subscription_value: "Cisco",       notify_severity_min: "critical", active: true  },
  { id: "sub-003", subscription_type: "vendor",   subscription_value: "Fortinet",   notify_severity_min: "critical", active: true  },
  { id: "sub-004", subscription_type: "keyword",  subscription_value: "OpenSSH",    notify_severity_min: "medium",   active: true  },
  { id: "sub-005", subscription_type: "keyword",  subscription_value: "VMware",     notify_severity_min: "high",     active: true  },
  { id: "sub-006", subscription_type: "product",  subscription_value: "Jenkins",    notify_severity_min: "high",     active: false },
];

// == Helper components ============================================

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    new:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    active:        "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    patched:       "border-green-500/30 text-green-400 bg-green-500/10",
    applied:       "border-green-500/30 text-green-400 bg-green-500/10",
    closed:        "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function CvssScore({ score }: { score: number }) {
  const color = score >= 9.0 ? "text-red-400" : score >= 7.0 ? "text-amber-400" : score >= 4.0 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", color)}>{score.toFixed(1)}</span>;
}

function EpssScore({ score }: { score: number }) {
  const pct = (score * 100).toFixed(1);
  const color = score >= 0.7 ? "text-red-400" : score >= 0.3 ? "text-amber-400" : "text-muted-foreground";
  return <span className={cn("text-[11px] tabular-nums", color)}>{pct}%</span>;
}

function KevIndicator({ listed }: { listed: boolean }) {
  return listed ? (
    <span className="flex items-center gap-1 text-[11px] text-red-400 font-semibold">
      <Flame className="h-3 w-3" /> KEV
    </span>
  ) : (
    <span className="text-[11px] text-muted-foreground">=</span>
  );
}

function ExploitIndicator({ available }: { available: boolean }) {
  return available ? (
    <span className="flex items-center gap-1 text-[11px] text-amber-400">
      <Zap className="h-3 w-3" /> Yes
    </span>
  ) : (
    <span className="text-[11px] text-muted-foreground">No</span>
  );
}

// == Main Component ===============================================

export default function VulnIntelligenceDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(false);
  const [stats, setStats]               = useState<any>(null);
  const [cves, setCves]                 = useState<any[]>([]);
  const [advisories, setAdvisories]     = useState<any[]>([]);
  const [subscriptions, setSubscriptions] = useState<any[]>([]);

  useEffect(() => {
    setLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-intel/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-intel/cves?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/api/v1/vuln-intel/advisories?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-intel/subscriptions?org_id=${ORG_ID}`),
    ]).then(([statsRes, cvesRes, advisoriesRes, subsRes]) => {
      if (statsRes.status === "fulfilled")      setStats(statsRes.value);
      if (cvesRes.status === "fulfilled")       setCves(cvesRes.value?.items ?? cvesRes.value ?? []);
      if (advisoriesRes.status === "fulfilled") setAdvisories(advisoriesRes.value?.items ?? advisoriesRes.value ?? []);
      if (subsRes.status === "fulfilled")       setSubscriptions(subsRes.value?.items ?? subsRes.value ?? []);
    }).finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const displayStats  = stats ?? MOCK_STATS;
  const displayCves   = cves.length > 0 ? cves : MOCK_CVES;
  const displayAdvisories = advisories.length > 0 ? advisories : MOCK_ADVISORIES;
  const displaySubs   = subscriptions.length > 0 ? subscriptions : MOCK_SUBSCRIPTIONS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Vulnerability Intelligence"
        description="CVE tracking, EPSS scoring, KEV monitoring, vendor advisories, and intel subscriptions"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || loading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || loading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard
          title="CVEs Tracked"
          value={displayStats.total_cves?.toLocaleString() ?? "1,847"}
          icon={ShieldAlert}
          trend="up"
        />
        <KpiCard
          title="Critical CVEs"
          value={displayStats.critical_cves ?? "143"}
          icon={AlertTriangle}
          trend="up"
          className="border-red-500/20"
        />
        <KpiCard
          title="KEV Listed"
          value={displayStats.kev_listed ?? "38"}
          icon={Flame}
          trend="up"
          className="border-orange-500/20"
        />
        <KpiCard
          title="EPSS High (>30%)"
          value={displayStats.epss_high ?? "212"}
          icon={TrendingUp}
          trend="up"
          className="border-amber-500/20"
        />
      </div>

      {/* CVE Intelligence Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" />
              CVE Intelligence Feed
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {displayCves.filter((c: any) => c.kev_listed).length} KEV
              </Badge>
              <Badge className="text-[10px] border border-border text-muted-foreground">
                {displayCves.length} CVEs
              </Badge>
            </div>
          </div>
          <CardDescription className="text-xs">Tracked CVEs with CVSS, EPSS probability, KEV status, and exploit availability</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE ID</TableHead>
                  <TableHead className="text-[11px] h-8 max-w-[240px]">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">CVSS</TableHead>
                  <TableHead className="text-[11px] h-8">EPSS</TableHead>
                  <TableHead className="text-[11px] h-8">KEV</TableHead>
                  <TableHead className="text-[11px] h-8">Exploit</TableHead>
                  <TableHead className="text-[11px] h-8">Affected Products</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayCves.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  displayCves.map((cve: any, i: number) => (
                  <TableRow key={cve.cve_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2">
                      <span className="font-mono text-[11px] text-blue-400 flex items-center gap-1">
                        {cve.cve_id}
                        <ExternalLink className="h-2.5 w-2.5 opacity-50" />
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground max-w-[240px] truncate">
                      {cve.title || "="}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={cve.severity ?? "medium"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <CvssScore score={cve.cvss_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2">
                      <EpssScore score={cve.epss_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2">
                      <KevIndicator listed={cve.kev_listed ?? false} />
                    </TableCell>
                    <TableCell className="py-2">
                      <ExploitIndicator available={cve.exploit_available ?? false} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[180px] truncate">
                      {Array.isArray(cve.affected_products)
                        ? cve.affected_products.slice(0, 2).join(", ")
                        : (cve.affected_products || "=")}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={cve.status ?? "new"} />
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Vendor Advisories + Subscriptions */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">

        {/* Vendor Advisories */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <BookOpen className="h-4 w-4 text-purple-400" />
                Vendor Advisories
              </CardTitle>
              <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
                {displayAdvisories.filter((a: any) => a.status === "new").length} new
              </Badge>
            </div>
            <CardDescription className="text-xs">Vendor security advisories = track and apply patches</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {displayAdvisories.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              displayAdvisories.map((adv: any, i: number) => (
              <div key={adv.id ?? i} className={cn(
                "rounded-lg border bg-muted/20 p-3 space-y-2",
                adv.status === "new" ? "border-amber-500/20" : "border-border"
              )}>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-xs font-semibold truncate">{adv.vendor}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">{adv.id}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <SeverityBadge severity={adv.severity ?? "medium"} />
                    <StatusBadge status={adv.status ?? "new"} />
                  </div>
                </div>
                <div className="text-[11px] text-muted-foreground truncate">{adv.product}</div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-muted-foreground">
                    CVEs: <span className="text-foreground font-mono">{Array.isArray(adv.cves_covered) ? adv.cves_covered.join(", ") : "="}</span>
                  </span>
                  <span className="text-muted-foreground tabular-nums">{adv.release_date}</span>
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-muted-foreground">
                    Patch: <span className="text-green-400 font-mono">{adv.patch_version || "="}</span>
                  </span>
                  {adv.status === "applied" ? (
                    <span className="flex items-center gap-1 text-green-400">
                      <CheckCircle className="h-3 w-3" /> Applied
                    </span>
                  ) : (
                    <Button variant="outline" size="sm" className="h-5 px-2 text-[10px] border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                      Apply
                    </Button>
                  )}
                </div>
              </div>
            )))}
          </CardContent>
        </Card>

        {/* Intel Subscriptions */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Bell className="h-4 w-4 text-blue-400" />
                Intel Subscriptions
              </CardTitle>
              <Badge className="text-[10px] border border-border text-muted-foreground">
                {displaySubs.filter((s: any) => s.active !== false).length} active
              </Badge>
            </div>
            <CardDescription className="text-xs">Vendor, product, and keyword subscriptions for CVE notifications</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {displaySubs.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              displaySubs.map((sub: any, i: number) => (
              <div key={sub.id ?? i} className={cn(
                "flex items-center justify-between rounded-lg border p-3",
                sub.active === false ? "border-border bg-muted/10 opacity-60" : "border-border bg-muted/20"
              )}>
                <div className="flex items-center gap-3 min-w-0">
                  <div className={cn(
                    "h-2 w-2 rounded-full shrink-0",
                    sub.active === false ? "bg-slate-500" : "bg-green-500"
                  )} />
                  <div className="min-w-0">
                    <div className="text-xs font-medium truncate">{sub.subscription_value}</div>
                    <div className="text-[10px] text-muted-foreground capitalize">
                      {sub.subscription_type} subscription
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <Badge className={cn(
                    "text-[10px] border capitalize",
                    sub.notify_severity_min === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                    sub.notify_severity_min === "high"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10"
                  )}>
                    {sub.notify_severity_min}+
                  </Badge>
                  {sub.active === false ? (
                    <XCircle className="h-4 w-4 text-muted-foreground" />
                  ) : (
                    <CheckCircle className="h-4 w-4 text-green-400" />
                  )}
                </div>
              </div>
            )))}

            <div className="pt-2">
              <Button variant="outline" size="sm" className="w-full h-8 text-xs border-dashed border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                + Add Subscription
              </Button>
            </div>
          </CardContent>
        </Card>

      </div>

      {/* Summary strip */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-blue-400" />
            Intelligence Overview
          </CardTitle>
          <CardDescription className="text-xs">Patch coverage and exploit availability from stats endpoint</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {[
              { label: "Exploit Available",  value: displayStats.exploit_available ?? 319, color: "text-red-400" },
              { label: "Patch Available",    value: displayStats.patch_available?.toLocaleString() ?? "1,412", color: "text-green-400" },
              { label: "New Advisories",     value: displayStats.advisories_new ?? 7,   color: "text-amber-400" },
              { label: "EPSS High Risk",     value: displayStats.epss_high ?? 212,       color: "text-orange-400" },
            ].map((item) => (
              <div key={item.label} className="rounded-lg border border-border bg-muted/20 p-3 text-center space-y-1">
                <div className={cn("text-2xl font-bold tabular-nums", item.color)}>{item.value}</div>
                <div className="text-[11px] text-muted-foreground">{item.label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

    </motion.div>
  );
}
