/**
 * Cross-Domain Analytics
 *
 * DuckDB-powered unified risk intelligence across all security domains.
 *   1. KPIs: Domains Connected, Active Alerts, Avg Risk Score, IOC Correlations
 *   2. Executive summary panel (5 rows)
 *   3. Asset-vulnerability correlation table (10 rows)
 *   4. IOC search bar with mock results panel
 *   5. Domain health grid (18 tiles, 6×3)
 *   6. Cross-domain compliance trend (6-month animated bar chart)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Database, Search, Shield, AlertTriangle, RefreshCw, BarChart3, Globe, Activity } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY  = import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID   = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
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

const EXEC_SUMMARY = [
  { label: "Security Posture",  value: "B+",  color: "text-green-400",  badge: "border-green-500/30 text-green-400 bg-green-500/10" },
  { label: "Open Cases",        value: "3",   color: "text-amber-400",  badge: "border-amber-500/30 text-amber-400 bg-amber-500/10" },
  { label: "Critical Vulns",    value: "12",  color: "text-red-400",    badge: "border-red-500/30 text-red-400 bg-red-500/10" },
  { label: "Hunt Findings",     value: "43",  color: "text-purple-400", badge: "border-purple-500/30 text-purple-400 bg-purple-500/10" },
  { label: "Compliance Score",  value: "78%", color: "text-blue-400",   badge: "border-blue-500/30 text-blue-400 bg-blue-500/10" },
];

const ASSET_VULN = [
  { asset: "api-gateway-prod",   type: "Service",    risk: "Critical", vuln: "CVE-2025-29927",     cvss: 9.8, days: 3  },
  { asset: "auth-service",       type: "Service",    risk: "Critical", vuln: "SQL Injection",       cvss: 9.1, days: 7  },
  { asset: "db-primary-001",     type: "Database",   risk: "High",     vuln: "Unencrypted PII",     cvss: 7.5, days: 14 },
  { asset: "worker-node-04",     type: "Container",  risk: "High",     vuln: "Log4Shell",           cvss: 10.0, days: 21 },
  { asset: "s3-data-exports",    type: "Storage",    risk: "High",     vuln: "Public ACL",          cvss: 7.2, days: 5  },
  { asset: "vpn-concentrator",   type: "Network",    risk: "Medium",   vuln: "TLS 1.0",             cvss: 5.9, days: 30 },
  { asset: "jenkins-ci",         type: "Service",    risk: "Medium",   vuln: "SSRF via webhook",    cvss: 6.5, days: 12 },
  { asset: "k8s-ingress",        type: "Container",  risk: "Medium",   vuln: "CORS misconfigured",  cvss: 5.3, days: 9  },
  { asset: "ldap-server",        type: "Directory",  risk: "Low",      vuln: "Weak cipher suite",   cvss: 4.1, days: 45 },
  { asset: "monitoring-agent",   type: "Service",    risk: "Low",      vuln: "Outdated OpenSSL",    cvss: 3.7, days: 60 },
];

const IOC_RESULTS = [
  { ioc: "185.220.101.47",  type: "IP",     domains: ["Feed Intel", "Threat Correlation", "Hunt Findings"] },
  { ioc: "evil-domain.ru",  type: "Domain", domains: ["Feed Intel", "Threat Correlation"] },
  { ioc: "dGVzdC1tYWx3YXJl", type: "Hash", domains: ["Hunt Findings"] },
  { ioc: "103.76.128.99",   type: "IP",     domains: ["Feed Intel", "Hunt Findings"] },
  { ioc: "malware-cdn.xyz", type: "Domain", domains: ["Feed Intel", "Threat Correlation", "Hunt Findings"] },
];

const DOMAINS = [
  { name: "Vulnerabilities",   db: "12.4 MB", records: "1,847",  updated: "2m ago",   stale: false },
  { name: "Threat Intel",      db: "34.1 MB", records: "28,430", updated: "5m ago",   stale: false },
  { name: "Hunt Findings",     db: "8.2 MB",  records: "423",    updated: "1h ago",   stale: false },
  { name: "Asset Inventory",   db: "22.7 MB", records: "3,914",  updated: "15m ago",  stale: false },
  { name: "Compliance",        db: "5.1 MB",  records: "6,720",  updated: "2h ago",   stale: false },
  { name: "Attack Paths",      db: "9.3 MB",  records: "891",    updated: "30m ago",  stale: false },
  { name: "SLA Tracking",      db: "3.8 MB",  records: "2,341",  updated: "10m ago",  stale: false },
  { name: "IOC Correlations",  db: "41.2 MB", records: "84,720", updated: "3m ago",   stale: false },
  { name: "Identity Events",   db: "18.6 MB", records: "52,140", updated: "1m ago",   stale: false },
  { name: "Cloud Posture",     db: "7.9 MB",  records: "1,204",  updated: "45m ago",  stale: false },
  { name: "Network Flow",      db: "62.3 MB", records: "218,400",updated: "8m ago",   stale: false },
  { name: "Secrets Scan",      db: "2.1 MB",  records: "374",    updated: "4h ago",   stale: false },
  { name: "SBOM",              db: "11.4 MB", records: "9,821",  updated: "6h ago",   stale: false },
  { name: "Pentest Results",   db: "4.7 MB",  records: "287",    updated: "3d ago",   stale: true  },
  { name: "Code Scanning",     db: "15.8 MB", records: "12,430", updated: "2h ago",   stale: false },
  { name: "Container Scans",   db: "6.2 MB",  records: "3,120",  updated: "8d ago",   stale: true  },
  { name: "Vendor Risk",       db: "3.4 MB",  records: "892",    updated: "1d ago",   stale: false },
  { name: "Evidence Vault",    db: "9.1 MB",  records: "4,312",  updated: "12d ago",  stale: true  },
];

const TREND = [
  { month: "Nov", score: 58 },
  { month: "Dec", score: 61 },
  { month: "Jan", score: 64 },
  { month: "Feb", score: 69 },
  { month: "Mar", score: 74 },
  { month: "Apr", score: 78 },
];

const TREND_MAX = 100;

// ── Helpers ────────────────────────────────────────────────────

function RiskBadge({ risk }: { risk: string }) {
  const cls =
    risk === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    risk === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    risk === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{risk}</Badge>;
}

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "Service"   ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "Database"  ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "Container" ? "border-cyan-500/30 text-cyan-400 bg-cyan-500/10" :
    type === "Storage"   ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
    type === "Network"   ? "border-green-500/30 text-green-400 bg-green-500/10" :
                           "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function CrossDomainAnalytics() {
  const [refreshing, setRefreshing] = useState(false);
  const [iocQuery, setIocQuery] = useState("");
  const [showResults, setShowResults] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveIocResults, setLiveIocResults] = useState<any>(null);
  const [iocLoading, setIocLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/analytics-engine/executive?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/analytics-engine/asset-vuln?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/analytics-engine/compliance-trend?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/analytics-engine/domains`),
    ]).then(([execRes, assetRes, trendRes, domainsRes]) => {
      const exec    = execRes.status    === "fulfilled" ? execRes.value    : null;
      const assets  = assetRes.status   === "fulfilled" ? assetRes.value   : null;
      const trend   = trendRes.status   === "fulfilled" ? trendRes.value   : null;
      const domains = domainsRes.status === "fulfilled" ? domainsRes.value : null;
      if (exec || assets || trend || domains) {
        setLiveData({ exec, assets, trend, domains });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleIocSearch = () => {
    if (!iocQuery.trim()) { setShowResults(true); return; }
    setIocLoading(true);
    apiFetch(`/api/v1/analytics-engine/threat-ioc?org_id=${ORG_ID}&ioc=${encodeURIComponent(iocQuery)}`)
      .then((data) => { setLiveIocResults(data); setShowResults(true); })
      .catch(() => setShowResults(true))
      .finally(() => setIocLoading(false));
  };

  const handleRefresh = () => {
    setRefreshing(true);
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/analytics-engine/executive?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/analytics-engine/asset-vuln?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/analytics-engine/compliance-trend?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/analytics-engine/domains`),
    ]).then(([execRes, assetRes, trendRes, domainsRes]) => {
      const exec    = execRes.status    === "fulfilled" ? execRes.value    : null;
      const assets  = assetRes.status   === "fulfilled" ? assetRes.value   : null;
      const trend   = trendRes.status   === "fulfilled" ? trendRes.value   : null;
      const domains = domainsRes.status === "fulfilled" ? domainsRes.value : null;
      if (exec || assets || trend || domains) {
        setLiveData({ exec, assets, trend, domains });
      }
    }).finally(() => { setDataLoading(false); setRefreshing(false); });
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
        title="Cross-Domain Analytics"
        description="DuckDB-powered unified risk intelligence across all security domains"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Domains Connected"  value={liveData?.domains?.length          ?? 18}      icon={Database}      trend="up" />
        <KpiCard title="Active Alerts"      value={liveData?.exec?.open_incidents      ?? 34}      icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Avg Risk Score"     value={liveData?.exec?.posture_score       ?? "62.4"}  icon={Shield}        trend="down" className="border-amber-500/20" />
        <KpiCard title="IOC Correlations"   value={liveData?.exec?.active_threats      ?? "847"}   icon={Globe}         trend="up" />
      </div>

      {/* Executive Summary + Compliance Trend */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Executive Summary */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Executive Summary
            </CardTitle>
            <CardDescription className="text-xs">Aggregated posture across all domains</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {EXEC_SUMMARY.map((row) => {
              let displayValue = row.value;
              if (liveData?.exec) {
                if (row.label === "Security Posture") displayValue = liveData.exec.posture_score ?? row.value;
                else if (row.label === "Open Cases")  displayValue = String(liveData.exec.open_incidents ?? row.value);
                else if (row.label === "Critical Vulns") displayValue = String(liveData.exec.critical_vulns ?? row.value);
                else if (row.label === "Hunt Findings") displayValue = String(liveData.exec.active_threats ?? row.value);
                else if (row.label === "Compliance Score") displayValue = liveData.exec.compliance_avg ? `${liveData.exec.compliance_avg}%` : row.value;
              }
              return (
                <div key={row.label} className="flex items-center justify-between py-1.5 border-b border-border/40 last:border-0">
                  <span className="text-xs text-muted-foreground">{row.label}</span>
                  <Badge className={cn("text-xs font-bold border", row.badge)}>{displayValue}</Badge>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Compliance Trend */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              Compliance Score Trend (6 months)
            </CardTitle>
            <CardDescription className="text-xs">Aggregate cross-domain compliance score</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-3 h-36">
              {TREND.map((m) => (
                <div key={m.month} className="flex-1 flex flex-col items-center gap-0.5">
                  <span className="text-[10px] text-muted-foreground mb-1">{m.score}%</span>
                  <div className="w-full flex items-end h-24">
                    <motion.div
                      initial={{ height: 0 }}
                      animate={{ height: `${(m.score / TREND_MAX) * 100}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn(
                        "w-full rounded-t",
                        m.score >= 75 ? "bg-green-500/70" : m.score >= 60 ? "bg-amber-500/70" : "bg-red-500/70"
                      )}
                    />
                  </div>
                  <span className="text-[10px] text-muted-foreground">{m.month}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* IOC Search */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Search className="h-4 w-4 text-amber-400" />
            IOC Cross-Domain Search
          </CardTitle>
          <CardDescription className="text-xs">Search an IP, domain, or hash across all connected data sources</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <input
              className="flex-1 h-9 rounded-md border border-border bg-muted/30 px-3 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              placeholder="Enter IP, domain, hash, or CVE..."
              value={iocQuery}
              onChange={(e) => setIocQuery(e.target.value)}
            />
            <Button size="sm" onClick={handleIocSearch} disabled={iocLoading} className="h-9 px-4">
              {iocLoading ? "Searching…" : "Search"}
            </Button>
          </div>
          {showResults && (
            <div className="rounded-md border border-border overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">IOC</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Seen In Domains</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {liveIocResults
                    ? (
                      <TableRow className="hover:bg-muted/30">
                        <TableCell className="text-xs font-mono py-2">{iocQuery}</TableCell>
                        <TableCell className="py-2">
                          <Badge className="text-[10px] border border-border text-muted-foreground">IOC</Badge>
                        </TableCell>
                        <TableCell className="py-2">
                          <div className="flex flex-wrap gap-1">
                            {liveIocResults.threat_feed_hits > 0 && <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">Feed Intel ({liveIocResults.threat_feed_hits})</Badge>}
                            {liveIocResults.threat_hunt_hits > 0 && <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">Hunt Findings ({liveIocResults.threat_hunt_hits})</Badge>}
                            {!liveIocResults.threat_feed_hits && !liveIocResults.threat_hunt_hits && <Badge className="text-[10px] border border-border text-muted-foreground">No hits found</Badge>}
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                    : IOC_RESULTS.map((r) => (
                      <TableRow key={r.ioc} className="hover:bg-muted/30">
                        <TableCell className="text-xs font-mono py-2">{r.ioc}</TableCell>
                        <TableCell className="py-2">
                          <Badge className="text-[10px] border border-border text-muted-foreground">{r.type}</Badge>
                        </TableCell>
                        <TableCell className="py-2">
                          <div className="flex flex-wrap gap-1">
                            {r.domains.map((d) => (
                              <Badge key={d} className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">{d}</Badge>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  }
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Asset-Vulnerability Correlation */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-400" />
              Asset-Vulnerability Correlation
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">10 assets</Badge>
          </div>
          <CardDescription className="text-xs">Cross-domain join: CMDB × vulnerability scanner × threat intel</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Top Vulnerability</TableHead>
                  <TableHead className="text-[11px] h-8">CVSS</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Days Open</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.assets ?? ASSET_VULN).map((row: any) => (
                  <TableRow key={row.asset ?? row.asset_id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.asset ?? row.asset_id}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={row.type} /></TableCell>
                    <TableCell className="py-2.5"><RiskBadge risk={row.risk} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground max-w-[160px] truncate">{row.vuln}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", row.cvss >= 9 ? "bg-red-500" : row.cvss >= 7 ? "bg-amber-500" : "bg-yellow-500")}
                            style={{ width: `${(row.cvss / 10) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs tabular-nums font-medium">{row.cvss}</span>
                      </div>
                    </TableCell>
                    <TableCell className={cn("text-xs tabular-nums py-2.5 text-right font-medium", row.days > 14 ? "text-red-400" : row.days > 7 ? "text-amber-400" : "text-muted-foreground")}>
                      {row.days}d
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Domain Health Grid */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Database className="h-4 w-4 text-green-400" />
            Domain Health Grid
          </CardTitle>
          <CardDescription className="text-xs">18 connected data domains — green = healthy, amber = stale (&gt;7 days)</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
            {(liveData?.domains ?? DOMAINS).map((d: any) => (
              <div
                key={d.name ?? d.db_name}
                className={cn(
                  "rounded-lg border p-2.5 flex flex-col gap-1",
                  d.stale
                    ? "border-amber-500/30 bg-amber-500/5"
                    : "border-green-500/20 bg-green-500/5"
                )}
              >
                <span className={cn("text-[10px] font-semibold truncate", d.stale ? "text-amber-400" : "text-green-400")}>{d.name}</span>
                <span className="text-[9px] text-muted-foreground">{d.db}</span>
                <span className="text-[9px] text-muted-foreground">{d.records} rows</span>
                <span className={cn("text-[9px]", d.stale ? "text-amber-400" : "text-muted-foreground")}>{d.updated}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
