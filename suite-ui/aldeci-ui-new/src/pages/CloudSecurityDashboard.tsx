/**
 * Cloud Security Posture Dashboard
 *
 * Multi-cloud misconfiguration and compliance monitoring.
 *   1. KPIs: Cloud Accounts, Open Findings, Critical Misconfigs, Avg Posture Score
 *   2. Account health table (8 rows)
 *   3. CIS benchmark compliance bars (6 frameworks)
 *   4. Top misconfigurations table (10 rows)
 *   5. Remediation priority: 3 grouped columns (Immediate/This Week/Next Sprint)
 *
 * API stubs: GET /api/v1/cloud/accounts, /api/v1/cloud/findings, /api/v1/cloud/benchmarks
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, AlertTriangle, Shield, BarChart3, RefreshCw, Zap, CheckCircle } from "lucide-react";
import { toast } from "sonner";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const ACCOUNTS = [
  { name: "prod-aws-us-east",   provider: "AWS",   region: "us-east-1",      findings: 87, critical: 6,  score: 68, scanned: "12m ago"  },
  { name: "prod-aws-eu-west",   provider: "AWS",   region: "eu-west-1",      findings: 54, critical: 3,  score: 74, scanned: "12m ago"  },
  { name: "staging-aws",        provider: "AWS",   region: "us-west-2",      findings: 31, critical: 1,  score: 82, scanned: "15m ago"  },
  { name: "prod-azure-east",    provider: "Azure", region: "eastus",          findings: 29, critical: 4,  score: 71, scanned: "20m ago"  },
  { name: "dev-azure",          provider: "Azure", region: "westeurope",      findings: 12, critical: 0,  score: 89, scanned: "22m ago"  },
  { name: "prod-gcp-central",   provider: "GCP",   region: "us-central1",    findings: 14, critical: 2,  score: 77, scanned: "18m ago"  },
  { name: "analytics-gcp",      provider: "GCP",   region: "europe-west1",   findings: 6,  critical: 1,  score: 85, scanned: "25m ago"  },
  { name: "backup-aws-ap",      provider: "AWS",   region: "ap-southeast-1", findings: 1,  critical: 1,  score: 91, scanned: "30m ago"  },
];

const BENCHMARKS = [
  { name: "CIS AWS",   pass: 178, fail: 34, total: 212 },
  { name: "NIST 800",  pass: 241, fail: 59, total: 300 },
  { name: "SOC 2",     pass: 89,  fail: 11, total: 100 },
  { name: "PCI DSS",   pass: 264, fail: 60, total: 324 },
  { name: "HIPAA",     pass: 143, fail: 22, total: 165 },
  { name: "GDPR",      pass: 71,  fail: 9,  total: 80  },
];

const MISCONFIGS = [
  { resource: "S3 Bucket",       type: "public_s3",    severity: "Critical", account: "prod-aws-us-east", status: "Open"     },
  { resource: "Security Group",  type: "open_sg",      severity: "Critical", account: "prod-aws-eu-west", status: "Open"     },
  { resource: "IAM User",        type: "no_mfa",       severity: "High",     account: "prod-azure-east",  status: "Open"     },
  { resource: "RDS Instance",    type: "unencrypted",  severity: "High",     account: "prod-aws-us-east", status: "In Review"},
  { resource: "CloudTrail",      type: "logging_off",  severity: "Critical", account: "prod-gcp-central", status: "Open"     },
  { resource: "EBS Volume",      type: "unencrypted",  severity: "High",     account: "staging-aws",      status: "Open"     },
  { resource: "Lambda Function", type: "public_s3",    severity: "Medium",   account: "prod-aws-us-east", status: "In Review"},
  { resource: "VPC",             type: "open_sg",      severity: "Medium",   account: "prod-azure-east",  status: "Open"     },
  { resource: "GCS Bucket",      type: "public_s3",    severity: "High",     account: "analytics-gcp",    status: "Open"     },
  { resource: "Azure AD",        type: "no_mfa",       severity: "Critical", account: "prod-azure-east",  status: "Open"     },
];

const REMEDIATION = {
  immediate: [
    { id: "CF-001", title: "Public S3 bucket — prod billing data",  severity: "Critical" },
    { id: "CF-002", title: "SSH port 22 open to 0.0.0.0/0",         severity: "Critical" },
    { id: "CF-010", title: "CloudTrail disabled in us-east-1",       severity: "Critical" },
    { id: "CF-018", title: "Root account active — no MFA",           severity: "Critical" },
  ],
  thisWeek: [
    { id: "CF-004", title: "RDS unencrypted at rest — prod-db-01",  severity: "High" },
    { id: "CF-007", title: "EBS snapshot public — snap-0a1b2c3d",   severity: "High" },
    { id: "CF-011", title: "IAM user keys older than 90 days",      severity: "High" },
    { id: "CF-014", title: "Azure AD guest accounts unrestricted",   severity: "High" },
    { id: "CF-019", title: "GCS bucket ACL: allUsers read",          severity: "High" },
  ],
  nextSprint: [
    { id: "CF-022", title: "VPC flow logs disabled — staging",      severity: "Medium" },
    { id: "CF-025", title: "Lambda: deprecated runtime (python3.7)  ",severity: "Medium" },
    { id: "CF-028", title: "Security Hub not enabled — ap-southeast",severity: "Medium" },
    { id: "CF-031", title: "Unused IAM roles older than 60 days",   severity: "Low"    },
  ],
};

// ── Helpers ────────────────────────────────────────────────────

function ProviderBadge({ provider }: { provider: string }) {
  const cls =
    provider === "AWS"   ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
    provider === "Azure" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
                           "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{provider}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground bg-muted/20";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "Open"      ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "In Review" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
                             "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{status}</Badge>;
}

function FindingTypeBadge({ type }: { type: string }) {
  return (
    <Badge className="text-[9px] border border-border bg-muted/30 text-muted-foreground px-1.5 py-0 font-mono">
      {type}
    </Badge>
  );
}

function ScoreBar({ value }: { value: number }) {
  const color = value >= 85 ? "bg-green-500" : value >= 70 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-20 rounded-full bg-muted/30 overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${value}%` }} />
      </div>
      <span className={cn("text-[10px] tabular-nums font-bold",
        value >= 85 ? "text-green-400" : value >= 70 ? "text-yellow-400" : "text-red-400"
      )}>{value}%</span>
    </div>
  );
}

function RemediationCard({ item }: { item: { id: string; title: string; severity: string } }) {
  const borderColor =
    item.severity === "Critical" ? "border-red-500/30 hover:border-red-500/50" :
    item.severity === "High"     ? "border-amber-500/30 hover:border-amber-500/50" :
    item.severity === "Medium"   ? "border-yellow-500/30 hover:border-yellow-500/50" :
                                   "border-border hover:border-border/80";
  const dotColor =
    item.severity === "Critical" ? "bg-red-500" :
    item.severity === "High"     ? "bg-amber-500" :
    item.severity === "Medium"   ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className={cn("rounded-md border p-2.5 bg-card/50 cursor-default transition-colors", borderColor)}>
      <div className="flex items-start gap-2">
        <span className={cn("mt-1 inline-block w-2 h-2 rounded-full flex-shrink-0", dotColor)} />
        <div className="min-w-0">
          <p className="text-[10px] font-mono text-muted-foreground">{item.id}</p>
          <p className="text-[11px] leading-tight mt-0.5 truncate" title={item.title}>{item.title}</p>
        </div>
      </div>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CloudSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/cloud-security-engine/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-security-engine/accounts?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-security-engine/findings?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, accountsResult, findingsResult]) => {
      const stats    = statsResult.status    === "fulfilled" ? statsResult.value    : null;
      const accounts = accountsResult.status === "fulfilled" ? accountsResult.value : null;
      const findings = findingsResult.status === "fulfilled" ? findingsResult.value : null;
      if (stats || accounts || findings) {
        setLiveData({ stats, accounts, findings });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
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
        title="Cloud Security Posture"
        description="Multi-cloud misconfiguration and compliance"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Cloud Accounts"      value={liveData?.stats?.total_accounts    ?? liveData?.accounts?.length ?? 12}    icon={Cloud}         />
        <KpiCard title="Open Findings"       value={liveData?.stats?.total_findings    ?? liveData?.findings?.length ?? 234}   icon={AlertTriangle} trend="up" className="border-amber-500/20" />
        <KpiCard title="Critical Misconfigs" value={liveData?.stats?.critical_findings ?? liveData?.stats?.critical_count ?? 18} icon={Zap}         trend="up" className="border-red-500/20" />
        <KpiCard title="Avg Posture Score"   value={liveData?.stats?.avg_risk_score != null ? `${(100 - liveData.stats.avg_risk_score).toFixed(1)}%` : "73.2%"} icon={Shield} trend="up" className="border-green-500/20" />
      </div>

      {/* Account health table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Cloud className="h-4 w-4 text-blue-400" />
            Account Health
          </CardTitle>
          <CardDescription className="text-xs">Per-account finding counts, posture scores, and last scan</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Account</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Region</TableHead>
                  <TableHead className="text-[11px] h-8">Findings</TableHead>
                  <TableHead className="text-[11px] h-8">Critical</TableHead>
                  <TableHead className="text-[11px] h-8">Posture Score</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scanned</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(Array.isArray(liveData?.accounts) && liveData.accounts.length > 0
                  ? liveData.accounts.map((acct: any) => ({
                      name:     acct.account_name || acct.account_id || acct.name || "",
                      provider: acct.provider || "AWS",
                      region:   acct.region || "",
                      findings: acct.finding_count ?? acct.findings ?? 0,
                      critical: acct.critical_count ?? acct.critical ?? 0,
                      score:    acct.risk_score != null ? Math.round(100 - acct.risk_score) : acct.score ?? 75,
                      scanned:  acct.last_scanned || acct.scanned || "–",
                    }))
                  : ACCOUNTS
                ).map((acct: any) => (
                  <TableRow key={acct.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono font-medium py-2.5">{acct.name}</TableCell>
                    <TableCell className="py-2.5"><ProviderBadge provider={acct.provider} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{acct.region}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums font-bold py-2.5", acct.findings > 50 ? "text-red-400" : acct.findings > 20 ? "text-amber-400" : "text-muted-foreground")}>{acct.findings}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums font-bold py-2.5", acct.critical > 0 ? "text-red-400" : "text-muted-foreground")}>{acct.critical}</TableCell>
                    <TableCell className="py-2.5"><ScoreBar value={acct.score} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{acct.scanned}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Scan Now</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* CIS benchmark + Top misconfigs */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* CIS Benchmark bars */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-400" />
              Framework Compliance
            </CardTitle>
            <CardDescription className="text-xs">Pass / fail breakdown across 6 security frameworks</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {BENCHMARKS.map((b) => {
              const pct = Math.round((b.pass / b.total) * 100);
              return (
                <div key={b.name} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium">{b.name}</span>
                    <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                      <span className="text-green-400">{b.pass} pass</span>
                      <span className="text-red-400">{b.fail} fail</span>
                      <span className="font-bold text-foreground tabular-nums">{pct}%</span>
                    </div>
                  </div>
                  <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full", pct >= 90 ? "bg-green-500" : pct >= 75 ? "bg-yellow-500" : "bg-red-500")}
                    />
                  </div>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Top misconfigurations */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Top Misconfigurations
            </CardTitle>
            <CardDescription className="text-xs">Highest severity cloud misconfigurations requiring action</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Resource</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Account</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Fix</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(Array.isArray(liveData?.findings) && liveData.findings.length > 0
                    ? liveData.findings.slice(0, 10).map((f: any) => ({
                        resource: f.resource_name || f.resource_type || f.resource || "Resource",
                        type:     f.category || f.type || "misconfiguration",
                        severity: f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1) : "Medium",
                        account:  f.account_id || f.account || "",
                        status:   f.status === "open" ? "Open" : f.status === "in_review" ? "In Review" : f.status || "Open",
                      }))
                    : MISCONFIGS
                  ).map((m: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2">{m.resource}</TableCell>
                      <TableCell className="py-2"><FindingTypeBadge type={m.type} /></TableCell>
                      <TableCell className="py-2"><SeverityBadge sev={m.severity} /></TableCell>
                      <TableCell className="text-[10px] py-2 text-muted-foreground max-w-[100px] truncate">{m.account}</TableCell>
                      <TableCell className="py-2"><StatusBadge status={m.status} /></TableCell>
                      <TableCell className="py-2 text-right">
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10">Fix</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Remediation priority */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-purple-400" />
            Remediation Priority Board
          </CardTitle>
          <CardDescription className="text-xs">Findings grouped by remediation urgency</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {/* Immediate */}
            <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 space-y-2">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-red-400">Immediate</span>
                <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">{REMEDIATION.immediate.length}</Badge>
              </div>
              {REMEDIATION.immediate.map((item) => (
                <RemediationCard key={item.id} item={item} />
              ))}
            </div>

            {/* This Week */}
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-2">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-amber-400">This Week</span>
                <Badge className="text-[9px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{REMEDIATION.thisWeek.length}</Badge>
              </div>
              {REMEDIATION.thisWeek.map((item) => (
                <RemediationCard key={item.id} item={item} />
              ))}
            </div>

            {/* Next Sprint */}
            <div className="rounded-lg border border-border bg-muted/10 p-3 space-y-2">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-muted-foreground">Next Sprint</span>
                <Badge className="text-[9px] border border-border text-muted-foreground">{REMEDIATION.nextSprint.length}</Badge>
              </div>
              {REMEDIATION.nextSprint.map((item) => (
                <RemediationCard key={item.id} item={item} />
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
