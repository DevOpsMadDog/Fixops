/**
 * Configuration Benchmarks Dashboard
 *
 * CIS, DISA STIG, and custom hardening assessments.
 *   1. KPIs: Profiles, Assessments Run, Avg Score, Critical Failures
 *   2. Assessment profiles table (8 rows)
 *   3. Latest assessment results (12 check results)
 *   4. Failed checks drill-down (8 failed checks, expandable accordion)
 *   5. Score by standard bar chart (5 bars)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ClipboardCheck, Shield, AlertTriangle, RefreshCw, BarChart3, ChevronDown, ChevronRight, CheckCircle2, XCircle, Minus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const PROFILES = [
  { name: "CIS Ubuntu 22.04 L2",     standard: "CIS",          target: "Linux",      version: "2.0.0", last_assessed: "2026-04-15", score: 72 },
  { name: "CIS AWS Foundations",      standard: "CIS",          target: "Cloud",      version: "3.0.0", last_assessed: "2026-04-14", score: 81 },
  { name: "DISA STIG RHEL 9",        standard: "DISA STIG",    target: "Linux",      version: "1.1",   last_assessed: "2026-04-13", score: 55 },
  { name: "DISA STIG Apache 2.4",    standard: "DISA STIG",    target: "Web Server", version: "2.0",   last_assessed: "2026-04-10", score: 63 },
  { name: "NIST 800-53 Rev 5",       standard: "NIST 800-53",  target: "Full Stack", version: "Rev 5", last_assessed: "2026-04-08", score: 68 },
  { name: "PCI DSS 4.0 Network",     standard: "PCI DSS",      target: "Network",    version: "4.0",   last_assessed: "2026-04-12", score: 74 },
  { name: "CIS Kubernetes 1.29",     standard: "CIS",          target: "Container",  version: "1.9.0", last_assessed: "2026-04-15", score: 59 },
  { name: "CIS Docker CE",           standard: "CIS",          target: "Container",  version: "1.7.0", last_assessed: "2026-04-11", score: 83 },
];

const CHECK_RESULTS = [
  { ref: "CIS-1.1.1",   title: "Ensure mounting of cramfs disabled",     category: "Filesystem",   status: "pass",    severity: "Low",     actual: "cramfs disabled", expected: "disabled"  },
  { ref: "CIS-1.3.2",   title: "Ensure filesystem integrity is checked",  category: "Filesystem",   status: "fail",    severity: "Medium",  actual: "aide not found",  expected: "aide installed" },
  { ref: "CIS-2.1.1",   title: "Ensure xinetd not installed",            category: "Services",     status: "pass",    severity: "Medium",  actual: "not installed",   expected: "not installed" },
  { ref: "CIS-3.1.2",   title: "Ensure packet redirect disabled",        category: "Network",      status: "fail",    severity: "Medium",  actual: "1",               expected: "0" },
  { ref: "CIS-3.3.1",   title: "Ensure IPv6 router ads not accepted",    category: "Network",      status: "pass",    severity: "Medium",  actual: "0",               expected: "0" },
  { ref: "CIS-4.1.1.1", title: "Ensure auditd installed",               category: "Logging",      status: "pass",    severity: "High",    actual: "installed",       expected: "installed" },
  { ref: "CIS-4.1.6",   title: "Ensure system admin scope collected",    category: "Logging",      status: "warn",    severity: "Medium",  actual: "partial",         expected: "full" },
  { ref: "CIS-5.2.4",   title: "Ensure SSH LogLevel is appropriate",    category: "SSH",          status: "pass",    severity: "Medium",  actual: "VERBOSE",         expected: "INFO or VERBOSE" },
  { ref: "CIS-5.2.11",  title: "Ensure only strong MACs used",          category: "SSH",          status: "fail",    severity: "High",    actual: "hmac-sha1 found", expected: "strong only" },
  { ref: "CIS-5.3.1",   title: "Ensure sudo is installed",              category: "Access",       status: "pass",    severity: "High",    actual: "installed",       expected: "installed" },
  { ref: "CIS-6.1.2",   title: "Ensure /etc/passwd permissions 644",    category: "Permissions",  status: "pass",    severity: "Medium",  actual: "644",             expected: "644" },
  { ref: "CIS-6.2.1",   title: "Ensure accounts in /etc/passwd valid",  category: "Accounts",     status: "fail",    severity: "High",    actual: "2 orphan found",  expected: "none" },
];

const FAILED_CHECKS = [
  {
    ref: "CIS-1.3.2",
    title: "Ensure filesystem integrity checking is configured",
    severity: "Medium",
    remediation: "Install AIDE: `apt install aide aide-common`. Initialize: `aideinit`. Configure cron: add `0 5 * * * /usr/bin/aide --config /etc/aide/aide.conf --check` to root crontab.",
  },
  {
    ref: "CIS-3.1.2",
    title: "Ensure packet redirect sending is disabled",
    severity: "Medium",
    remediation: "Set `net.ipv4.conf.all.send_redirects = 0` and `net.ipv4.conf.default.send_redirects = 0` in `/etc/sysctl.d/60-netipv4_sysctl.conf`. Run `sysctl -w` to apply.",
  },
  {
    ref: "CIS-5.2.11",
    title: "Ensure only approved MAC algorithms are used",
    severity: "High",
    remediation: "Edit `/etc/ssh/sshd_config`. Set `MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256`. Restart sshd.",
  },
  {
    ref: "CIS-6.2.1",
    title: "Ensure no orphan UIDs/GIDs exist in /etc/passwd",
    severity: "High",
    remediation: "Run `awk -F: '{print $3}' /etc/passwd | sort -u` and cross-check against home directories. Remove stale accounts with `userdel -r <username>` or assign to valid groups.",
  },
  {
    ref: "STIG-V-230221",
    title: "RHEL 9 must use a DoD-approved virus protection",
    severity: "High",
    remediation: "Install ClamAV or approved AV solution. Enable `clamav-freshclam` and `clamav-daemon` services. Configure scheduled scans via systemd timer.",
  },
  {
    ref: "STIG-V-230232",
    title: "RHEL 9 must restrict access to /var/log/audit",
    severity: "Medium",
    remediation: "Run `chmod 0750 /var/log/audit` and `chown root:root /var/log/audit`. Verify with `ls -la /var/log/ | grep audit`.",
  },
  {
    ref: "CIS-AWS-2.1.2",
    title: "Ensure S3 bucket access logging is enabled",
    severity: "Medium",
    remediation: "Enable access logging on all S3 buckets via AWS CLI: `aws s3api put-bucket-logging --bucket <name> --bucket-logging-status ...` or use Terraform `aws_s3_bucket_logging` resource.",
  },
  {
    ref: "CIS-K8S-4.2.6",
    title: "Ensure that the --protect-kernel-defaults argument is set to true",
    severity: "High",
    remediation: "In the kubelet config file (`/var/lib/kubelet/config.yaml`), set `protectKernelDefaults: true`. Restart kubelet: `systemctl restart kubelet`.",
  },
];

const SCORE_BY_STANDARD = [
  { standard: "CIS",         score: 73.8, count: 4 },
  { standard: "DISA STIG",   score: 59.0, count: 2 },
  { standard: "NIST 800-53", score: 68.0, count: 1 },
  { standard: "PCI DSS",     score: 74.0, count: 1 },
  { standard: "Custom",      score: 61.0, count: 0 },
];

// ── Helpers ────────────────────────────────────────────────────

const STANDARD_COLORS: Record<string, string> = {
  "CIS":          "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "DISA STIG":    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "NIST 800-53":  "border-green-500/30 text-green-400 bg-green-500/10",
  "PCI DSS":      "border-orange-500/30 text-orange-400 bg-orange-500/10",
};

const TARGET_COLORS: Record<string, string> = {
  "Linux":      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  "Cloud":      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "Container":  "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "Network":    "border-green-500/30 text-green-400 bg-green-500/10",
  "Web Server": "border-amber-500/30 text-amber-400 bg-amber-500/10",
  "Full Stack": "border-red-500/30 text-red-400 bg-red-500/10",
};

function ScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-24 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums", score >= 80 ? "text-green-400" : score >= 60 ? "text-amber-400" : "text-red-400")}>
        {score}%
      </span>
    </div>
  );
}

const CATEGORY_COLORS: Record<string, string> = {
  "Filesystem":  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "Services":    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "Network":     "border-green-500/30 text-green-400 bg-green-500/10",
  "Logging":     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  "SSH":         "border-amber-500/30 text-amber-400 bg-amber-500/10",
  "Access":      "border-red-500/30 text-red-400 bg-red-500/10",
  "Permissions": "border-orange-500/30 text-orange-400 bg-orange-500/10",
  "Accounts":    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
};

function SevBadge({ sev }: { sev: string }) {
  const cls =
    sev === "High"   ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium" ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function StatusIcon({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle2 className="h-4 w-4 text-green-400" />;
  if (status === "fail") return <XCircle className="h-4 w-4 text-red-400" />;
  if (status === "warn") return <AlertTriangle className="h-4 w-4 text-amber-400" />;
  return <Minus className="h-4 w-4 text-muted-foreground" />;
}

// ── Component ──────────────────────────────────────────────────

export default function ConfigBenchmarkDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/config-benchmark/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/config-benchmark/profiles?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/config-benchmark/assessments?org_id=${ORG_ID}`),
    ]).then(([statsResult, profilesResult, assessmentsResult]) => {
      const stats       = statsResult.status       === "fulfilled" ? statsResult.value       : null;
      const profiles    = profilesResult.status    === "fulfilled" ? profilesResult.value    : null;
      const assessments = assessmentsResult.status === "fulfilled" ? assessmentsResult.value : null;
      if (stats || profiles || assessments) {
        setLiveData({ stats, profiles, assessments });
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
        title="Configuration Benchmarks"
        description="CIS, DISA STIG, and custom hardening assessments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Profiles"          value={liveData?.stats?.total_profiles ?? liveData?.profiles?.length ?? 8}      icon={ClipboardCheck} trend="up" />
        <KpiCard title="Assessments Run"   value={liveData?.stats?.total_assessments ?? liveData?.assessments?.length ?? 34}     icon={Shield}         trend="up" />
        <KpiCard title="Avg Score"         value={liveData?.stats?.avg_score ? `${liveData.stats.avg_score.toFixed(1)}%` : "65.2%"}  icon={BarChart3}      trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Failures" value={liveData?.stats?.critical_failures ?? liveData?.stats?.failed_checks ?? 23}     icon={AlertTriangle}  trend="down" className="border-red-500/20" />
      </div>

      {/* Assessment Profiles */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4 text-blue-400" />
              Assessment Profiles
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">8 profiles</Badge>
          </div>
          <CardDescription className="text-xs">Hardening standard configurations and last assessment results</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Profile Name</TableHead>
                  <TableHead className="text-[11px] h-8">Standard</TableHead>
                  <TableHead className="text-[11px] h-8">Target</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Last Assessed</TableHead>
                  <TableHead className="text-[11px] h-8">Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.profiles ?? PROFILES).map((p: any) => (
                  <TableRow key={p.name ?? p.profile_id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[180px] truncate">{p.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", STANDARD_COLORS[p.standard] ?? "border-border text-muted-foreground")}>{p.standard}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", TARGET_COLORS[p.target ?? p.target_type] ?? "border-border text-muted-foreground")}>{p.target ?? p.target_type}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground font-mono">{p.version}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{p.last_assessed ?? p.created_at ?? "—"}</TableCell>
                    <TableCell className="py-2.5"><ScoreBar score={p.score ?? 0} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Assess Now</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Latest Assessment Results + Score by Standard */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Check Results — spans 2 cols */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="h-4 w-4 text-purple-400" />
                Latest Assessment Results
              </CardTitle>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                <CheckCircle2 className="h-3 w-3 text-green-400" /> Pass
                <XCircle className="h-3 w-3 text-red-400" /> Fail
                <AlertTriangle className="h-3 w-3 text-amber-400" /> Warn
              </div>
            </div>
            <CardDescription className="text-xs">CIS Ubuntu 22.04 L2 — Apr 15 2026</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8 w-8"></TableHead>
                    <TableHead className="text-[11px] h-8">Ref</TableHead>
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">Actual</TableHead>
                    <TableHead className="text-[11px] h-8">Expected</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {CHECK_RESULTS.map((c) => (
                    <TableRow key={c.ref} className="hover:bg-muted/30">
                      <TableCell className="py-2.5 w-8"><StatusIcon status={c.status} /></TableCell>
                      <TableCell className="text-[10px] font-mono py-2.5 text-muted-foreground whitespace-nowrap">{c.ref}</TableCell>
                      <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{c.title}</TableCell>
                      <TableCell className="py-2.5">
                        <Badge className={cn("text-[10px] border", CATEGORY_COLORS[c.category] ?? "border-border text-muted-foreground")}>{c.category}</Badge>
                      </TableCell>
                      <TableCell className="py-2.5"><SevBadge sev={c.severity} /></TableCell>
                      <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground max-w-[100px] truncate">{c.actual}</TableCell>
                      <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground max-w-[100px] truncate">{c.expected}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Score by Standard */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-green-400" />
              Score by Standard
            </CardTitle>
            <CardDescription className="text-xs">Average score across all profiles per standard</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 pt-2">
            {SCORE_BY_STANDARD.map((s) => (
              <div key={s.standard} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{s.standard}</span>
                  <span className={cn("font-bold tabular-nums", s.score >= 80 ? "text-green-400" : s.score >= 60 ? "text-amber-400" : "text-red-400")}>
                    {s.score}%
                  </span>
                </div>
                <div className="h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${s.score}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", s.score >= 80 ? "bg-green-500" : s.score >= 60 ? "bg-amber-500" : "bg-red-500")}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Failed Checks Accordion */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <XCircle className="h-4 w-4" />
              Failed Checks — Remediation Guide
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{FAILED_CHECKS.length} failed</Badge>
          </div>
          <CardDescription className="text-xs">Click a check to expand remediation steps</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {FAILED_CHECKS.map((fc) => {
            const isOpen = expandedCheck === fc.ref;
            return (
              <div key={fc.ref} className="rounded-md border border-border/60 overflow-hidden">
                <button
                  className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-muted/30 transition-colors"
                  onClick={() => setExpandedCheck(isOpen ? null : fc.ref)}
                >
                  {isOpen
                    ? <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                    : <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  }
                  <span className="text-[10px] font-mono text-muted-foreground w-24 shrink-0">{fc.ref}</span>
                  <span className="text-xs flex-1 truncate">{fc.title}</span>
                  <SevBadge sev={fc.severity} />
                </button>
                {isOpen && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="px-4 pb-3 pt-1 border-t border-border/40 bg-muted/10"
                  >
                    <p className="text-xs text-muted-foreground leading-relaxed font-mono whitespace-pre-wrap">{fc.remediation}</p>
                  </motion.div>
                )}
              </div>
            );
          })}
        </CardContent>
      </Card>
    </motion.div>
  );
}
