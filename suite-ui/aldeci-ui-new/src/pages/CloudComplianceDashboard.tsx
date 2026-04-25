/**
 * Cloud Compliance Dashboard
 *
 * Multi-cloud compliance posture across AWS / Azure / GCP.
 *   1. KPI cards: Frameworks Assessed, Controls Passed, Controls Failed, Overall Score
 *   2. Assessments table (frameworks with pass/fail/score)
 *   3. Failed controls table (severity + remediation)
 *   4. Remediation plans list
 *
 * API: GET /api/v1/cloud-compliance/stats
 *      GET /api/v1/cloud-compliance/assessments
 *      GET /api/v1/cloud-compliance/controls?status=failed
 *      GET /api/v1/cloud-compliance/remediation-plans
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Cloud,
  CheckCircle,
  XCircle,
  BarChart3,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  ClipboardList,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helper ──────────────────────────────────────────────────────────────
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

const ORG_ID = "juice-shop-corp";

const apiFetch = async (path: string) => {
  const sep = path.includes("?") ? "&" : "?";
  const res = await fetch(buildApiUrl(`/api/v1${path}${sep}org_id=${ORG_ID}`), {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": getStoredOrgId() },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
};

// ── Mock data ───────────────────────────────────────────────────────────────

const MOCK_STATS = {
  assessments_run: 12,
  frameworks_assessed: 6,
  total_controls: 480,
  pass_rate: 78.5,
  critical_failures: 7,
  remediation_plans_active: 14,
  avg_score_by_framework: {
    cis_aws_v1_5: 84.2,
    cis_azure_v1_5: 79.1,
    nist_800_53: 72.6,
    soc2: 88.0,
    pci_dss: 65.4,
    hipaa: 70.3,
  },
};

const MOCK_ASSESSMENTS = [
  { id: "a1", cloud_provider: "aws",   framework: "cis_aws_v1.5",  status: "completed", passed: 112, failed: 21, not_applicable: 7, score: 84.2, assessed_at: "2026-04-16T06:00:00Z" },
  { id: "a2", cloud_provider: "azure", framework: "cis_azure_v1.5", status: "completed", passed: 95,  failed: 25, not_applicable: 3, score: 79.1, assessed_at: "2026-04-15T22:00:00Z" },
  { id: "a3", cloud_provider: "aws",   framework: "nist_800_53",    status: "completed", passed: 87,  failed: 33, not_applicable: 12, score: 72.6, assessed_at: "2026-04-15T18:00:00Z" },
  { id: "a4", cloud_provider: "aws",   framework: "soc2",           status: "completed", passed: 44,  failed: 6,  not_applicable: 2, score: 88.0, assessed_at: "2026-04-14T08:00:00Z" },
  { id: "a5", cloud_provider: "gcp",   framework: "pci_dss",        status: "completed", passed: 74,  failed: 39, not_applicable: 5, score: 65.4, assessed_at: "2026-04-13T12:00:00Z" },
  { id: "a6", cloud_provider: "azure", framework: "hipaa",          status: "running",   passed: 61,  failed: 29, not_applicable: 8, score: 70.3, assessed_at: null },
];

const MOCK_FAILED_CONTROLS = [
  { id: "c1", control_id: "CIS-1.4",  control_name: "Root account MFA",            severity: "critical", status: "failed", section: "IAM",        region: "us-east-1",  remediation: "Enable MFA on root account immediately" },
  { id: "c2", control_id: "CIS-2.1",  control_name: "CloudTrail multi-region",     severity: "high",     status: "failed", section: "Logging",     region: "us-west-2",  remediation: "Enable CloudTrail in all regions" },
  { id: "c3", control_id: "PCI-6.2",  control_name: "Patch management policy",     severity: "critical", status: "failed", section: "Maintenance", region: "global",     remediation: "Apply critical patches within 30 days" },
  { id: "c4", control_id: "NIST-AC-2", control_name: "Account management review", severity: "high",     status: "failed", section: "Access",      region: "global",     remediation: "Quarterly review of privileged accounts" },
  { id: "c5", control_id: "CIS-4.3",  control_name: "SSH access restricted",       severity: "high",     status: "failed", section: "Networking",  region: "eu-west-1",  remediation: "Restrict SSH to bastion host only" },
  { id: "c6", control_id: "HIPAA-164.312", control_name: "PHI encryption at rest", severity: "critical", status: "failed", section: "Encryption",  region: "us-east-1",  remediation: "Enable AES-256 on all PHI storage" },
  { id: "c7", control_id: "SOC2-CC6.6", control_name: "Boundary protection",       severity: "medium",   status: "failed", section: "Security",    region: "ap-east-1",  remediation: "Review WAF rules and network ACLs" },
];

const MOCK_REMEDIATION_PLANS = [
  { id: "r1", control_id: "CIS-1.4",   priority: "p1", assigned_team: "CloudSec",  status: "in_progress", estimated_effort: "low",    target_date: "2026-04-17" },
  { id: "r2", control_id: "PCI-6.2",   priority: "p1", assigned_team: "InfraSec",  status: "planned",     estimated_effort: "high",   target_date: "2026-04-20" },
  { id: "r3", control_id: "CIS-2.1",   priority: "p2", assigned_team: "CloudOps",  status: "planned",     estimated_effort: "medium", target_date: "2026-04-19" },
  { id: "r4", control_id: "HIPAA-164.312", priority: "p1", assigned_team: "DataSec", status: "in_progress", estimated_effort: "high", target_date: "2026-04-18" },
  { id: "r5", control_id: "NIST-AC-2", priority: "p2", assigned_team: "IAM Team",  status: "planned",     estimated_effort: "medium", target_date: "2026-04-22" },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

const PROVIDER_LABELS: Record<string, string> = {
  aws: "AWS", azure: "Azure", gcp: "GCP", multi: "Multi-Cloud",
};

const FRAMEWORK_LABELS: Record<string, string> = {
  "cis_aws_v1.5": "CIS AWS v1.5",
  "cis_aws_v1_5": "CIS AWS v1.5",
  "cis_azure_v1.5": "CIS Azure v1.5",
  "cis_azure_v1_5": "CIS Azure v1.5",
  "cis_gcp_v1.3": "CIS GCP v1.3",
  nist_800_53: "NIST 800-53",
  soc2: "SOC 2",
  pci_dss: "PCI DSS",
  hipaa: "HIPAA",
  iso27001: "ISO 27001",
};

function fmLabel(fw: string) {
  return FRAMEWORK_LABELS[fw] ?? fw.toUpperCase().replace(/_/g, " ");
}

function scoreColor(score: number) {
  if (score >= 85) return "text-green-400";
  if (score >= 70) return "text-amber-400";
  return "text-red-400";
}

function scoreBg(score: number) {
  if (score >= 85) return "bg-green-500/10 border-green-500/30";
  if (score >= 70) return "bg-amber-500/10 border-amber-500/30";
  return "bg-red-500/10 border-red-500/30";
}

function severityBadge(sev: string) {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-300 border-red-500/30",
    high:     "bg-orange-500/20 text-orange-300 border-orange-500/30",
    medium:   "bg-amber-500/20 text-amber-300 border-amber-500/30",
    low:      "bg-blue-500/20 text-blue-300 border-blue-500/30",
    info:     "bg-slate-500/20 text-slate-300 border-slate-500/30",
  };
  return map[sev] ?? map.info;
}

function priorityBadge(p: string) {
  const map: Record<string, string> = {
    p1: "bg-red-500/20 text-red-300 border-red-500/30",
    p2: "bg-orange-500/20 text-orange-300 border-orange-500/30",
    p3: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    p4: "bg-slate-500/20 text-slate-300 border-slate-500/30",
  };
  return map[p] ?? map.p3;
}

function statusBadge(s: string) {
  const map: Record<string, string> = {
    completed:   "bg-green-500/20 text-green-300 border-green-500/30",
    running:     "bg-blue-500/20 text-blue-300 border-blue-500/30",
    failed:      "bg-red-500/20 text-red-300 border-red-500/30",
    in_progress: "bg-blue-500/20 text-blue-300 border-blue-500/30",
    planned:     "bg-slate-500/20 text-slate-300 border-slate-500/30",
    deferred:    "bg-purple-500/20 text-purple-300 border-purple-500/30",
    completed_r: "bg-green-500/20 text-green-300 border-green-500/30",
  };
  return map[s] ?? map.planned;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function CloudComplianceDashboard() {
  const [stats, setStats] = useState<any | null>(null);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [failedControls, setFailedControls] = useState<any[]>([]);
  const [remPlans, setRemPlans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchAll = async () => {
    setLoading(true);
    const [statsRes, assRes, ctrlRes, remRes] = await Promise.allSettled([
      apiFetch("/cloud-compliance/stats"),
      apiFetch("/cloud-compliance/assessments"),
      apiFetch("/cloud-compliance/controls?status=failed"),
      apiFetch("/cloud-compliance/remediation-plans"),
    ]);
    const norm = (v: any) => Array.isArray(v) ? v : (v?.items ?? []);
    if (statsRes.status === "fulfilled") setStats(statsRes.value); else setStats(null);
    setAssessments(assRes.status === "fulfilled" ? norm(assRes.value) : []);
    setFailedControls(ctrlRes.status === "fulfilled" ? norm(ctrlRes.value) : []);
    setRemPlans(remRes.status === "fulfilled" ? norm(remRes.value) : []);
    setLoading(false);
    setLastRefresh(new Date());
  };

  useEffect(() => { fetchAll(); }, []);

  if (loading && !stats) return <PageSkeleton />;

  const liveStats = stats ?? { assessments_run: 0, frameworks_assessed: 0, total_controls: 0, pass_rate: 0, critical_failures: 0, remediation_plans_active: 0, avg_score_by_framework: {} };
  const totalPassed = assessments.reduce((s, a) => s + (a.passed ?? 0), 0);
  const totalFailed = assessments.reduce((s, a) => s + (a.failed ?? 0), 0);
  const overallScore = assessments.length > 0
    ? Math.round(assessments.reduce((s, a) => s + (a.score ?? 0), 0) / assessments.length * 10) / 10
    : (liveStats.pass_rate ?? 0);

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Cloud Compliance"
        description="Multi-cloud compliance posture — AWS, Azure, GCP"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={fetchAll}
            disabled={loading}
            className="gap-2"
          >
            <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard
            title="Frameworks Assessed"
            value={liveStats.frameworks_assessed ?? 0}
            icon={<BarChart3 className="h-4 w-4 text-blue-400" />}
            description="Unique frameworks scanned"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <KpiCard
            title="Controls Passed"
            value={totalPassed}
            icon={<CheckCircle className="h-4 w-4 text-green-400" />}
            description="Across all assessments"
            trend="up"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="Controls Failed"
            value={totalFailed}
            icon={<XCircle className="h-4 w-4 text-red-400" />}
            description={`${liveStats.critical_failures ?? 0} critical`}
            trend="down"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard
            title="Overall Score"
            value={`${overallScore}%`}
            icon={<ShieldCheck className="h-4 w-4 text-amber-400" />}
            description="Avg across frameworks"
          />
        </motion.div>
      </div>

      {/* Framework Score Bars */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Compliance Score by Framework
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(liveStats.avg_score_by_framework ?? {}).map(([fw, score]) => (
                <div key={fw} className="flex items-center gap-3">
                  <span className="w-32 shrink-0 text-xs text-slate-400">{fmLabel(fw)}</span>
                  <div className="flex-1 rounded-full bg-slate-800 h-2 overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-700",
                        score >= 85 ? "bg-green-500" : score >= 70 ? "bg-amber-500" : "bg-red-500"
                      )}
                      style={{ width: `${score}%` }}
                    />
                  </div>
                  <span className={cn("w-12 text-right text-xs font-semibold", scoreColor(score as number))}>
                    {(score as number).toFixed(1)}%
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Assessments Table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <ClipboardList className="h-4 w-4 text-blue-400" />
              Compliance Assessments
            </CardTitle>
            <CardDescription className="text-xs text-slate-500">
              {assessments.length} assessments across {liveStats.frameworks_assessed} frameworks
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700">
                  <TableHead className="text-slate-400 text-xs">Provider</TableHead>
                  <TableHead className="text-slate-400 text-xs">Framework</TableHead>
                  <TableHead className="text-slate-400 text-xs">Status</TableHead>
                  <TableHead className="text-slate-400 text-xs text-right">Passed</TableHead>
                  <TableHead className="text-slate-400 text-xs text-right">Failed</TableHead>
                  <TableHead className="text-slate-400 text-xs text-right">Score</TableHead>
                  <TableHead className="text-slate-400 text-xs">Last Assessed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assessments.map((a) => (
                  <TableRow key={a.id} className="border-slate-800 hover:bg-slate-800/40">
                    <TableCell className="text-xs font-medium text-slate-300">
                      {PROVIDER_LABELS[a.cloud_provider] ?? a.cloud_provider.toUpperCase()}
                    </TableCell>
                    <TableCell className="text-xs text-slate-300">{fmLabel(a.framework)}</TableCell>
                    <TableCell>
                      <Badge className={cn("text-xs border", statusBadge(a.status))}>
                        {a.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right text-xs text-green-400">{a.passed}</TableCell>
                    <TableCell className="text-right text-xs text-red-400">{a.failed}</TableCell>
                    <TableCell className="text-right">
                      <span className={cn("text-xs font-bold", scoreColor(a.score))}>
                        {a.score.toFixed(1)}%
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-slate-500">
                      {a.assessed_at ? new Date(a.assessed_at).toLocaleDateString() : "In progress"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      {/* Failed Controls + Remediation Plans side-by-side */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* Failed Controls */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
          <Card className="border-slate-700 bg-slate-900/50 h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <XCircle className="h-4 w-4 text-red-400" />
                Failed Controls
              </CardTitle>
              <CardDescription className="text-xs text-slate-500">
                {failedControls.length} failures — {liveStats.critical_failures ?? 0} critical
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {failedControls.map((c) => (
                  <div
                    key={c.id}
                    className={cn(
                      "rounded-lg border p-3 text-xs",
                      c.severity === "critical"
                        ? "border-red-500/30 bg-red-500/5"
                        : c.severity === "high"
                        ? "border-orange-500/30 bg-orange-500/5"
                        : "border-slate-700 bg-slate-800/30"
                    )}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-slate-400">{c.control_id}</span>
                        <Badge className={cn("text-xs border", severityBadge(c.severity))}>
                          {c.severity}
                        </Badge>
                      </div>
                      <span className="text-slate-500 shrink-0">{c.region}</span>
                    </div>
                    <p className="font-medium text-slate-200 mb-1">{c.control_name}</p>
                    <p className="text-slate-500 line-clamp-2">{c.remediation}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Remediation Plans */}
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}>
          <Card className="border-slate-700 bg-slate-900/50 h-full">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                Active Remediation Plans
              </CardTitle>
              <CardDescription className="text-xs text-slate-500">
                {liveStats.remediation_plans_active ?? 0} plans in progress or planned
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700">
                    <TableHead className="text-slate-400 text-xs">Control</TableHead>
                    <TableHead className="text-slate-400 text-xs">Priority</TableHead>
                    <TableHead className="text-slate-400 text-xs">Team</TableHead>
                    <TableHead className="text-slate-400 text-xs">Status</TableHead>
                    <TableHead className="text-slate-400 text-xs">Target</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {remPlans.map((r) => (
                    <TableRow key={r.id} className="border-slate-800 hover:bg-slate-800/40">
                      <TableCell className="font-mono text-xs text-slate-300">{r.control_id}</TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs border", priorityBadge(r.priority))}>
                          {r.priority.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-slate-400">{r.assigned_team}</TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs border", statusBadge(r.status))}>
                          {r.status.replace("_", " ")}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-slate-500">{r.target_date}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <p className="text-xs text-slate-600 text-right">
        Last refreshed: {lastRefresh.toLocaleTimeString()}
      </p>
    </div>
  );
}
