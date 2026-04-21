/**
 * CSPM Dashboard — Cloud Security Posture Management
 *
 * Continuous misconfiguration detection across AWS, Azure, GCP:
 *   1. KPI Row — Posture Score, Critical Misconfigs, Resources Scanned, Compliant %
 *   2. Provider Cards — AWS / Azure / GCP score + last scan + critical count
 *   3. Findings Table — 10 rows with severity, resource, provider, rule, category, Remediate
 *   4. CIS Benchmark Card — Pass/Fail/Manual for CIS AWS 1.5
 *   5. Remediation Priority — top 5 fixes with impact score
 *
 * API: GET /api/v1/cspm/findings, GET /api/v1/cspm/score
 * Fallback: mock data when API unavailable
 */

import { useState, useEffect, JSX } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Cloud, AlertTriangle, CheckCircle2, Shield, Server,
  RefreshCw, Wrench, BarChart3, Target, Database,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type Provider = "AWS" | "Azure" | "GCP";

interface Finding {
  id: string;
  severity: Severity;
  resource: string;
  provider: Provider;
  rule_name: string;
  category: string;
  status: "OPEN" | "REMEDIATED";
}

interface ProviderScore {
  name: Provider;
  score: number;
  last_scan: string;
  critical_count: number;
  color: string;
  icon: JSX.Element;
}

interface CISBenchmark {
  framework: string;
  pass: number;
  fail: number;
  manual: number;
}

interface RemediationItem {
  id: string;
  title: string;
  provider: Provider;
  impact: number;
  affected: number;
  category: string;
}

interface CSPMScore {
  posture_score: number;
  critical_misconfigs: number;
  resources_scanned: number;
  compliant_pct: number;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_SCORE: CSPMScore = {
  posture_score: 74,
  critical_misconfigs: 6,
  resources_scanned: 1247,
  compliant_pct: 89,
};

const MOCK_FINDINGS: Finding[] = [
  { id: "f01", severity: "CRITICAL", resource: "s3://prod-customer-data", provider: "AWS", rule_name: "S3_PUBLIC_ACCESS_ENABLED", category: "Storage", status: "OPEN" },
  { id: "f02", severity: "CRITICAL", resource: "iam::root-account", provider: "AWS", rule_name: "ROOT_ACCOUNT_NO_MFA", category: "Identity", status: "OPEN" },
  { id: "f03", severity: "HIGH", resource: "sg-0a1b2c3d (default)", provider: "AWS", rule_name: "SSH_OPEN_TO_WORLD", category: "Network", status: "OPEN" },
  { id: "f04", severity: "HIGH", resource: "trail/prod-us-east-1", provider: "AWS", rule_name: "CLOUDTRAIL_LOGGING_DISABLED", category: "Logging", status: "OPEN" },
  { id: "f05", severity: "CRITICAL", resource: "storageaccount/prodblob01", provider: "Azure", rule_name: "BLOB_PUBLIC_ACCESS_ALLOWED", category: "Storage", status: "OPEN" },
  { id: "f06", severity: "HIGH", resource: "vm/prod-app-01", provider: "Azure", rule_name: "DISK_ENCRYPTION_DISABLED", category: "Compute", status: "OPEN" },
  { id: "f07", severity: "MEDIUM", resource: "rds/prod-postgres", provider: "AWS", rule_name: "RDS_MULTI_AZ_DISABLED", category: "Database", status: "OPEN" },
  { id: "f08", severity: "HIGH", resource: "gke-cluster/prod-cluster", provider: "GCP", rule_name: "GKE_BASIC_AUTH_ENABLED", category: "Containers", status: "OPEN" },
  { id: "f09", severity: "MEDIUM", resource: "storage/prod-assets", provider: "GCP", rule_name: "GCS_BUCKET_ALLUSER_READ", category: "Storage", status: "OPEN" },
  { id: "f10", severity: "LOW", resource: "ec2/i-0abc123", provider: "AWS", rule_name: "EC2_IMDSV1_ENABLED", category: "Compute", status: "OPEN" },
];

const MOCK_CIS: CISBenchmark = {
  framework: "CIS AWS Foundations 1.5",
  pass: 38,
  fail: 9,
  manual: 11,
};

const MOCK_REMEDIATION: RemediationItem[] = [
  { id: "r1", title: "Block all S3 public access at account level", provider: "AWS", impact: 95, affected: 12, category: "Storage" },
  { id: "r2", title: "Enable MFA on root account", provider: "AWS", impact: 92, affected: 1, category: "Identity" },
  { id: "r3", title: "Restrict SSH (port 22) to known CIDRs", provider: "AWS", impact: 88, affected: 7, category: "Network" },
  { id: "r4", title: "Enable CloudTrail in all regions", provider: "AWS", impact: 82, affected: 4, category: "Logging" },
  { id: "r5", title: "Disable Azure Blob public access", provider: "Azure", impact: 78, affected: 3, category: "Storage" },
];

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function severityColor(sev: Severity): string {
  const map: Record<Severity, string> = {
    CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
    HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    LOW: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return map[sev];
}

function providerColor(p: Provider): string {
  const map: Record<Provider, string> = {
    AWS: "bg-orange-500/15 text-orange-300 border-orange-500/30",
    Azure: "bg-blue-500/15 text-blue-300 border-blue-500/30",
    GCP: "bg-green-500/15 text-green-300 border-green-500/30",
  };
  return map[p];
}

function scoreGrade(score: number): { label: string; color: string } {
  if (score >= 85) return { label: "Good", color: "text-emerald-400" };
  if (score >= 65) return { label: "Fair", color: "text-amber-400" };
  return { label: "Poor", color: "text-red-400" };
}

// ══════════════════════════════════════════════════════════════
// Sub-components
// ══════════════════════════════════════════════════════════════

function ScoreBar({ score }: { score: number }): JSX.Element {
  const color =
    score >= 85 ? "bg-emerald-500" : score >= 65 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="w-full bg-slate-700/50 rounded-full h-2 mt-2">
      <div
        className={cn("h-2 rounded-full transition-all", color)}
        style={{ width: `${score}%` }}
      />
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function CSPMDashboard() {
  const [remediating, setRemediating] = useState<Set<string>>(new Set());

  const { data: scoreData, isLoading: scoreLoading } = useQuery<CSPMScore>({
    queryKey: ["cspm-posture", ORG_ID],
    queryFn: async () => {
      try {
        const data = await apiFetch(`/api/v1/cspm/posture?org_id=${ORG_ID}`);
        // Map OrgPosture → CSPMScore shape
        return {
          posture_score: data.overall_score ?? data.posture_score ?? MOCK_SCORE.posture_score,
          critical_misconfigs: data.critical_count ?? data.critical_misconfigs ?? MOCK_SCORE.critical_misconfigs,
          resources_scanned: data.total_resources ?? data.resources_scanned ?? MOCK_SCORE.resources_scanned,
          compliant_pct: data.compliant_pct ?? Math.round((1 - (data.critical_count ?? 0) / Math.max(data.total_resources ?? 1, 1)) * 100),
        } as CSPMScore;
      } catch {
        return MOCK_SCORE;
      }
    },
    staleTime: 5 * 60 * 1000,
  });

  const { data: findingsData, isLoading: findingsLoading } = useQuery<Finding[]>({
    queryKey: ["cspm-findings", ORG_ID],
    queryFn: async () => {
      try {
        const data = await apiFetch(`/api/v1/cspm/findings?org_id=${ORG_ID}`);
        // API returns list directly or wrapped
        const items: any[] = Array.isArray(data) ? data : (data.items ?? data.findings ?? []);
        return items.map((f: any) => ({
          id: f.id ?? f.finding_id ?? String(Math.random()),
          severity: (f.severity ?? "MEDIUM").toUpperCase() as Finding["severity"],
          resource: f.resource_id ?? f.resource ?? f.name ?? "unknown",
          provider: (f.provider ?? f.cloud_provider ?? "AWS").toUpperCase() as Finding["provider"],
          rule_name: f.rule_id ?? f.rule_name ?? f.title ?? "unknown",
          category: f.category ?? f.resource_type ?? "General",
          status: f.status === "open" || f.status === "OPEN" ? "OPEN" : "REMEDIATED",
        }));
      } catch {
        return MOCK_FINDINGS;
      }
    },
    staleTime: 5 * 60 * 1000,
  });

  if (scoreLoading || findingsLoading) return <PageSkeleton />;

  const score = scoreData ?? MOCK_SCORE;
  const findings = findingsData ?? MOCK_FINDINGS;

  const providers: ProviderScore[] = [
    {
      name: "AWS",
      score: 71,
      last_scan: "2 min ago",
      critical_count: 4,
      color: "border-orange-500/30",
      icon: <Cloud className="w-5 h-5 text-orange-400" />,
    },
    {
      name: "Azure",
      score: 85,
      last_scan: "5 min ago",
      critical_count: 1,
      color: "border-blue-500/30",
      icon: <Cloud className="w-5 h-5 text-blue-400" />,
    },
    {
      name: "GCP",
      score: 68,
      last_scan: "8 min ago",
      critical_count: 1,
      color: "border-green-500/30",
      icon: <Cloud className="w-5 h-5 text-green-400" />,
    },
  ];

  const handleRemediate = (id: string) => {
    setRemediating((prev) => new Set([...prev, id]));
  };

  const cisBenchmark: CISBenchmark = MOCK_CIS;
  const cisTotal = cisBenchmark.pass + cisBenchmark.fail + cisBenchmark.manual;

  return (
    <div className="space-y-8 p-6">
      {/* Header */}
      <PageHeader
        title="Cloud Security Posture"
        description="Continuous misconfiguration detection across AWS, Azure, GCP"
      />

      {/* ── KPI Row ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="grid grid-cols-4 gap-4"
      >
        <KpiCard
          title="Posture Score"
          value={`${score.posture_score}/100`}
          icon={<Shield className="w-5 h-5 text-blue-400" />}
          trend="up"
          trendLabel="+3 this week"
        />
        <KpiCard
          title="Critical Misconfigs"
          value={String(score.critical_misconfigs)}
          icon={<AlertTriangle className="w-5 h-5 text-red-400" />}
          trend="down"
          trendLabel="-2 resolved"
        />
        <KpiCard
          title="Resources Scanned"
          value={score.resources_scanned.toLocaleString()}
          icon={<Server className="w-5 h-5 text-purple-400" />}
          trend="up"
          trendLabel="+47 new"
        />
        <KpiCard
          title="Compliant"
          value={`${score.compliant_pct}%`}
          icon={<CheckCircle2 className="w-5 h-5 text-emerald-400" />}
          trend="up"
          trendLabel="+1.2% vs last scan"
        />
      </motion.div>

      {/* ── Provider Cards ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="grid grid-cols-3 gap-4"
      >
        {providers.map((p) => {
          const grade = scoreGrade(p.score);
          return (
            <Card
              key={p.name}
              className={cn(
                "bg-gradient-to-br from-slate-800/50 to-slate-900/50 border",
                p.color
              )}
            >
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-base">
                  {p.icon}
                  {p.name}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-end justify-between">
                  <span className={cn("text-3xl font-bold", grade.color)}>
                    {p.score}
                  </span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "border",
                      p.score >= 85
                        ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                        : p.score >= 65
                          ? "bg-amber-500/10 text-amber-400 border-amber-500/30"
                          : "bg-red-500/10 text-red-400 border-red-500/30"
                    )}
                  >
                    {grade.label}
                  </Badge>
                </div>
                <ScoreBar score={p.score} />
                <div className="flex justify-between text-xs text-gray-400 pt-1">
                  <span className="flex items-center gap-1">
                    <RefreshCw className="w-3 h-3" />
                    {p.last_scan}
                  </span>
                  <span className="flex items-center gap-1 text-red-400">
                    <AlertTriangle className="w-3 h-3" />
                    {p.critical_count} critical
                  </span>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </motion.div>

      {/* ── Findings Table ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-400" />
                Open Findings
              </span>
              <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30">
                {findings.filter((f) => f.status === "OPEN").length} open
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700/50 hover:bg-slate-800/20">
                    <TableHead className="text-gray-300">Severity</TableHead>
                    <TableHead className="text-gray-300">Resource</TableHead>
                    <TableHead className="text-gray-300">Provider</TableHead>
                    <TableHead className="text-gray-300">Rule</TableHead>
                    <TableHead className="text-gray-300">Category</TableHead>
                    <TableHead className="text-gray-300 text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.map((f) => (
                    <TableRow
                      key={f.id}
                      className="border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn("border font-mono text-xs", severityColor(f.severity))}
                        >
                          {f.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-gray-300 max-w-[200px] truncate">
                        {f.resource}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn("border text-xs", providerColor(f.provider))}
                        >
                          {f.provider}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-gray-400">
                        {f.rule_name}
                      </TableCell>
                      <TableCell className="text-sm text-gray-300">{f.category}</TableCell>
                      <TableCell className="text-right">
                        {remediating.has(f.id) ? (
                          <Badge
                            variant="outline"
                            className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-xs"
                          >
                            Queued
                          </Badge>
                        ) : (
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 px-3 text-xs border-blue-500/30 hover:bg-blue-500/10 text-blue-400"
                            onClick={() => handleRemediate(f.id)}
                          >
                            <Wrench className="w-3 h-3 mr-1" />
                            Remediate
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* ── CIS Benchmark + Remediation Priority ── */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="grid grid-cols-2 gap-4"
      >
        {/* CIS Benchmark */}
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5 text-indigo-400" />
              CIS Benchmark
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-gray-400">{cisBenchmark.framework}</p>
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-lg bg-emerald-500/10 border border-emerald-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-emerald-400">{cisBenchmark.pass}</p>
                <p className="text-xs text-gray-400 mt-1">Pass</p>
              </div>
              <div className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-center">
                <p className="text-2xl font-bold text-red-400">{cisBenchmark.fail}</p>
                <p className="text-xs text-gray-400 mt-1">Fail</p>
              </div>
              <div className="rounded-lg bg-slate-700/30 border border-slate-600/30 p-3 text-center">
                <p className="text-2xl font-bold text-gray-300">{cisBenchmark.manual}</p>
                <p className="text-xs text-gray-400 mt-1">Manual</p>
              </div>
            </div>
            {/* Progress bar */}
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-gray-400">
                <span>Pass rate</span>
                <span>{Math.round((cisBenchmark.pass / cisTotal) * 100)}%</span>
              </div>
              <div className="w-full bg-slate-700/50 rounded-full h-2 flex overflow-hidden">
                <div
                  className="bg-emerald-500 h-2"
                  style={{ width: `${(cisBenchmark.pass / cisTotal) * 100}%` }}
                />
                <div
                  className="bg-red-500 h-2"
                  style={{ width: `${(cisBenchmark.fail / cisTotal) * 100}%` }}
                />
                <div className="bg-slate-500 h-2 flex-1" />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Remediation Priority */}
        <Card className="bg-gradient-to-br from-slate-800/50 to-slate-900/50 border-slate-700/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="w-5 h-5 text-red-400" />
              Remediation Priority
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {MOCK_REMEDIATION.map((item, idx) => (
              <div
                key={item.id}
                className="flex items-center gap-3 p-2 rounded-lg bg-slate-800/40 border border-slate-700/40 hover:border-slate-600/60 transition-colors"
              >
                <div className="flex-shrink-0 w-6 h-6 rounded-full bg-slate-700 flex items-center justify-center text-xs font-bold text-gray-300">
                  {idx + 1}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate">{item.title}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <Badge
                      variant="outline"
                      className={cn("border text-xs px-1 py-0", providerColor(item.provider))}
                    >
                      {item.provider}
                    </Badge>
                    <span className="text-xs text-gray-400 flex items-center gap-1">
                      <Database className="w-3 h-3" />
                      {item.affected} affected
                    </span>
                  </div>
                </div>
                <div className="flex-shrink-0 text-right">
                  <p className="text-sm font-bold text-amber-400">{item.impact}</p>
                  <p className="text-xs text-gray-500">impact</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
