/**
 * Compliance Gap Dashboard
 *
 * Control gaps across security frameworks.
 *   1. KPI cards: Total Assessments, Open Gaps, Critical Gaps, Avg Remediation Hours
 *   2. Framework compliance score grid (SOC2/ISO27001/NIST/PCI-DSS/HIPAA/GDPR)
 *   3. Gap table: Control ID, Name, Framework, Severity, Status, Description
 *
 * API: GET /api/v1/compliance-gaps/{stats,assessments,gaps}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, RefreshCw, AlertTriangle, CheckCircle, Clock, FileText,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
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

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_assessments: 12,
  open_gaps: 34,
  critical_gaps: 7,
  avg_remediation_hours: 48.5,
};

const MOCK_FRAMEWORKS = [
  { name: "SOC 2",    compliance_pct: 82 },
  { name: "ISO 27001",compliance_pct: 76 },
  { name: "NIST CSF", compliance_pct: 91 },
  { name: "PCI-DSS",  compliance_pct: 68 },
  { name: "HIPAA",    compliance_pct: 74 },
  { name: "GDPR",     compliance_pct: 85 },
];

const MOCK_GAPS = [
  { control_id: "CC6.1",   control_name: "Logical Access Controls",       framework: "SOC 2",    severity: "critical", status: "open",            description: "Privileged accounts lack MFA enforcement across all systems" },
  { control_id: "A.9.4.2", control_name: "Secure Log-On Procedures",      framework: "ISO 27001",severity: "high",     status: "in_remediation",  description: "Login attempt logging incomplete for legacy services" },
  { control_id: "PR.AC-4", control_name: "Access Permissions Management", framework: "NIST CSF", severity: "medium",   status: "open",            description: "Role-based access review cadence does not meet quarterly requirement" },
  { control_id: "REQ-8.3", control_name: "Strong Cryptography",           framework: "PCI-DSS",  severity: "critical", status: "open",            description: "TLS 1.0/1.1 still enabled on 3 payment processing endpoints" },
  { control_id: "164.312", control_name: "Audit Controls",                framework: "HIPAA",    severity: "high",     status: "open",            description: "PHI access logs not retained for full 6-year period" },
  { control_id: "Art.32",  control_name: "Security of Processing",        framework: "GDPR",     severity: "medium",   status: "in_remediation",  description: "Encryption at rest not applied to all personal data stores" },
  { control_id: "CC7.2",   control_name: "System Monitoring",             framework: "SOC 2",    severity: "low",      status: "remediated",      description: "Alerting threshold for anomalous logins tuned and verified" },
  { control_id: "REQ-6.3", control_name: "Security Vulnerability Mgmt",  framework: "PCI-DSS",  severity: "high",     status: "open",            description: "Patch SLA for critical CVEs exceeded in Q1 for 2 systems" },
  { control_id: "A.12.6.1","control_name": "Management of Technical Vulns", framework: "ISO 27001",severity: "medium", status: "in_remediation",  description: "Vulnerability scanning schedule gap for DMZ segment" },
  { control_id: "PR.DS-1", control_name: "Data-at-Rest Protection",       framework: "NIST CSF", severity: "low",      status: "open",            description: "Non-production S3 buckets missing encryption policy tag" },
];

// ── Helpers ────────────────────────────────────────────────────

function complianceColor(pct: number): string {
  if (pct >= 85) return "text-green-400";
  if (pct >= 70) return "text-yellow-400";
  return "text-red-400";
}

function complianceBar(pct: number): string {
  if (pct >= 85) return "bg-green-500";
  if (pct >= 70) return "bg-yellow-500";
  return "bg-red-500";
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function GapStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:           "border-red-500/30 text-red-400 bg-red-500/10",
    in_remediation: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    remediated:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ComplianceGapDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    assessments: any[] | null;
    gaps: any[] | null;
  }>({ stats: null, assessments: null, gaps: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/compliance-gaps/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance-gaps/assessments?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/compliance-gaps/gaps?org_id=${ORG_ID}`),
    ]).then(([statsRes, assessRes, gapsRes]) => {
      setLiveData({
        stats:       statsRes.status  === "fulfilled" ? statsRes.value  : null,
        assessments: assessRes.status === "fulfilled" ? assessRes.value : null,
        gaps:        gapsRes.status   === "fulfilled" ? gapsRes.value   : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats       = liveData.stats       ?? MOCK_STATS;
  const frameworks  = liveData.assessments ?? MOCK_FRAMEWORKS;
  const gaps        = liveData.gaps        ?? MOCK_GAPS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
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
        title="Compliance Gap Analysis"
        description="Control gaps across security frameworks"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assessments"      value={stats.total_assessments}                    icon={FileText}      trend="flat"   />
        <KpiCard title="Open Gaps"              value={stats.open_gaps}                             icon={AlertTriangle} trend="down"   className="border-red-500/20" />
        <KpiCard title="Critical Gaps"          value={stats.critical_gaps}                         icon={Shield}        trend="down"   className="border-orange-500/20" />
        <KpiCard title="Avg Remediation (hrs)"  value={stats.avg_remediation_hours.toFixed(1)}      icon={Clock}         trend="flat"   className="border-blue-500/20" />
      </div>

      {/* Framework Scores Grid */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            Framework Compliance Scores
          </CardTitle>
          <CardDescription className="text-xs">Control coverage across all active frameworks</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
            {frameworks.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              frameworks.map((fw: any, i: number) => {
              const pct = fw.compliance_pct ?? 0;
              return (
                <motion.div
                  key={fw.name ?? i}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: i * 0.06 }}
                  className="rounded-lg border border-border bg-muted/10 p-4 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold">{fw.name}</span>
                    <span className={cn("text-lg font-bold tabular-nums", complianceColor(pct))}>
                      {pct}%
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ duration: 0.7, delay: i * 0.06 }}
                      ))
                    )}
                    />
                  </div>
                  <div className="text-[10px] text-muted-foreground">
                    {pct >= 85 ? "Compliant" : pct >= 70 ? "Partial compliance" : "Significant gaps"}
                  </div>
                </motion.div>
              );
            })
            )}
          </div>
        </CardContent>
      </Card>

      {/* Gaps Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Control Gaps
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {gaps.filter((g: any) => g.severity === "critical").length} critical
              </Badge>
              <Badge className="text-[10px] border border-border text-muted-foreground">
                {gaps.length} total
              </Badge>
            </div>
          </div>
          <CardDescription className="text-xs">Open and in-remediation control gaps requiring attention</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Control ID</TableHead>
                  <TableHead className="text-[11px] h-8">Control Name</TableHead>
                  <TableHead className="text-[11px] h-8">Framework</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gaps.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  gaps.map((g: any, i: number) => (
                  <TableRow key={g.control_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground whitespace-nowrap">{g.control_id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium whitespace-nowrap">{g.control_name}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-border text-muted-foreground whitespace-nowrap">
                        {g.framework}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={g.severity ?? "low"} /></TableCell>
                    <TableCell className="py-2"><GapStatusBadge status={g.status ?? "open"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[280px] truncate" title={g.description}>
                      {g.description}
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
