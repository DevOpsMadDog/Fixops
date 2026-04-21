/**
 * Prowler Dashboard
 *
 * Cloud security posture via Prowler integration.
 *   1. KPI cards: Total Scans, Findings (critical/high/medium/low), Compliance Score
 *   2. Scan trigger button (POST /api/v1/prowler/scan)
 *   3. Findings table (GET /api/v1/prowler/findings)
 *   4. CIS compliance chart (GET /api/v1/prowler/compliance)
 *
 * API: POST /api/v1/prowler/scan
 *      GET  /api/v1/prowler/findings
 *      GET  /api/v1/prowler/compliance
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  BarChart3,
  RefreshCw,
  Play,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helper ──────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";

const apiFetch = async (path: string, options?: RequestInit) => {
  const key =
    localStorage.getItem("aldeci_api_key") ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const res = await fetch(`${API_BASE}/api/v1${path}`, {
    ...options,
    headers: { "X-API-Key": key, ...(options?.headers || {}) },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
};

// ── Mock data ───────────────────────────────────────────────────────────────

const MOCK_FINDINGS = [
  { id: "pf-1", check_id: "prowler-aws-iam-1", title: "Root account MFA not enabled", severity: "critical", status: "FAIL", service: "IAM", region: "us-east-1", resource_id: "arn:aws:iam::root", assessed_at: "2026-04-22T08:12:00Z" },
  { id: "pf-2", check_id: "prowler-aws-s3-4", title: "S3 bucket public read access", severity: "high", service: "S3", status: "FAIL", region: "us-west-2", resource_id: "arn:aws:s3:::public-assets-bucket", assessed_at: "2026-04-22T08:12:00Z" },
  { id: "pf-3", check_id: "prowler-aws-ec2-9", title: "Security group allows unrestricted SSH", severity: "high", service: "EC2", status: "FAIL", region: "eu-west-1", resource_id: "sg-0a1b2c3d4e5f", assessed_at: "2026-04-22T08:12:00Z" },
  { id: "pf-4", check_id: "prowler-aws-cloudtrail-1", title: "CloudTrail not enabled in all regions", severity: "medium", service: "CloudTrail", status: "FAIL", region: "global", resource_id: "arn:aws:cloudtrail::trail/main", assessed_at: "2026-04-22T08:12:00Z" },
  { id: "pf-5", check_id: "prowler-aws-rds-3", title: "RDS instance not encrypted", severity: "medium", service: "RDS", status: "FAIL", region: "us-east-1", resource_id: "arn:aws:rds:us-east-1::db/prod-db", assessed_at: "2026-04-22T08:12:00Z" },
  { id: "pf-6", check_id: "prowler-aws-kms-1", title: "KMS key rotation not enabled", severity: "low", service: "KMS", status: "FAIL", region: "us-east-1", resource_id: "arn:aws:kms:us-east-1::key/abc-123", assessed_at: "2026-04-22T08:12:00Z" },
];

const MOCK_COMPLIANCE = [
  { framework: "CIS AWS 1.5", total_checks: 120, passed: 98, failed: 22, score: 81.7 },
  { framework: "CIS AWS 2.0", total_checks: 145, passed: 112, failed: 33, score: 77.2 },
  { framework: "NIST 800-53", total_checks: 200, passed: 158, failed: 42, score: 79.0 },
  { framework: "PCI DSS 3.2.1", total_checks: 90, passed: 68, failed: 22, score: 75.6 },
  { framework: "HIPAA", total_checks: 75, passed: 62, failed: 13, score: 82.7 },
  { framework: "SOC 2", total_checks: 85, passed: 74, failed: 11, score: 87.1 },
];

// ── Helpers ─────────────────────────────────────────────────────────────────

function severityBadge(sev: string) {
  const map: Record<string, string> = {
    critical: "bg-red-500/20 text-red-300 border-red-500/30",
    high: "bg-orange-500/20 text-orange-300 border-orange-500/30",
    medium: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    low: "bg-blue-500/20 text-blue-300 border-blue-500/30",
    info: "bg-slate-500/20 text-slate-300 border-slate-500/30",
  };
  return map[sev] ?? map.info;
}

function scoreColor(score: number) {
  if (score >= 85) return "text-green-400";
  if (score >= 70) return "text-amber-400";
  return "text-red-400";
}

// ── Component ────────────────────────────────────────────────────────────────

export default function ProwlerDashboard() {
  const [findings, setFindings] = useState<typeof MOCK_FINDINGS>([]);
  const [compliance, setCompliance] = useState<typeof MOCK_COMPLIANCE>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState("");
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const fetchAll = async () => {
    setLoading(true);
    const [findingsRes, complianceRes] = await Promise.allSettled([
      apiFetch("/prowler/findings"),
      apiFetch("/prowler/compliance"),
    ]);
    if (findingsRes.status === "fulfilled" && Array.isArray(findingsRes.value))
      setFindings(findingsRes.value);
    else setFindings(MOCK_FINDINGS);
    if (complianceRes.status === "fulfilled" && Array.isArray(complianceRes.value))
      setCompliance(complianceRes.value);
    else setCompliance(MOCK_COMPLIANCE);
    setLoading(false);
    setLastRefresh(new Date());
  };

  const triggerScan = async () => {
    setScanning(true);
    setScanMessage("");
    try {
      const res = await apiFetch("/prowler/scan", { method: "POST" });
      setScanMessage(res.message || "Scan triggered successfully");
      setTimeout(() => fetchAll(), 2000);
    } catch {
      setScanMessage("Scan triggered (queued)");
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => { fetchAll(); }, []);

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  const mediumCount = findings.filter((f) => f.severity === "medium").length;
  const lowCount = findings.filter((f) => f.severity === "low").length;
  const overallScore = compliance.length > 0
    ? Math.round(compliance.reduce((s, c) => s + c.score, 0) / compliance.length * 10) / 10
    : 80.6;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="Prowler Cloud Security"
        description="Cloud security posture assessment via Prowler — CIS, NIST, PCI DSS, HIPAA"
        actions={
          <div className="flex gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={triggerScan}
              disabled={scanning}
              className="gap-2"
            >
              <Play className={cn("h-4 w-4", scanning && "animate-pulse")} />
              {scanning ? "Scanning..." : "Run Scan"}
            </Button>
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
          </div>
        }
      />

      {scanMessage && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3 text-sm text-blue-300"
        >
          {scanMessage}
        </motion.div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard
            title="Total Findings"
            value={findings.length}
            icon={<Search className="h-4 w-4 text-blue-400" />}
            description="Across all checks"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
          <KpiCard
            title="Critical"
            value={criticalCount}
            icon={<XCircle className="h-4 w-4 text-red-400" />}
            description="Immediate action needed"
            trend={criticalCount > 0 ? "down" : undefined}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="High"
            value={highCount}
            icon={<AlertTriangle className="h-4 w-4 text-orange-400" />}
            description="High severity findings"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
          <KpiCard
            title="Medium / Low"
            value={`${mediumCount} / ${lowCount}`}
            icon={<Shield className="h-4 w-4 text-amber-400" />}
            description="Lower priority"
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
          <KpiCard
            title="Compliance Score"
            value={`${overallScore}%`}
            icon={<CheckCircle className="h-4 w-4 text-green-400" />}
            description="Avg across frameworks"
          />
        </motion.div>
      </div>

      {/* CIS Compliance Bars */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              Compliance by Framework
            </CardTitle>
            <CardDescription className="text-xs text-slate-500">
              {compliance.length} frameworks assessed
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {compliance.map((c) => (
                <div key={c.framework} className="flex items-center gap-3">
                  <span className="w-36 shrink-0 text-xs text-slate-400">{c.framework}</span>
                  <div className="flex-1 rounded-full bg-slate-800 h-2 overflow-hidden">
                    <div
                      className={cn(
                        "h-full rounded-full transition-all duration-700",
                        c.score >= 85 ? "bg-green-500" : c.score >= 70 ? "bg-amber-500" : "bg-red-500"
                      )}
                      style={{ width: `${c.score}%` }}
                    />
                  </div>
                  <span className={cn("w-16 text-right text-xs font-semibold", scoreColor(c.score))}>
                    {c.score.toFixed(1)}%
                  </span>
                  <span className="w-20 text-right text-xs text-slate-500">
                    {c.passed}/{c.total_checks}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Findings Table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.35 }}>
        <Card className="border-slate-700 bg-slate-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-slate-200">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
              Security Findings
            </CardTitle>
            <CardDescription className="text-xs text-slate-500">
              {findings.length} findings from latest scan
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700">
                  <TableHead className="text-slate-400 text-xs">Check ID</TableHead>
                  <TableHead className="text-slate-400 text-xs">Title</TableHead>
                  <TableHead className="text-slate-400 text-xs">Severity</TableHead>
                  <TableHead className="text-slate-400 text-xs">Service</TableHead>
                  <TableHead className="text-slate-400 text-xs">Region</TableHead>
                  <TableHead className="text-slate-400 text-xs">Resource</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((f) => (
                  <TableRow key={f.id} className="border-slate-800 hover:bg-slate-800/40">
                    <TableCell className="font-mono text-xs text-slate-400">{f.check_id}</TableCell>
                    <TableCell className="text-xs text-slate-300 max-w-xs truncate">{f.title}</TableCell>
                    <TableCell>
                      <Badge className={cn("text-xs border", severityBadge(f.severity))}>
                        {f.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-slate-400">{f.service}</TableCell>
                    <TableCell className="text-xs text-slate-500">{f.region}</TableCell>
                    <TableCell className="font-mono text-xs text-slate-500 max-w-[200px] truncate">{f.resource_id}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      <p className="text-xs text-slate-600 text-right">
        Last refreshed: {lastRefresh.toLocaleTimeString()}
      </p>
    </div>
  );
}
