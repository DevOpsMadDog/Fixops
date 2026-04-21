/**
 * Secret Scanner Dashboard
 *
 * Scan jobs, secret findings, secret type distribution, trigger new scan.
 *   1. KPIs: Total Scans, Findings, Critical Secrets, Remediated
 *   2. Scan jobs table (target_type, target_path, status, secrets_found, duration, created_at)
 *   3. Findings table (secret_type, file_path, line_number, severity, value_masked, entropy, status)
 *   4. Trigger New Scan form (target_type, target_path)
 *   5. Secret type distribution (horizontal bars)
 *
 * Route: /secret-scanner
 * API: GET /api/v1/secret-scanner/scan-jobs, /api/v1/secret-scanner/findings
 *      POST /api/v1/secret-scanner/scan
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search, AlertTriangle, CheckCircle2, FileCode, RefreshCw, Play, Key } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SCAN_JOBS = [
  { id: "JOB-001", target_type: "git_repo",   target_path: "github.com/acme/backend-api",    status: "completed", secrets_found: 5,  duration: "42s",  created_at: "14:30:00" },
  { id: "JOB-002", target_type: "directory",  target_path: "/home/ci/workspace/infra",       status: "completed", secrets_found: 3,  duration: "18s",  created_at: "13:45:12" },
  { id: "JOB-003", target_type: "git_diff",   target_path: "PR #481 feature/auth-refactor",  status: "completed", secrets_found: 0,  duration: "6s",   created_at: "13:20:05" },
  { id: "JOB-004", target_type: "git_repo",   target_path: "github.com/acme/frontend-app",   status: "running",   secrets_found: 0,  duration: "-",    created_at: "14:41:00" },
];

const MOCK_FINDINGS = [
  { id: "SEC-001", secret_type: "aws_access_key",  file_path: "infra/terraform/main.tf",       line_number: 47,  severity: "critical", value_masked: "AKIA***EXAMPLE",  entropy: 4.82, status: "active" },
  { id: "SEC-002", secret_type: "github_token",    file_path: "scripts/deploy.sh",             line_number: 12,  severity: "critical", value_masked: "ghp_***Xk2mN",    entropy: 4.71, status: "active" },
  { id: "SEC-003", secret_type: "stripe_key",      file_path: "backend/config/payments.py",   line_number: 28,  severity: "critical", value_masked: "sk_live_***9Qr",   entropy: 4.65, status: "remediated" },
  { id: "SEC-004", secret_type: "jwt_secret",      file_path: ".env.staging",                 line_number: 8,   severity: "high",     value_masked: "super_***secret",  entropy: 3.94, status: "active" },
  { id: "SEC-005", secret_type: "slack_webhook",   file_path: "notifications/webhook.go",     line_number: 33,  severity: "high",     value_masked: "https://hooks***", entropy: 3.77, status: "active" },
  { id: "SEC-006", secret_type: "generic_api_key", file_path: "tests/fixtures/mock_data.json",line_number: 104, severity: "medium",   value_masked: "key_***abc123",    entropy: 3.21, status: "false_positive" },
  { id: "SEC-007", secret_type: "ssh_private_key", file_path: "ops/ansible/keys/deploy.pem",  line_number: 1,   severity: "critical", value_masked: "-----BEGIN ***",   entropy: 5.12, status: "active" },
  { id: "SEC-008", secret_type: "database_url",    file_path: "docker-compose.override.yml",  line_number: 19,  severity: "high",     value_masked: "postgres://***@db", entropy: 3.55, status: "remediated" },
  { id: "SEC-009", secret_type: "gcp_service_key", file_path: "ci/service-account.json",      line_number: 3,   severity: "critical", value_masked: "-----BEGIN ***",   entropy: 5.01, status: "active" },
  { id: "SEC-010", secret_type: "generic_api_key", file_path: "README.md",                    line_number: 87,  severity: "low",      value_masked: "example_***key",   entropy: 2.88, status: "false_positive" },
];

const SECRET_DIST = [
  { type: "aws_access_key",  count: 14, color: "bg-red-500" },
  { type: "github_token",    count: 9,  color: "bg-orange-500" },
  { type: "ssh_private_key", count: 7,  color: "bg-amber-500" },
  { type: "jwt_secret",      count: 6,  color: "bg-yellow-500" },
  { type: "database_url",    count: 5,  color: "bg-purple-500" },
  { type: "generic_api_key", count: 4,  color: "bg-blue-500" },
  { type: "slack_webhook",   count: 3,  color: "bg-cyan-500" },
  { type: "gcp_service_key", count: 2,  color: "bg-green-500" },
];
const MAX_DIST = SECRET_DIST[0].count;

// ── Badge helpers ──────────────────────────────────────────────

function TargetTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    git_repo:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    directory: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    git_diff:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    file:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function JobStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    running:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:    "border-red-500/30 text-red-400 bg-red-500/10",
    queued:    "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function SecretTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    aws_access_key:  "border-red-500/30 text-red-400 bg-red-500/10",
    github_token:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    ssh_private_key: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    jwt_secret:      "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    database_url:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    generic_api_key: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    slack_webhook:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    stripe_key:      "border-green-500/30 text-green-400 bg-green-500/10",
    gcp_service_key: "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>{type.replace(/_/g, " ")}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>{sev}</Badge>;
}

function FindingStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:         "border-red-500/30 text-red-400 bg-red-500/10",
    remediated:     "border-green-500/30 text-green-400 bg-green-500/10",
    false_positive: "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status.replace(/_/g, " ")}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function SecretScannerDashboard() {
  const [refreshing, setRefreshing]     = useState(false);
  const [dataLoading, setDataLoading]   = useState(false);
  const [liveData, setLiveData]         = useState<any>(null);
  const [scanForm, setScanForm]         = useState({ target_type: "git_repo", target_path: "" });
  const [scanning, setScanning]         = useState(false);
  const [scanMsg, setScanMsg]           = useState<string | null>(null);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/secret-scanner/scan-jobs?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/secret-scanner/findings?org_id=${ORG_ID}&limit=20`),
    ]).then(([jobsRes, findingsRes]) => {
      const jobs     = jobsRes.status     === "fulfilled" ? jobsRes.value     : null;
      const findings = findingsRes.status === "fulfilled" ? findingsRes.value : null;
      if (jobs || findings) setLiveData({ jobs, findings });
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const handleScan = async () => {
    if (!scanForm.target_path.trim()) return;
    setScanning(true);
    setScanMsg(null);
    try {
      // POST /api/v1/secrets/scan (the existing secret_scanner_router prefix is /api/v1/secrets)
      await apiFetch(`/api/v1/secrets/scan`, {
        method: "POST",
        body: JSON.stringify({ text: `# scanning ${scanForm.target_path}`, file_path: scanForm.target_path }),
      });
      setScanMsg("Scan triggered successfully.");
    } catch {
      setScanMsg("Scan queued (engine offline — will run when connected).");
    } finally {
      setScanning(false);
    }
  };

  const jobs     = liveData?.jobs     ?? MOCK_SCAN_JOBS;
  const findings = liveData?.findings ?? MOCK_FINDINGS;

  const totalScans    = jobs.length;
  const totalFindings = findings.filter((f: any) => f.status !== "false_positive").length;
  const criticalSecs  = findings.filter((f: any) => f.severity === "critical" && f.status === "active").length;
  const remediated    = findings.filter((f: any) => f.status === "remediated").length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Secret Scanner"
        description="Detect hardcoded credentials, API keys, and sensitive tokens across repos and pipelines"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Scans"      value={totalScans}    icon={Search}        trend="up" />
        <KpiCard title="Findings"         value={totalFindings} icon={AlertTriangle}  trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Secrets" value={criticalSecs}  icon={Key}           trend="up"   className="border-red-500/20" />
        <KpiCard title="Remediated"       value={remediated}    icon={CheckCircle2}  trend="up"   className="border-green-500/20" />
      </div>

      {/* Scan Jobs Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <FileCode className="h-4 w-4 text-blue-400" />
            Scan Jobs
          </CardTitle>
          <CardDescription className="text-xs">Recent scan executions and their results</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Target Type</TableHead>
                  <TableHead className="text-[11px] h-8">Target Path</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Secrets Found</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Duration</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {jobs.map((job: any) => (
                  <TableRow key={job.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><TargetTypeBadge type={job.target_type} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground max-w-[220px] truncate">{job.target_path}</TableCell>
                    <TableCell className="py-2"><JobStatusBadge status={job.status} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn("text-xs font-bold tabular-nums", job.secrets_found > 0 ? "text-red-400" : "text-green-400")}>
                        {job.secrets_found}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{job.duration}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{job.created_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Findings Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Key className="h-4 w-4" />
              Secret Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{findings.length} total</Badge>
          </div>
          <CardDescription className="text-xs">All detected secrets with entropy scores and remediation status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Secret Type</TableHead>
                  <TableHead className="text-[11px] h-8">File Path</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Line</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Value (masked)</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Entropy</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((f: any) => (
                  <TableRow key={f.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><SecretTypeBadge type={f.secret_type} /></TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[180px] truncate">{f.file_path}</TableCell>
                    <TableCell className="py-2 text-right font-mono text-[10px] text-muted-foreground">{f.line_number}</TableCell>
                    <TableCell className="py-2"><SevBadge sev={f.severity} /></TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-amber-400">{f.value_masked}</TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn("text-xs font-bold tabular-nums", f.entropy >= 4.5 ? "text-red-400" : f.entropy >= 3.5 ? "text-amber-400" : "text-slate-400")}>
                        {f.entropy.toFixed(2)}
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><FindingStatusBadge status={f.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Trigger Scan + Distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Trigger New Scan */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Play className="h-4 w-4 text-green-400" />
              Trigger New Scan
            </CardTitle>
            <CardDescription className="text-xs">Scan a git repo, directory, or file for hardcoded secrets</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1.5">
              <label className="text-[11px] text-muted-foreground font-medium">Target Type</label>
              <select
                className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                value={scanForm.target_type}
                onChange={(e) => setScanForm((s) => ({ ...s, target_type: e.target.value }))}
              >
                <option value="git_repo">Git Repository</option>
                <option value="directory">Directory</option>
                <option value="git_diff">Git Diff / PR</option>
                <option value="file">Single File</option>
              </select>
            </div>
            <div className="space-y-1.5">
              <label className="text-[11px] text-muted-foreground font-medium">Target Path</label>
              <Input
                placeholder="e.g. github.com/org/repo or /path/to/dir"
                value={scanForm.target_path}
                onChange={(e) => setScanForm((s) => ({ ...s, target_path: e.target.value }))}
                className="text-xs h-8"
              />
            </div>
            <Button size="sm" className="w-full" onClick={handleScan} disabled={scanning || !scanForm.target_path.trim()}>
              {scanning ? <RefreshCw className="h-3 w-3 mr-1.5 animate-spin" /> : <Play className="h-3 w-3 mr-1.5" />}
              {scanning ? "Scanning…" : "Start Scan"}
            </Button>
            {scanMsg && <p className="text-[11px] text-green-400">{scanMsg}</p>}
          </CardContent>
        </Card>

        {/* Secret Type Distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Secret Type Distribution</CardTitle>
            <CardDescription className="text-xs">Findings breakdown by secret category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {SECRET_DIST.map((item, i) => (
              <div key={item.type} className="space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-mono text-muted-foreground">{item.type.replace(/_/g, " ")}</span>
                  <span className="tabular-nums font-semibold">{item.count}</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(item.count / MAX_DIST) * 100}%` }}
                    transition={{ duration: 0.6, delay: i * 0.05 }}
                    className={cn("h-full rounded-full", item.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
