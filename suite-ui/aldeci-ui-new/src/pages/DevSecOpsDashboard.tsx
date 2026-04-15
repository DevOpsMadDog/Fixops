/**
 * DevSecOps Dashboard
 *
 * Pipeline security gates, SAST/SCA/secrets scanning, and gate policies.
 *   1. KPIs: Active Pipelines, Pass Rate, Blocked Builds, Critical Findings
 *   2. Pipeline table (10 rows)
 *   3. Build history timeline (8 recent runs)
 *   4. Security findings table (15 rows)
 *   5. Gate policies (6 policies)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { GitBranch, Shield, AlertTriangle, RefreshCw, Code2, CheckCircle2, XCircle, Clock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

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

const PIPELINES = [
  { name: "api-gateway",        ci: "GitHub Actions", branch: "main",    sast: true,  sca: true,  secrets: true,  status: "passed"  },
  { name: "auth-service",       ci: "GitHub Actions", branch: "main",    sast: true,  sca: true,  secrets: true,  status: "blocked" },
  { name: "frontend-app",       ci: "GitHub Actions", branch: "develop", sast: true,  sca: false, secrets: true,  status: "passed"  },
  { name: "data-pipeline",      ci: "GitLab CI",      branch: "main",    sast: false, sca: true,  secrets: false, status: "failed"  },
  { name: "ml-inference",       ci: "Jenkins",        branch: "feature", sast: true,  sca: true,  secrets: false, status: "passed"  },
  { name: "notification-svc",   ci: "CircleCI",       branch: "main",    sast: true,  sca: false, secrets: true,  status: "passed"  },
  { name: "reporting-engine",   ci: "Azure DevOps",   branch: "main",    sast: true,  sca: true,  secrets: true,  status: "blocked" },
  { name: "webhook-processor",  ci: "GitHub Actions", branch: "develop", sast: false, sca: true,  secrets: true,  status: "failed"  },
  { name: "iac-deployer",       ci: "GitLab CI",      branch: "main",    sast: true,  sca: false, secrets: true,  status: "passed"  },
  { name: "legacy-monolith",    ci: "Jenkins",        branch: "main",    sast: false, sca: false, secrets: false, status: "blocked" },
];

const BUILD_HISTORY = [
  { id: "#4821", pipeline: "api-gateway",       status: "passed",  duration: 4.2, findings: 0  },
  { id: "#4820", pipeline: "auth-service",      status: "blocked", duration: 2.8, findings: 3  },
  { id: "#4819", pipeline: "data-pipeline",     status: "failed",  duration: 1.1, findings: 7  },
  { id: "#4818", pipeline: "frontend-app",      status: "passed",  duration: 5.7, findings: 1  },
  { id: "#4817", pipeline: "reporting-engine",  status: "blocked", duration: 3.4, findings: 5  },
  { id: "#4816", pipeline: "notification-svc",  status: "passed",  duration: 2.1, findings: 0  },
  { id: "#4815", pipeline: "webhook-processor", status: "failed",  duration: 0.8, findings: 12 },
  { id: "#4814", pipeline: "ml-inference",      status: "passed",  duration: 6.3, findings: 2  },
];

const FINDINGS = [
  { sev: "Critical", scanner: "SAST",    title: "SQL Injection",              file: "src/db/queries.py",            line: 142, cve: "—",              suppressed: false },
  { sev: "Critical", scanner: "SAST",    title: "Command Injection",          file: "src/utils/shell.py",           line: 87,  cve: "—",              suppressed: false },
  { sev: "Critical", scanner: "SCA",     title: "Log4Shell",                  file: "pom.xml",                      line: 34,  cve: "CVE-2021-44228", suppressed: false },
  { sev: "Critical", scanner: "Secrets", title: "AWS Key Exposed",            file: ".env.backup",                  line: 12,  cve: "—",              suppressed: false },
  { sev: "Critical", scanner: "SCA",     title: "Spring4Shell",               file: "pom.xml",                      line: 41,  cve: "CVE-2022-22965", suppressed: false },
  { sev: "High",     scanner: "SAST",    title: "Path Traversal",             file: "src/files/upload.py",          line: 219, cve: "—",              suppressed: false },
  { sev: "High",     scanner: "SCA",     title: "Prototype Pollution",        file: "package-lock.json",            line: 890, cve: "CVE-2021-23343", suppressed: false },
  { sev: "High",     scanner: "SAST",    title: "SSRF via URL param",         file: "src/webhooks/handler.py",      line: 67,  cve: "—",              suppressed: false },
  { sev: "High",     scanner: "Secrets", title: "GitHub Token in source",     file: "scripts/deploy.sh",            line: 5,   cve: "—",              suppressed: false },
  { sev: "Medium",   scanner: "SAST",    title: "XSS — unescaped output",     file: "src/templates/report.html",   line: 334, cve: "—",              suppressed: false },
  { sev: "Medium",   scanner: "SCA",     title: "ReDoS — vulnerable regex",   file: "requirements.txt",            line: 23,  cve: "CVE-2022-25869", suppressed: true  },
  { sev: "Medium",   scanner: "SAST",    title: "Hardcoded password",         file: "src/config/db.py",             line: 18,  cve: "—",              suppressed: false },
  { sev: "Low",      scanner: "SAST",    title: "Missing security header",    file: "src/middleware/headers.py",    line: 55,  cve: "—",              suppressed: true  },
  { sev: "Low",      scanner: "SCA",     title: "Outdated lodash",            file: "package.json",                 line: 71,  cve: "CVE-2021-23337", suppressed: false },
  { sev: "Low",      scanner: "Secrets", title: "Slack webhook URL",          file: "docs/setup.md",                line: 102, cve: "—",              suppressed: true  },
];

const GATE_POLICIES = [
  { name: "Critical Block",     rule: "block_on_critical = true",         threshold: "0 critical",    color: "text-red-400",    bg: "bg-red-500/10 border-red-500/20"     },
  { name: "High Threshold",     rule: "max_high = 5",                     threshold: "≤5 high",       color: "text-amber-400",  bg: "bg-amber-500/10 border-amber-500/20" },
  { name: "Secrets Gate",       rule: "block_on_secrets = true",          threshold: "0 secrets",     color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20" },
  { name: "SCA OSS Gate",       rule: "block_on_oss_critical = true",     threshold: "0 OSS critical",color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/20"   },
  { name: "Medium Threshold",   rule: "max_medium = 20",                  threshold: "≤20 medium",    color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/20" },
  { name: "Coverage Gate",      rule: "min_sast_coverage = 80",           threshold: "≥80% coverage", color: "text-green-400",  bg: "bg-green-500/10 border-green-500/20" },
];

// ── Helpers ────────────────────────────────────────────────────

const CI_COLORS: Record<string, string> = {
  "GitHub Actions": "border-purple-500/30 text-purple-400 bg-purple-500/10",
  "GitLab CI":      "border-orange-500/30 text-orange-400 bg-orange-500/10",
  "Jenkins":        "border-blue-500/30 text-blue-400 bg-blue-500/10",
  "CircleCI":       "border-green-500/30 text-green-400 bg-green-500/10",
  "Azure DevOps":   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
};

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "passed"  ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "failed"  ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "blocked" ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                           "border-border text-muted-foreground";
  const icon =
    status === "passed"  ? <CheckCircle2 className="h-3 w-3" /> :
    status === "failed"  ? <XCircle className="h-3 w-3" /> :
    status === "blocked" ? <AlertTriangle className="h-3 w-3" /> : null;
  return (
    <Badge className={cn("text-[10px] border flex items-center gap-1", cls)}>
      {icon}{status}
    </Badge>
  );
}

function SevDot({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "bg-red-500" :
    sev === "High"     ? "bg-amber-500" :
    sev === "Medium"   ? "bg-yellow-500" : "bg-green-500";
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", cls)} />;
}

function ScannerBadge({ type }: { type: string }) {
  const cls =
    type === "SAST"    ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "SCA"     ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "Secrets" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

const MAX_DURATION = 7;

// ── Component ──────────────────────────────────────────────────

export default function DevSecOpsDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/devsecops/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/devsecops/pipelines?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/devsecops/findings?org_id=${ORG_ID}&suppressed=false`),
    ]).then(([statsResult, pipelinesResult, findingsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const pipelines = pipelinesResult.status === "fulfilled" ? pipelinesResult.value : null;
      const findings  = findingsResult.status  === "fulfilled" ? findingsResult.value  : null;
      if (stats || pipelines || findings) {
        setLiveData({ stats, pipelines, findings });
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
        title="DevSecOps"
        description="Pipeline security gates, SAST/SCA/secrets scanning, and gate policies"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Pipelines"  value={liveData?.stats?.total_pipelines ?? 12}     icon={GitBranch}     trend="up" />
        <KpiCard title="Pass Rate"         value={liveData?.stats?.pass_rate != null ? `${liveData.stats.pass_rate}%` : "73.4%"}  icon={CheckCircle2}  trend="down" className="border-amber-500/20" />
        <KpiCard title="Blocked Builds"    value={liveData?.stats?.blocked_runs ?? liveData?.stats?.total_blocked ?? 8}      icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Critical Findings" value={liveData?.stats?.critical_findings ?? liveData?.stats?.findings_critical ?? 5}      icon={Shield}        trend="up"   className="border-red-500/20" />
      </div>

      {/* Pipeline Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-blue-400" />
              Active Pipelines
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">10 pipelines</Badge>
          </div>
          <CardDescription className="text-xs">Current scan gate configuration per pipeline</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Pipeline</TableHead>
                  <TableHead className="text-[11px] h-8">CI Platform</TableHead>
                  <TableHead className="text-[11px] h-8">Branch</TableHead>
                  <TableHead className="text-[11px] h-8">SAST</TableHead>
                  <TableHead className="text-[11px] h-8">SCA</TableHead>
                  <TableHead className="text-[11px] h-8">Secrets</TableHead>
                  <TableHead className="text-[11px] h-8">Last Run</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.pipelines?.items ?? liveData?.pipelines ?? PIPELINES).map((row: any) => (
                  <TableRow key={row.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", CI_COLORS[row.ci] ?? "border-border text-muted-foreground")}>{row.ci}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 font-mono text-muted-foreground">{row.branch}</TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-bold", row.sast ? "text-green-400" : "text-muted-foreground/40")}>{row.sast ? "ON" : "OFF"}</span>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-bold", row.sca ? "text-green-400" : "text-muted-foreground/40")}>{row.sca ? "ON" : "OFF"}</span>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-bold", row.secrets ? "text-green-400" : "text-muted-foreground/40")}>{row.secrets ? "ON" : "OFF"}</span>
                    </TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Build History Timeline */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Clock className="h-4 w-4 text-purple-400" />
            Build History Timeline
          </CardTitle>
          <CardDescription className="text-xs">8 most recent pipeline runs — bar width proportional to duration</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {BUILD_HISTORY.map((run) => {
            const widthPct = Math.max(8, (run.duration / MAX_DURATION) * 100);
            const barColor =
              run.status === "passed"  ? "bg-green-500/70" :
              run.status === "blocked" ? "bg-orange-500/70" : "bg-red-500/70";
            return (
              <div key={run.id} className="flex items-center gap-3">
                <span className="text-[10px] font-mono text-muted-foreground w-12 shrink-0">{run.id}</span>
                <span className="text-[10px] text-muted-foreground w-40 shrink-0 truncate">{run.pipeline}</span>
                <div className="flex-1 h-5 bg-muted/20 rounded overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${widthPct}%` }}
                    transition={{ duration: 0.7, ease: "easeOut" }}
                    className={cn("h-full rounded flex items-center px-2", barColor)}
                  >
                    <span className="text-[9px] text-white font-medium whitespace-nowrap">{run.duration}min</span>
                  </motion.div>
                </div>
                <span className={cn("text-[10px] font-bold w-8 text-right tabular-nums shrink-0", run.findings > 0 ? "text-red-400" : "text-muted-foreground")}>
                  {run.findings > 0 ? `+${run.findings}` : "0"}
                </span>
                <StatusBadge status={run.status} />
              </div>
            );
          })}
          <div className="flex items-center gap-4 pt-2 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-green-500/70 inline-block" />Passed</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-orange-500/70 inline-block" />Blocked</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/70 inline-block" />Failed</span>
          </div>
        </CardContent>
      </Card>

      {/* Security Findings Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Code2 className="h-4 w-4 text-red-400" />
              Security Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{(liveData?.findings?.items ?? liveData?.findings ?? FINDINGS).length} findings</Badge>
          </div>
          <CardDescription className="text-xs">Aggregated SAST, SCA, and secrets findings across all pipelines</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-4"></TableHead>
                  <TableHead className="text-[11px] h-8">Scanner</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">File</TableHead>
                  <TableHead className="text-[11px] h-8">Line</TableHead>
                  <TableHead className="text-[11px] h-8">CVE</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.findings?.items ?? liveData?.findings ?? FINDINGS).map((f: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2.5 w-4"><SevDot sev={f.sev} /></TableCell>
                    <TableCell className="py-2.5"><ScannerBadge type={f.scanner} /></TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[180px] truncate">{f.title}</TableCell>
                    <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground max-w-[160px] truncate">{f.file}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{f.line}</TableCell>
                    <TableCell className="text-[10px] py-2.5 font-mono text-muted-foreground">{f.cve}</TableCell>
                    <TableCell className="py-2.5">
                      {f.suppressed
                        ? <Badge className="text-[10px] border border-border text-muted-foreground">suppressed</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">active</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Gate Policies */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-green-400" />
            Gate Policies
          </CardTitle>
          <CardDescription className="text-xs">Active security gate rules — violations block the pipeline</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {GATE_POLICIES.map((p) => (
              <div key={p.name} className={cn("rounded-lg border p-3 space-y-1.5", p.bg)}>
                <span className={cn("text-xs font-semibold", p.color)}>{p.name}</span>
                <div className="font-mono text-[10px] text-muted-foreground bg-muted/30 rounded px-2 py-1">{p.rule}</div>
                <Badge className={cn("text-[10px] border mt-1", p.bg, p.color)}>{p.threshold}</Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
