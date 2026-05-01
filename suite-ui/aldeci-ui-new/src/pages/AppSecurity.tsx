// FOLDED into AppLayerSecurityHub at /discover/app-security?tab=web (Phase 3, 2026-05-02)
/**
 * Application Security (AppSec) Dashboard
 *
 * SAST/DAST scan results and finding management.
 *   1. KPIs: Applications, Total Scans, Open Findings, Critical
 *   2. Application table (8 rows)
 *   3. OWASP Top 10 breakdown — horizontal bars
 *   4. Recent scan results (10 scans)
 *   5. Critical findings table (8 rows)
 *
 * API stubs: GET /api/v1/appsec/apps, /api/v1/appsec/scans, /api/v1/appsec/findings
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Code2, Shield, AlertTriangle, Bug, RefreshCw, BarChart3, Zap, Search,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY  = import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID   = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
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

const APPLICATIONS = [
  { name: "ALDECI Core API",      type: "api",    stack: ["Python", "FastAPI"], risk: "High",     lastScan: "2026-04-16 06:00", findings: 47 },
  { name: "Portal Web App",       type: "web",    stack: ["React", "Node.js"], risk: "Medium",    lastScan: "2026-04-15 22:00", findings: 31 },
  { name: "Mobile SDK (iOS)",     type: "mobile", stack: ["Swift", "Obj-C"],   risk: "Low",       lastScan: "2026-04-15 18:00", findings: 8  },
  { name: "Auth Service",         type: "api",    stack: ["Go", "JWT"],        risk: "Critical",  lastScan: "2026-04-16 00:00", findings: 62 },
  { name: "Admin Dashboard",      type: "web",    stack: ["React", "Vite"],    risk: "Medium",    lastScan: "2026-04-14 20:00", findings: 19 },
  { name: "Mobile SDK (Android)", type: "mobile", stack: ["Kotlin", "Java"],   risk: "Low",       lastScan: "2026-04-14 12:00", findings: 5  },
  { name: "Notification Service", type: "api",    stack: ["Python", "Redis"],  risk: "Low",       lastScan: "2026-04-13 08:00", findings: 3  },
  { name: "Reporting Engine",     type: "web",    stack: ["React", "D3.js"],   risk: "Medium",    lastScan: "2026-04-12 16:00", findings: 24 },
];

const OWASP_TOP10 = [
  { id: "A01", name: "Broken Access Control",          count: 68, max: 80 },
  { id: "A02", name: "Cryptographic Failures",          count: 34, max: 80 },
  { id: "A03", name: "Injection",                       count: 52, max: 80 },
  { id: "A04", name: "Insecure Design",                 count: 29, max: 80 },
  { id: "A05", name: "Security Misconfiguration",       count: 47, max: 80 },
  { id: "A06", name: "Vulnerable/Outdated Components",  count: 38, max: 80 },
  { id: "A07", name: "Identification/Auth Failures",    count: 25, max: 80 },
  { id: "A08", name: "Software/Data Integrity Failures",count: 12, max: 80 },
  { id: "A09", name: "Security Logging Failures",       count: 19, max: 80 },
  { id: "A10", name: "SSRF",                            count: 8,  max: 80 },
];

const SCANS = [
  { app: "Auth Service",         tool: "Semgrep",  type: "SAST",  status: "Complete", findings: 31, time: "2026-04-16 00:00" },
  { app: "ALDECI Core API",      tool: "ZAP",      type: "DAST",  status: "Complete", findings: 22, time: "2026-04-16 06:00" },
  { app: "ALDECI Core API",      tool: "Bandit",   type: "SAST",  status: "Complete", findings: 25, time: "2026-04-16 05:30" },
  { app: "Portal Web App",       tool: "ZAP",      type: "DAST",  status: "Complete", findings: 18, time: "2026-04-15 22:00" },
  { app: "Portal Web App",       tool: "Semgrep",  type: "SAST",  status: "Complete", findings: 13, time: "2026-04-15 21:45" },
  { app: "Auth Service",         tool: "Semgrep",  type: "SAST",  status: "Complete", findings: 31, time: "2026-04-15 12:00" },
  { app: "Admin Dashboard",      tool: "Semgrep",  type: "SAST",  status: "Complete", findings: 11, time: "2026-04-14 20:00" },
  { app: "Mobile SDK (iOS)",     tool: "Bandit",   type: "SAST",  status: "Complete", findings: 8,  time: "2026-04-14 18:00" },
  { app: "Reporting Engine",     tool: "ZAP",      type: "DAST",  status: "Complete", findings: 14, time: "2026-04-12 16:00" },
  { app: "Notification Service", tool: "Semgrep",  type: "SAST",  status: "Complete", findings: 3,  time: "2026-04-13 08:00" },
];

const CRITICAL_FINDINGS = [
  { id: "CWE-89",  app: "Auth Service",    vuln: "SQL Injection",             severity: "Critical", file: "src/auth/db_query.py:L142",   status: "Open" },
  { id: "CWE-22",  app: "ALDECI Core API", vuln: "Path Traversal",            severity: "Critical", file: "core/file_upload.py:L89",     status: "Open" },
  { id: "CWE-918", app: "ALDECI Core API", vuln: "SSRF in Webhook Handler",   severity: "Critical", file: "core/webhook.py:L201",        status: "Open" },
  { id: "CWE-502", app: "Reporting Engine",vuln: "Insecure Deserialization",  severity: "Critical", file: "src/report/loader.py:L55",    status: "Open" },
  { id: "CWE-287", app: "Auth Service",    vuln: "Auth Bypass via JWT alg:none", severity: "Critical", file: "src/auth/tokens.py:L38", status: "Investigating" },
  { id: "CWE-79",  app: "Portal Web App",  vuln: "Stored XSS in Comments",   severity: "Critical", file: "src/components/Comment.jsx:L77", status: "Open" },
  { id: "CWE-611", app: "ALDECI Core API", vuln: "XML External Entity (XXE)", severity: "Critical", file: "core/xml_parser.py:L34",     status: "Open" },
  { id: "CWE-434", app: "Admin Dashboard", vuln: "Unrestricted File Upload",  severity: "Critical", file: "src/pages/Upload.tsx:L112",  status: "Investigating" },
];

// ── Helpers ────────────────────────────────────────────────────

function RiskBadge({ risk }: { risk: string }) {
  const cls =
    risk === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    risk === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    risk === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                          "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{risk}</Badge>;
}

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "web"    ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "api"    ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
                        "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{type}</Badge>;
}

function ToolBadge({ tool }: { tool: string }) {
  const cls =
    tool === "Semgrep" ? "border-indigo-500/30 text-indigo-400 bg-indigo-500/10" :
    tool === "ZAP"     ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                         "border-slate-500/30 text-slate-400 bg-slate-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{tool}</Badge>;
}

function ScanTypeBadge({ type }: { type: string }) {
  const cls = type === "SAST"
    ? "border-blue-500/30 text-blue-400 bg-blue-500/10"
    : "border-orange-500/30 text-orange-400 bg-orange-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function AppSecurity() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/appsec/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/appsec/apps?org_id=${ORG_ID}`),
    ]).then(([statsResult, appsResult]) => {
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      const apps  = appsResult.status  === "fulfilled" ? appsResult.value  : null;
      if (stats || apps) setLiveData({ stats, apps });
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/appsec/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/appsec/apps?org_id=${ORG_ID}`),
    ]).then(([statsResult, appsResult]) => {
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      const apps  = appsResult.status  === "fulfilled" ? appsResult.value  : null;
      if (stats || apps) setLiveData({ stats, apps });
    }).finally(() => { setDataLoading(false); setRefreshing(false); });
  };

  const owaspMax = Math.max(...OWASP_TOP10.map(o => o.count));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Application Security (AppSec)"
        description="SAST/DAST scan results and finding management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Applications"   value={liveData?.stats?.total_apps      ?? 24}  icon={Code2}         trend="up" />
        <KpiCard title="Total Scans"    value={liveData?.stats?.total_scans     ?? 187} icon={Search}        trend="up"   className="border-blue-500/20" />
        <KpiCard title="Open Findings"  value={liveData?.stats?.open_findings   ?? 312} icon={Bug}           trend="down" className="border-amber-500/20" />
        <KpiCard title="Critical"       value={liveData?.stats?.critical_count  ?? 18}  icon={AlertTriangle} trend="down" className="border-red-500/20" />
      </div>

      {/* Application table + OWASP breakdown */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Application table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Code2 className="h-4 w-4 text-indigo-400" />
              Applications
            </CardTitle>
            <CardDescription className="text-xs">All tracked applications with risk ratings and scan coverage</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Application</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Stack</TableHead>
                    <TableHead className="text-[11px] h-8">Risk</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.apps?.items ?? liveData?.apps ?? APPLICATIONS).map((app: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2.5 max-w-[130px] truncate">{app.name}</TableCell>
                      <TableCell className="py-2.5"><TypeBadge type={app.type ?? app.app_type ?? "web"} /></TableCell>
                      <TableCell className="py-2.5">
                        <div className="flex gap-1 flex-wrap">
                          {(app.stack ?? [app.language ?? "other"]).map((t: string) => (
                            <Badge key={t} className="text-[9px] border border-border bg-muted/20 text-muted-foreground">{t}</Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="py-2.5"><RiskBadge risk={app.risk ?? app.criticality ?? "Medium"} /></TableCell>
                      <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">
                        <span className={app.findings > 40 ? "text-red-400" : app.findings > 20 ? "text-amber-400" : "text-muted-foreground"}>
                          {app.findings ?? 0}
                        </span>
                      </TableCell>
                      <TableCell className="py-2.5 text-right">
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Scan</Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* OWASP Top 10 */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-400" />
              OWASP Top 10 Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Findings mapped to OWASP Top 10 categories</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {OWASP_TOP10.map((o) => (
              <div key={o.id} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="font-mono text-[10px] text-muted-foreground shrink-0">{o.id}</span>
                    <span className="truncate text-[11px]">{o.name}</span>
                  </div>
                  <span className={cn("tabular-nums font-bold ml-2 shrink-0",
                    o.count > 50 ? "text-red-400" : o.count > 30 ? "text-amber-400" : "text-muted-foreground"
                  )}>{o.count}</span>
                </div>
                <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(o.count / owaspMax) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full",
                      o.count > 50 ? "bg-red-500" : o.count > 30 ? "bg-amber-500" : "bg-blue-500"
                    )}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Recent scan results */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Zap className="h-4 w-4 text-yellow-400" />
              Recent Scan Results
            </CardTitle>
            <Badge className="text-[10px] border border-border bg-muted/20">{SCANS.length} scans</Badge>
          </div>
          <CardDescription className="text-xs">Latest SAST and DAST scan runs across all applications</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Application</TableHead>
                  <TableHead className="text-[11px] h-8">Tool</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                  <TableHead className="text-[11px] h-8">Timestamp</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SCANS.map((s, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[150px] truncate">{s.app}</TableCell>
                    <TableCell className="py-2.5"><ToolBadge tool={s.tool} /></TableCell>
                    <TableCell className="py-2.5"><ScanTypeBadge type={s.type} /></TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">{s.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">
                      <span className={s.findings > 25 ? "text-red-400" : s.findings > 15 ? "text-amber-400" : "text-muted-foreground"}>
                        {s.findings}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{s.time}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Critical findings table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Critical Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {CRITICAL_FINDINGS.length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">Findings requiring immediate remediation — P0 priority</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CWE/CVE</TableHead>
                  <TableHead className="text-[11px] h-8">Application</TableHead>
                  <TableHead className="text-[11px] h-8">Vulnerability</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">File Location</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CRITICAL_FINDINGS.map((f, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{f.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[120px] truncate">{f.app}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[160px] truncate">{f.vuln}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{f.severity}</Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground max-w-[160px] truncate">{f.file}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border",
                        f.status === "Open"
                          ? "border-red-500/30 text-red-400 bg-red-500/10"
                          : "border-amber-500/30 text-amber-400 bg-amber-500/10"
                      )}>{f.status}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-red-500/30 text-red-400 hover:bg-red-500/10">
                        Fix
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
