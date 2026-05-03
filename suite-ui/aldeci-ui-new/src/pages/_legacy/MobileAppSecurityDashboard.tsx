// FOLDED into AppLayerSecurityHub at /discover/app-security?tab=mobile (Phase 3, 2026-05-02)
/**
 * Mobile App Security Dashboard
 *
 * Mobile application security scanning and findings management.
 *   1. KPI cards: Total Apps, Active Apps, Total Findings, Critical Findings
 *   2. Apps table
 *   3. Findings table
 *
 * API: GET /api/v1/mobile-app-security/{stats,apps,findings}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Smartphone, RefreshCw, AlertTriangle, ShieldAlert, CheckCircle } from "lucide-react";
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
  total_apps: 38,
  active_apps: 31,
  total_findings: 156,
  critical_findings: 12,
};

const MOCK_APPS = [
  { app_name: "ALDECI Mobile",      platform: "iOS",     category: "Security",    risk_level: "low",      last_scanned: "2026-04-16" },
  { app_name: "FieldOps Tracker",   platform: "Android", category: "Operations",  risk_level: "medium",   last_scanned: "2026-04-15" },
  { app_name: "SecureVault",        platform: "iOS",     category: "Finance",     risk_level: "high",     last_scanned: "2026-04-14" },
  { app_name: "HR Connect",         platform: "Android", category: "HR",          risk_level: "medium",   last_scanned: "2026-04-13" },
  { app_name: "Supply Tracker Pro", platform: "iOS",     category: "Logistics",   risk_level: "critical", last_scanned: "2026-04-12" },
  { app_name: "DevPortal",          platform: "Android", category: "Development", risk_level: "low",      last_scanned: "2026-04-16" },
];

const MOCK_FINDINGS = [
  { title: "Hardcoded API key",          finding_type: "SAST",    severity: "critical", owasp_category: "M1: Improper Platform Usage",    status: "open"    },
  { title: "Insecure data storage",      finding_type: "SAST",    severity: "high",     owasp_category: "M2: Insecure Data Storage",       status: "open"    },
  { title: "Weak certificate pinning",   finding_type: "DAST",    severity: "high",     owasp_category: "M3: Insecure Communication",      status: "open"    },
  { title: "Exported activity exposed",  finding_type: "SAST",    severity: "medium",   owasp_category: "M1: Improper Platform Usage",     status: "fixed"   },
  { title: "Broken authentication flow", finding_type: "DAST",    severity: "critical", owasp_category: "M4: Insecure Authentication",     status: "open"    },
  { title: "Unencrypted local DB",       finding_type: "Manual",  severity: "high",     owasp_category: "M2: Insecure Data Storage",       status: "in_review"},
];

// ── Badge helpers ──────────────────────────────────────────────

function PlatformBadge({ platform }: { platform: string }) {
  const map: Record<string, string> = {
    iOS:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    Android: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[platform] ?? "border-border text-muted-foreground")}>
      {platform}
    </Badge>
  );
}

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function FindingStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:      "border-red-500/30 text-red-400 bg-red-500/10",
    in_review: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    fixed:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function MobileAppSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    apps: any[] | null;
    findings: any[] | null;
  }>({ stats: null, apps: null, findings: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/mobile-app-security/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/mobile-app-security/apps?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/mobile-app-security/findings?org_id=${ORG_ID}`),
    ]).then(([statsRes, appsRes, findingsRes]) => {
      setLiveData({
        stats:    statsRes.status    === "fulfilled" ? statsRes.value    : null,
        apps:     appsRes.status     === "fulfilled" ? appsRes.value     : null,
        findings: findingsRes.status === "fulfilled" ? findingsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats    = liveData.stats    ?? MOCK_STATS;
  const apps     = liveData.apps     ?? MOCK_APPS;
  const findings = liveData.findings ?? MOCK_FINDINGS;

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
        title="Mobile App Security"
        description="Mobile application SAST/DAST scanning and OWASP Mobile Top 10 findings"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Apps"       value={stats.total_apps}         icon={Smartphone}   trend="flat" />
        <KpiCard title="Active Apps"      value={stats.active_apps}      icon={CheckCircle}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Total Findings"   value={stats.total_findings}   icon={AlertTriangle} trend="down" className="border-amber-500/20" />
        <KpiCard title="Critical Findings" value={stats.critical_findings} icon={ShieldAlert} trend="down" className="border-red-500/20" />
      </div>

      {/* Apps Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Smartphone className="h-4 w-4 text-blue-400" />
              Mobile Applications
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {apps.length} apps
            </Badge>
          </div>
          <CardDescription className="text-xs">Registered mobile apps with risk posture and scan dates</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">App Name</TableHead>
                  <TableHead className="text-[11px] h-8">Platform</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scanned</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  apps.map((a: any, i: number) => (
                  <TableRow key={a.app_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{a.app_name}</TableCell>
                    <TableCell className="py-2"><PlatformBadge platform={a.platform ?? "iOS"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.category}</TableCell>
                    <TableCell className="py-2"><RiskBadge level={a.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.last_scanned}</TableCell>
                  </TableRow>
                ))
                )}
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
              <ShieldAlert className="h-4 w-4" />
              Security Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {findings.filter((f: any) => f.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">OWASP Mobile Top 10 findings across all scanned apps</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">OWASP Category</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  findings.map((f: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{f.title}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{f.finding_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={f.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{f.owasp_category}</TableCell>
                    <TableCell className="py-2"><FindingStatusBadge status={f.status ?? "open"} /></TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
