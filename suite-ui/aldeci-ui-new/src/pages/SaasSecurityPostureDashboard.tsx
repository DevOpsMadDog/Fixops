/**
 * SaaS Security Posture Dashboard (SSPM)
 *
 * SaaS application risk and compliance monitoring.
 *   1. KPIs: Total Apps, High-Risk Apps, Open Findings, Compliance Rate %
 *   2. Apps table (app_name, app_category, vendor, risk_level, compliance_status, user_count)
 *
 * Route: /sspm
 * API: GET /api/v1/sspm
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, AlertTriangle, Users, CheckCircle2, LayoutGrid } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_APPS = [
  { id: "app-001", app_name: "Salesforce CRM",       app_category: "CRM",           vendor: "Salesforce",  risk_level: "low",      compliance_status: "compliant",     user_count: 842 },
  { id: "app-002", app_name: "Slack",                 app_category: "Collaboration", vendor: "Slack",       risk_level: "medium",   compliance_status: "partial",       user_count: 1240 },
  { id: "app-003", app_name: "GitHub Enterprise",     app_category: "DevOps",        vendor: "GitHub",      risk_level: "high",     compliance_status: "non_compliant", user_count: 380 },
  { id: "app-004", app_name: "Zoom",                  app_category: "Meetings",      vendor: "Zoom",        risk_level: "medium",   compliance_status: "partial",       user_count: 1580 },
  { id: "app-005", app_name: "Workday",               app_category: "HR",            vendor: "Workday",     risk_level: "low",      compliance_status: "compliant",     user_count: 620 },
  { id: "app-006", app_name: "ServiceNow",            app_category: "ITSM",          vendor: "ServiceNow",  risk_level: "medium",   compliance_status: "compliant",     user_count: 290 },
  { id: "app-007", app_name: "Dropbox Business",      app_category: "Storage",       vendor: "Dropbox",     risk_level: "critical", compliance_status: "non_compliant", user_count: 730 },
  { id: "app-008", app_name: "Okta",                  app_category: "IAM",           vendor: "Okta",        risk_level: "low",      compliance_status: "compliant",     user_count: 2100 },
  { id: "app-009", app_name: "Jira Cloud",            app_category: "Project Mgmt",  vendor: "Atlassian",   risk_level: "medium",   compliance_status: "partial",       user_count: 510 },
  { id: "app-010", app_name: "DocuSign",              app_category: "Signatures",    vendor: "DocuSign",    risk_level: "high",     compliance_status: "non_compliant", user_count: 185 },
];

const MOCK_STATS = { total_apps: 94, high_risk_apps: 18, open_findings: 237, compliance_rate: 71.3 };

// ── Badge helpers ──────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function ComplianceBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    compliant:     "border-green-500/30 text-green-400 bg-green-500/10",
    partial:       "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    non_compliant: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  const label: Record<string, string> = {
    compliant: "Compliant", partial: "Partial", non_compliant: "Non-Compliant",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

function exportCsv(apps: any[]) {
  const headers = ["app_name", "app_category", "vendor", "risk_level", "compliance_status", "user_count"];
  const rows = apps.map((a) => headers.map((h) => a[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "sspm_apps.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function SaasSecurityPostureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveApps, setLiveApps] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/sspm/apps?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/sspm/stats?org_id=${ORG_ID}`),
    ]).then(([appsRes, statsRes]) => {
      if (appsRes.status === "fulfilled") setLiveApps(appsRes.value?.apps ?? appsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const apps  = liveApps  ?? MOCK_APPS;
  const stats = liveStats ?? MOCK_STATS;

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
      <PageHeader
        title="SaaS Security Posture"
        description="Monitor SaaS application risk exposure, compliance status, and user access across your cloud application portfolio"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Apps"       value={stats.total_apps}                        icon={LayoutGrid}    trend="flat" className="border-violet-500/20" />
        <KpiCard title="High-Risk Apps"   value={stats.high_risk_apps}                    icon={AlertTriangle} trend="down" className="border-purple-500/20" />
        <KpiCard title="Open Findings"    value={stats.open_findings}                     icon={ShieldCheck}   trend="down" className="border-violet-500/20" />
        <KpiCard title="Compliance Rate"  value={`${stats.compliance_rate}%`}             icon={CheckCircle2}  trend="up"   className="border-purple-500/20" />
      </div>

      {/* Apps Table */}
      <Card className="border-violet-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-violet-400">
              <LayoutGrid className="h-4 w-4" />
              SaaS Application Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {apps.filter((a: any) => a.risk_level === "critical").length} critical
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(apps)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            SaaS apps with risk classification, vendor, compliance posture, and active user count
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">App Name</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Compliance</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Users</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  apps.map((app: any, i: number) => (
                  <TableRow key={app.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-violet-300 max-w-[180px] truncate">
                      {app.app_name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {app.app_category ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {app.vendor ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskBadge level={app.risk_level ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <ComplianceBadge status={app.compliance_status ?? "partial"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-purple-300 text-right">
                      {(app.user_count ?? 0).toLocaleString()}
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
