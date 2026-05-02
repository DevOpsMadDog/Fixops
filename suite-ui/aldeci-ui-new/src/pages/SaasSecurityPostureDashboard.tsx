/**
 * SaaS Security Posture Dashboard (SSPM)
 *
 * SaaS application risk and compliance monitoring.
 *   1. KPIs: Total Apps, High-Risk Apps, Open Findings, Compliance Rate %
 *   2. Apps table (app_name, app_category, vendor, risk_level, compliance_status, user_count)
 *
 * Route: /sspm
 * API: GET /api/v1/sspm/apps  GET /api/v1/sspm/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, AlertTriangle, CheckCircle2, LayoutGrid } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

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

function exportCsv(apps: Array<Record<string, unknown>>) {
  const headers = ["app_name", "app_category", "vendor", "risk_level", "compliance_status", "user_count"];
  const rows = apps.map((a) => headers.map((h) => a[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "sspm_apps.csv"; a.click();
  URL.revokeObjectURL(url);
}

interface SspmApp {
  id?: string;
  app_name?: string;
  app_category?: string;
  vendor?: string;
  risk_level?: string;
  compliance_status?: string;
  user_count?: number;
}

interface SspmStats {
  total_apps?: number;
  high_risk_apps?: number;
  open_findings?: number;
  compliance_rate?: number;
}

export default function SaasSecurityPostureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [apps, setApps] = useState<SspmApp[]>([]);
  const [stats, setStats] = useState<SspmStats>({});
  const [error, setError] = useState<string | null>(null);

  const fetchData = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/sspm/apps?org_id=default"),
      apiFetch("/api/v1/sspm/stats?org_id=default"),
    ]).then(([appsRes, statsRes]) => {
      if (appsRes.status === "fulfilled") {
        const v = appsRes.value;
        setApps(Array.isArray(v) ? v : (v?.apps ?? v?.items ?? []));
      } else {
        setError("Failed to load apps");
      }
      if (statsRes.status === "fulfilled") {
        setStats(statsRes.value ?? {});
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-6">
        <div className="h-10 w-64 rounded bg-muted animate-pulse" />
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded bg-muted animate-pulse" />)}
        </div>
        <div className="h-64 rounded bg-muted animate-pulse" />
      </div>
    );
  }

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

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Apps"      value={stats.total_apps ?? 0}            icon={LayoutGrid}    trend="flat" className="border-violet-500/20" />
        <KpiCard title="High-Risk Apps"  value={stats.high_risk_apps ?? 0}        icon={AlertTriangle} trend="down" className="border-purple-500/20" />
        <KpiCard title="Open Findings"   value={stats.open_findings ?? 0}         icon={ShieldCheck}   trend="down" className="border-violet-500/20" />
        <KpiCard title="Compliance Rate" value={`${stats.compliance_rate ?? 0}%`} icon={CheckCircle2}  trend="up"   className="border-purple-500/20" />
      </div>

      <Card className="border-violet-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-violet-400">
              <LayoutGrid className="h-4 w-4" />
              SaaS Application Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
                {apps.filter((a) => a.risk_level === "critical").length} critical
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7"
                onClick={() => exportCsv(apps as Array<Record<string, unknown>>)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            SaaS apps with risk classification, vendor, compliance posture, and active user count
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error ? (
            <div className="p-6">
              <EmptyState
                title="Failed to load SaaS apps"
                description={error}
                icon={AlertTriangle}
              />
            </div>
          ) : apps.length === 0 ? (
            <div className="p-6">
              <EmptyState
                title="No SaaS apps found"
                description="Connect your SaaS integrations to start monitoring application risk posture."
                icon={LayoutGrid}
              />
            </div>
          ) : (
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
                  {apps.map((app, i) => (
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
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
