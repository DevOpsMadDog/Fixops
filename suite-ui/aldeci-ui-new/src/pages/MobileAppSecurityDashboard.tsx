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
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

async function apiFetch<T = any>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

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
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [apps, setApps] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({ total_apps: 0, active_apps: 0, total_findings: 0, critical_findings: 0 });

  const load = async () => {
    setRefreshing(true);
    setError(null);
    try {
      const [appsRes, findingsRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/mobile-app-security/apps"),
        apiFetch<any>("/api/v1/mobile-app-security/findings"),
      ]);
      let appsArr: any[] = [];
      if (appsRes.status === "fulfilled") {
        const v = appsRes.value;
        appsArr = Array.isArray(v) ? v : (v?.apps ?? v?.items ?? []);
        setApps(appsArr);
      } else {
        setError((appsRes.reason as Error).message);
      }
      let findArr: any[] = [];
      if (findingsRes.status === "fulfilled") {
        const v = findingsRes.value;
        findArr = Array.isArray(v) ? v : (v?.findings ?? v?.items ?? []);
        setFindings(findArr);
      }
      setStats({
        total_apps: appsArr.length,
        active_apps: appsArr.filter((a: any) => a.status !== "inactive" && a.status !== "archived").length,
        total_findings: findArr.length,
        critical_findings: findArr.filter((f: any) => f.severity === "critical").length,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { load(); };

  if (loading) return <PageSkeleton />;

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
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {error && <ErrorState message={error} onRetry={load} />}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Apps"       value={stats.total_apps}       icon={Smartphone}   trend="flat" />
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
          {apps.length === 0 && !error ? <EmptyState icon={Smartphone} title="No mobile apps" description="Register a mobile app to start scanning." /> : (
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
                {apps.map((a: any, i: number) => (
                  <TableRow key={a.app_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{a.app_name}</TableCell>
                    <TableCell className="py-2"><PlatformBadge platform={a.platform ?? "iOS"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.category}</TableCell>
                    <TableCell className="py-2"><RiskBadge level={a.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{a.last_scanned}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          )}
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
          {findings.length === 0 && !error ? <EmptyState icon={ShieldAlert} title="No findings" description="No security findings reported for registered apps." /> : (
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
                {findings.map((f: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{f.title}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{f.finding_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={f.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{f.owasp_category}</TableCell>
                    <TableCell className="py-2"><FindingStatusBadge status={f.status ?? "open"} /></TableCell>
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
