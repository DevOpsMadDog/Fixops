/**
 * Application Risk Dashboard
 *
 * Application risk scoring, findings tracking, and environment-based risk posture.
 *   1. KPIs: Total Apps, Critical Risk Apps, Total Findings, Open Findings
 *   2. Applications table (name, app_type, environment, risk_score, risk_level, owner_team)
 *
 * Route: /application-risk
 * API: GET /api/v1/app-risk/applications
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AppWindow, RefreshCw, AlertTriangle, Shield, BarChart3 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "juice-shop-corp";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_APPS = [
  { name: "payments-api",        app_type: "REST API",      environment: "production",  risk_score: 94, risk_level: "critical", owner_team: "Payments" },
  { name: "auth-service",        app_type: "Microservice",  environment: "production",  risk_score: 81, risk_level: "high",     owner_team: "Identity" },
  { name: "admin-portal",        app_type: "Web App",       environment: "production",  risk_score: 76, risk_level: "high",     owner_team: "Platform" },
  { name: "data-pipeline",       app_type: "ETL",           environment: "production",  risk_score: 62, risk_level: "medium",   owner_team: "Data Eng" },
  { name: "reporting-service",   app_type: "REST API",      environment: "staging",     risk_score: 45, risk_level: "medium",   owner_team: "Analytics" },
  { name: "notification-svc",    app_type: "Microservice",  environment: "production",  risk_score: 38, risk_level: "low",      owner_team: "Comms" },
  { name: "inventory-mgmt",      app_type: "Web App",       environment: "staging",     risk_score: 97, risk_level: "critical", owner_team: "Ops" },
  { name: "customer-portal",     app_type: "Web App",       environment: "production",  risk_score: 55, risk_level: "medium",   owner_team: "CX" },
];

const MOCK_STATS = { total_apps: 138, critical_risk_apps: 12, total_findings: 847, open_findings: 293 };

// ── Badge helpers ──────────────────────────────────────────────

function RiskLevelBadge({ level }: { level: string }) {
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

function EnvBadge({ env }: { env: string }) {
  const map: Record<string, string> = {
    production: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    staging:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    development:"border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[env] ?? "border-border")}>
      {env}
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono font-bold text-[12px]", color)}>{score}</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function ApplicationRiskDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveApps, setLiveApps]   = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/app-risk/applications?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/app-risk/stats?org_id=${ORG_ID}`),
    ]).then(([appsRes, statsRes]) => {
      if (appsRes.status === "fulfilled") setLiveApps(appsRes.value?.applications ?? appsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
    setLoading(false);
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const apps  = liveApps  ?? ([] as any);
  const stats = liveStats ?? ({} as any);


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Application Risk"
        description="Application security posture, risk scoring, and findings prioritization across all environments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Apps"        value={stats.total_apps}        icon={AppWindow}     trend="flat" />
        <KpiCard title="Critical Risk Apps" value={stats.critical_risk_apps} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Total Findings"    value={stats.total_findings}    icon={BarChart3}     trend="flat" className="border-orange-500/20" />
        <KpiCard title="Open Findings"     value={stats.open_findings}     icon={Shield}        trend="up"   className="border-amber-500/20" />
      </div>

      {/* Applications Table */}
      <Card className="border-orange-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <AppWindow className="h-4 w-4" />
              Application Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {apps.filter((a: any) => a.risk_level === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Risk-scored application inventory — SAST/DAST findings, environment exposure, and owner mapping
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Application</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Environment</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Owner Team</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.map((app: any, i: number) => (
                  <TableRow key={app.name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] font-semibold">
                      {app.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {app.app_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <EnvBadge env={app.environment ?? "production"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskScore score={app.risk_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskLevelBadge level={app.risk_level ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {app.owner_team ?? "—"}
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
