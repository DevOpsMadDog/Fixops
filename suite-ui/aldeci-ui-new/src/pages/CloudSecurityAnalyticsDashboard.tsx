/**
 * Cloud Security Analytics Dashboard
 *
 * Cloud resource events, anomaly detection rules, and misconfiguration findings.
 *   1. KPIs: Cloud Resources, Misconfigs Found, Risk Score, Events/hr
 *   2. Cloud findings table (resource, provider, severity, finding, status)
 *
 * Route: /cloud-security-analytics
 * API: GET /api/v1/cloud-analytics/events
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, AlertTriangle, TrendingUp, Activity } from "lucide-react";

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

// == Mock data ==================================================

const MOCK_FINDINGS = [
  { id: "CLD-001", resource: "s3://prod-backups",           provider: "aws",   severity: "critical", finding: "Public read ACL enabled on production bucket",     status: "open" },
  { id: "CLD-002", resource: "iam::role/lambda-exec",       provider: "aws",   severity: "high",     finding: "Overprivileged Lambda role = AdministratorAccess", status: "open" },
  { id: "CLD-003", resource: "storage/customer-data",       provider: "gcp",   severity: "critical", finding: "Bucket publicly accessible without auth",          status: "investigating" },
  { id: "CLD-004", resource: "vm/prod-web-01",              provider: "azure", severity: "medium",   finding: "SSH port 22 open to 0.0.0.0/0",                   status: "open" },
  { id: "CLD-005", resource: "rds/prod-mysql-primary",      provider: "aws",   severity: "high",     finding: "Database instance publicly accessible",            status: "open" },
  { id: "CLD-006", resource: "cloudtrail/us-east-1",        provider: "aws",   severity: "medium",   finding: "CloudTrail log file validation disabled",          status: "remediated" },
  { id: "CLD-007", resource: "k8s/kube-system/secrets",     provider: "gcp",   severity: "high",     finding: "Kubernetes secrets stored unencrypted",            status: "open" },
  { id: "CLD-008", resource: "nsg/frontend-dmz",            provider: "azure", severity: "low",      finding: "Overly permissive inbound NSG rule",               status: "open" },
];

const MOCK_STATS = { cloud_resources: 3842, misconfigs_found: 47, risk_score: 68, events_hr: 12400 };

// == Badge helpers ==============================================

function ProviderBadge({ provider }: { provider: string }) {
  const map: Record<string, string> = {
    aws:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    gcp:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    azure: "border-sky-500/30 text-sky-400 bg-sky-500/10",
  };
  return <Badge className={cn("text-[10px] border uppercase font-mono", map[provider] ?? "border-border")}>{provider}</Badge>;
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>{severity}</Badge>;
}

function FindingStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:          "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    remediated:    "border-green-500/30 text-green-400 bg-green-500/10",
    suppressed:    "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

// == Component ==================================================

export default function CloudSecurityAnalyticsDashboard() {
  const [refreshing, setRefreshing]   = useState(false);
  const [liveFindings, setLiveFindings] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [liveStats, setLiveStats]       = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/cloud-analytics/events?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-analytics/anomalies?org_id=${ORG_ID}`),
    ]).then(([eventsRes, anomaliesRes]) => {
      if (eventsRes.status === "fulfilled") setLiveFindings(eventsRes.value?.events ?? eventsRes.value ?? null);
      if (anomaliesRes.status === "fulfilled") setLiveStats(anomaliesRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const findings = liveFindings ?? MOCK_FINDINGS;
  const stats    = liveStats    ?? MOCK_STATS;

  const openCount = findings.filter((f: any) => (f.status ?? "open") === "open").length;

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
        title="Cloud Security Analytics"
        description="Multi-cloud resource monitoring, misconfiguration detection, and event analytics"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Cloud Resources"   value={stats.cloud_resources.toLocaleString()}  icon={Cloud}          trend="up" />
        <KpiCard title="Misconfigs Found"  value={stats.misconfigs_found}                  icon={AlertTriangle}  trend="up"     className="border-sky-500/20" />
        <KpiCard title="Risk Score"        value={`${stats.risk_score}/100`}               icon={TrendingUp}     trend="flat" className="border-blue-500/20" />
        <KpiCard title="Events / hr"       value={stats.events_hr.toLocaleString()}        icon={Activity}       trend="up" />
      </div>

      {/* Findings Table */}
      <Card className="border-sky-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-sky-400">
              <Cloud className="h-4 w-4" />
              Cloud Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{openCount} open</Badge>
          </div>
          <CardDescription className="text-xs">
            Misconfigurations and security findings across AWS, GCP, and Azure
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Resource</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[240px]">Finding</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
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
                  <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{f.id}</TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[180px] truncate">
                      {f.resource ?? f.resource_id ?? "="}
                    </TableCell>
                    <TableCell className="py-2">
                      <ProviderBadge provider={f.provider ?? f.cloud_provider ?? "aws"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={f.severity ?? "medium"} />
                    </TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground max-w-[240px] truncate">
                      {f.finding ?? f.description ?? f.title ?? "="}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <FindingStatusBadge status={f.status ?? "open"} />
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
