/**
 * Cloud Posture Dashboard
 *
 * Cloud security posture management with findings tracking across providers.
 *   1. KPIs: Cloud Accounts, Avg Posture Score, Open Findings, Critical Findings
 *   2. Findings table (resource_id, provider, resource_type, severity, title, status)
 *
 * Route: /cloud-posture
 * API: GET /api/v1/cloud-posture
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, AlertTriangle, Server, ShieldAlert } from "lucide-react";

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

const MOCK_FINDINGS = [
  { id: "find-001", resource_id: "s3-prod-data",        provider: "AWS",   resource_type: "S3 Bucket",        severity: "critical", title: "Public read access enabled",     status: "open"     },
  { id: "find-002", resource_id: "vm-web-01",           provider: "Azure", resource_type: "Virtual Machine",  severity: "high",     title: "RDP exposed to internet",        status: "open"     },
  { id: "find-003", resource_id: "gke-cluster-prod",    provider: "GCP",   resource_type: "GKE Cluster",      severity: "high",     title: "Legacy ABAC authorization",      status: "open"     },
  { id: "find-004", resource_id: "rds-customers",       provider: "AWS",   resource_type: "RDS Instance",     severity: "medium",   title: "Encryption at rest disabled",    status: "resolved" },
  { id: "find-005", resource_id: "nsg-dev-01",          provider: "Azure", resource_type: "Network Sec Grp",  severity: "medium",   title: "SSH open to all IPs",            status: "open"     },
  { id: "find-006", resource_id: "lambda-data-process", provider: "AWS",   resource_type: "Lambda Function",  severity: "low",      title: "Excessive IAM permissions",      status: "open"     },
  { id: "find-007", resource_id: "bigquery-analytics",  provider: "GCP",   resource_type: "BigQuery Dataset", severity: "critical", title: "Dataset publicly accessible",    status: "open"     },
  { id: "find-008", resource_id: "storage-backups",     provider: "Azure", resource_type: "Storage Account",  severity: "low",      title: "Soft delete not enabled",        status: "resolved" },
];

const MOCK_STATS = { cloud_accounts: 12, avg_posture_score: 68, open_findings: 47, critical_findings: 6 };

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:     "border-red-500/30 text-red-400 bg-red-500/10",
    resolved: "border-green-500/30 text-green-400 bg-green-500/10",
    ignored:  "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function ProviderBadge({ provider }: { provider: string }) {
  const map: Record<string, string> = {
    AWS:   "border-sky-500/30 text-sky-400 bg-sky-500/10",
    Azure: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    GCP:   "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[provider] ?? "border-border")}>
      {provider}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CloudPostureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveFindings, setLiveFindings] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/cloud-posture/findings?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-posture/stats?org_id=${ORG_ID}`),
    ]).then(([findingsRes, statsRes]) => {
      if (findingsRes.status === "fulfilled") setLiveFindings(findingsRes.value?.findings ?? findingsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const findings = liveFindings ?? MOCK_FINDINGS;
  const stats    = liveStats    ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Cloud Posture"
        description="Multi-cloud security posture management with misconfiguration detection across AWS, Azure, and GCP"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Cloud Accounts"    value={stats.cloud_accounts}    icon={Cloud}       trend="flat" className="border-sky-500/20" />
        <KpiCard title="Avg Posture Score" value={`${stats.avg_posture_score}%`} icon={ShieldAlert} trend="up"   className="border-blue-500/20" />
        <KpiCard title="Open Findings"     value={stats.open_findings}     icon={AlertTriangle} trend="down" className="border-orange-500/20" />
        <KpiCard title="Critical Findings" value={stats.critical_findings} icon={Server}      trend="down" className="border-red-500/20" />
      </div>

      {/* Findings Table */}
      <Card className="border-sky-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-sky-400">
              <Cloud className="h-4 w-4" />
              Cloud Security Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {findings.filter((f: any) => f.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Misconfigurations and policy violations detected across cloud accounts and resource types
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Resource ID</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Resource Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.map((f: any, i: number) => (
                  <TableRow key={f.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-sky-300">
                      {f.resource_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ProviderBadge provider={f.provider ?? "Unknown"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {f.resource_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={f.severity ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[200px] truncate">
                      {f.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={f.status ?? "open"} />
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
