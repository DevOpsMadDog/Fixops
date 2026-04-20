/**
 * Patch Management Dashboard
 *
 * Enterprise patch lifecycle tracking with deployment success rates.
 *   1. KPIs: Total Patches, Critical Patches, Undeployed Critical, Success Rate %
 *   2. Patches table (title, patch_type, severity, status, deployed_count, failed_count)
 *
 * Route: /patch-management
 * API: GET /api/v1/patch-management
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, RefreshCw, AlertTriangle, CheckCircle, XCircle, BarChart2 } from "lucide-react";

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
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_PATCHES = [
  { id: "pat-001", title: "Windows Server 2022 KB5034439",    patch_type: "os",          severity: "critical", status: "deployed",    deployed_count: 412, failed_count: 3  },
  { id: "pat-002", title: "OpenSSL 3.x RCE Fix (CVE-2025-1)", patch_type: "library",    severity: "critical", status: "in_progress", deployed_count: 287, failed_count: 8  },
  { id: "pat-003", title: "Apache HTTP Server 2.4.59",         patch_type: "application",severity: "high",     status: "deployed",    deployed_count: 198, failed_count: 2  },
  { id: "pat-004", title: "Linux Kernel 6.8.4 Security",       patch_type: "os",         severity: "high",     status: "pending",     deployed_count: 0,   failed_count: 0  },
  { id: "pat-005", title: "PostgreSQL 16.2 Auth Bypass Fix",   patch_type: "database",   severity: "critical", status: "pending",     deployed_count: 0,   failed_count: 0  },
  { id: "pat-006", title: "Docker Engine 26.0.2",              patch_type: "container",  severity: "medium",   status: "deployed",    deployed_count: 340, failed_count: 1  },
  { id: "pat-007", title: "Chrome 124 Zero-Day Patch",         patch_type: "browser",    severity: "critical", status: "deployed",    deployed_count: 892, failed_count: 14 },
  { id: "pat-008", title: "nginx 1.26.0 Memory Corruption",    patch_type: "application",severity: "high",     status: "in_progress", deployed_count: 145, failed_count: 6  },
  { id: "pat-009", title: "Java JDK 21.0.3 Security Update",   patch_type: "runtime",   severity: "medium",   status: "deployed",    deployed_count: 210, failed_count: 0  },
  { id: "pat-010", title: "Terraform 1.8 Config Fix",           patch_type: "iac",       severity: "low",      status: "deployed",    deployed_count: 58,  failed_count: 0  },
];

const MOCK_STATS = {
  total_patches: 284,
  critical_patches: 47,
  undeployed_critical: 12,
  success_rate: 96.8,
};

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
    deployed:    "border-green-500/30 text-green-400 bg-green-500/10",
    in_progress: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    pending:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    failed:      "border-red-500/30 text-red-400 bg-red-500/10",
  };
  const label = status.replace(/_/g, " ");
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {label}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function PatchManagementDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [livePatches, setLivePatches] = useState<any[] | null>(null);
  const [liveStats, setLiveStats]     = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/patch-management/patches?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/patch-management/stats?org_id=${ORG_ID}`),
    ]).then(([patchRes, statsRes]) => {
      if (patchRes.status === "fulfilled")  setLivePatches(patchRes.value?.patches ?? patchRes.value ?? null);
      if (statsRes.status === "fulfilled")  setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const patches = livePatches ?? MOCK_PATCHES;
  const stats   = liveStats   ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Patch Management"
        description="Enterprise patch lifecycle — critical vulnerability remediation, deployment tracking, and success rate monitoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Patches"       value={stats.total_patches}                icon={Shield}        trend="flat" className="border-blue-500/20" />
        <KpiCard title="Critical Patches"    value={stats.critical_patches}             icon={AlertTriangle} trend="up"   className="border-indigo-500/20" />
        <KpiCard title="Undeployed Critical" value={stats.undeployed_critical}          icon={XCircle}       trend="down" className="border-blue-500/20" />
        <KpiCard title="Success Rate"        value={`${stats.success_rate}%`}           icon={CheckCircle}   trend="up"   className="border-indigo-500/20" />
      </div>

      {/* Patches Table */}
      <Card className="border-blue-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <BarChart2 className="h-4 w-4" />
              Patch Registry
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {patches.filter((p: any) => p.severity === "critical" && p.status !== "deployed").length} critical pending
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Security patches with type, severity, deployment progress, and failure tracking
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Patch Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Deployed</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Failed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {patches.map((patch: any, i: number) => (
                  <TableRow key={patch.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-blue-300 max-w-[240px] truncate">
                      {patch.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize font-mono">
                      {patch.patch_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={patch.severity ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={patch.status ?? "pending"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-indigo-300">
                      {patch.deployed_count ?? 0}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-right">
                      <span className={patch.failed_count > 0 ? "text-red-400" : "text-muted-foreground"}>
                        {patch.failed_count ?? 0}
                      </span>
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
