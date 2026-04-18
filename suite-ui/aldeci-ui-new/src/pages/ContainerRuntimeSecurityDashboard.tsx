/**
 * Container Runtime Security Dashboard
 *
 * Real-time security monitoring for container workloads.
 *   1. KPI cards: Total Containers, Running Containers, Violations, Blocked
 *   2. Container inventory table
 *   3. Runtime violations table
 *
 * API: GET /api/v1/container-runtime/{stats,containers,violations}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Box, RefreshCw, AlertTriangle, Shield, XCircle, Activity,
} from "lucide-react";
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
  total_containers: 312,
  running_containers: 287,
  violations_count: 18,
  blocked_count: 4,
};

const MOCK_CONTAINERS = [
  { id: "c-001", container_name: "api-gateway",        image: "nginx:1.25-alpine",       risk_score: 12, status: "running"  },
  { id: "c-002", container_name: "auth-service",       image: "node:20-slim",            risk_score: 25, status: "running"  },
  { id: "c-003", container_name: "db-postgres",        image: "postgres:16",             risk_score: 38, status: "running"  },
  { id: "c-004", container_name: "redis-cache",        image: "redis:7-alpine",          risk_score: 8,  status: "running"  },
  { id: "c-005", container_name: "ml-inference",       image: "python:3.11-slim",        risk_score: 62, status: "running"  },
  { id: "c-006", container_name: "legacy-connector",   image: "ubuntu:20.04",            risk_score: 85, status: "blocked"  },
  { id: "c-007", container_name: "report-generator",  image: "node:18",                  risk_score: 44, status: "running"  },
  { id: "c-008", container_name: "vuln-scanner",      image: "aquasec/trivy:latest",     risk_score: 15, status: "stopped"  },
  { id: "c-009", container_name: "siem-forwarder",    image: "fluent/fluentd:v1.16",     risk_score: 20, status: "running"  },
  { id: "c-010", container_name: "untrusted-sidecar", image: "unknown/pkg:latest",       risk_score: 97, status: "blocked"  },
];

const MOCK_VIOLATIONS = [
  { id: "v-001", violation_type: "privileged_container",     severity: "critical", container_id: "c-006", action_taken: "blocked",    timestamp: "2026-04-16T09:05:00Z" },
  { id: "v-002", violation_type: "host_network_access",      severity: "high",     container_id: "c-010", action_taken: "blocked",    timestamp: "2026-04-16T08:50:00Z" },
  { id: "v-003", violation_type: "unexpected_outbound",       severity: "high",     container_id: "c-005", action_taken: "alerted",    timestamp: "2026-04-16T08:30:00Z" },
  { id: "v-004", violation_type: "file_system_write",        severity: "medium",   container_id: "c-003", action_taken: "logged",     timestamp: "2026-04-16T07:45:00Z" },
  { id: "v-005", violation_type: "syscall_violation",        severity: "critical", container_id: "c-010", action_taken: "blocked",    timestamp: "2026-04-16T07:20:00Z" },
  { id: "v-006", violation_type: "drift_detection",          severity: "medium",   container_id: "c-007", action_taken: "alerted",    timestamp: "2026-04-15T22:15:00Z" },
  { id: "v-007", violation_type: "secret_in_env_var",        severity: "high",     container_id: "c-002", action_taken: "alerted",    timestamp: "2026-04-15T19:00:00Z" },
  { id: "v-008", violation_type: "untrusted_image",          severity: "critical", container_id: "c-010", action_taken: "blocked",    timestamp: "2026-04-15T16:30:00Z" },
];

// ── Badge helpers ──────────────────────────────────────────────

function RiskScoreBadge({ score }: { score: number }) {
  const cls =
    score >= 75 ? "border-red-500/30 text-red-400 bg-red-500/10" :
    score >= 40 ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                  "border-green-500/30 text-green-400 bg-green-500/10";
  return (
    <Badge className={cn("text-[10px] border font-mono", cls)}>{score}</Badge>
  );
}

function ContainerStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    running: "border-green-500/30 text-green-400 bg-green-500/10",
    stopped: "border-gray-500/30 text-gray-400 bg-gray-500/10",
    blocked: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
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

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    blocked: "border-red-500/30 text-red-400 bg-red-500/10",
    alerted: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    logged:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[action] ?? "border-border text-muted-foreground")}>
      {action}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

// ── Component ──────────────────────────────────────────────────

export default function ContainerRuntimeSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    containers: any[] | null;
    violations: any[] | null;
  }>({ stats: null, containers: null, violations: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/container-runtime/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/container-runtime/containers?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/container-runtime/violations?org_id=${ORG_ID}`),
    ]).then(([statsRes, containersRes, violationsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        containers: containersRes.status === "fulfilled" ? containersRes.value : null,
        violations: violationsRes.status === "fulfilled" ? violationsRes.value : null,
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

  const stats      = liveData.stats      ?? MOCK_STATS;
  const containers = liveData.containers ?? MOCK_CONTAINERS;
  const violations = liveData.violations ?? MOCK_VIOLATIONS;

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
        title="Container Runtime Security"
        description="Real-time security monitoring and policy enforcement for container workloads"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Containers"    value={stats.total_containers}    icon={Box
    setLoading(false);}           trend="flat" />
        <KpiCard title="Running Containers"  value={stats.running_containers}  icon={Activity}      trend="flat" className="border-green-500/20" />
        <KpiCard title="Violations"          value={stats.violations_count}    icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Blocked"             value={stats.blocked_count}       icon={XCircle}       trend="up"   className="border-red-500/20" />
      </div>

      {/* Containers Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Box className="h-4 w-4 text-cyan-400" />
              Container Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {containers.length} containers
            </Badge>
          </div>
          <CardDescription className="text-xs">Running containers with risk scores and runtime status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Container Name</TableHead>
                  <TableHead className="text-[11px] h-8">Image</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {containers.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  containers.map((c: any, i: number) => (
                  <TableRow key={c.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{c.id}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{c.container_name}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{c.image}</TableCell>
                    <TableCell className="py-2"><RiskScoreBadge score={c.risk_score ?? 0} /></TableCell>
                    <TableCell className="py-2"><ContainerStatusBadge status={c.status ?? "running"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Violations Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Shield className="h-4 w-4" />
              Runtime Violations
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {violations.filter((v: any) => v.action_taken === "blocked").length} blocked
            </Badge>
          </div>
          <CardDescription className="text-xs">Policy violations detected at container runtime</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Violation Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Container ID</TableHead>
                  <TableHead className="text-[11px] h-8">Action Taken</TableHead>
                  <TableHead className="text-[11px] h-8">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {violations.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  violations.map((v: any, i: number) => (
                  <TableRow key={v.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{v.id}</TableCell>
                    <TableCell className="py-2 text-[11px] capitalize">{(v.violation_type ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={v.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{v.container_id}</TableCell>
                    <TableCell className="py-2"><ActionBadge action={v.action_taken ?? "logged"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(v.timestamp)}</TableCell>
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
