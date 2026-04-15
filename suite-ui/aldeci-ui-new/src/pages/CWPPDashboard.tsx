/**
 * CWPPDashboard — Cloud Workload Protection Platform
 *
 * Route: /cwpp
 * Sections:
 *   1. KPIs: Workloads Protected, Suspicious, Open Findings, Events Blocked
 *   2. Workload inventory table (12 rows)
 *   3. Runtime event feed (15 events)
 *   4. Finding severity breakdown (5 types)
 *   5. Policy enforcement (3 policies)
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Activity, Zap, RefreshCw,
  Server, Eye, Lock
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const WORKLOADS = [
  { name: "api-gateway-prod", type: "container",   runtime: "docker",      image: "nginx:1.25.3",           cluster: "prod-k8s-1",  risk: 12, status: "running",    findings: 2  },
  { name: "auth-service",     type: "container",   runtime: "containerd",  image: "auth-svc:v2.1.4",        cluster: "prod-k8s-1",  risk: 28, status: "suspicious", findings: 7  },
  { name: "worker-node-07",   type: "vm",          runtime: "containerd",  image: "ubuntu:22.04",           cluster: "prod-ec2",    risk: 45, status: "running",    findings: 14 },
  { name: "scan-job-runner",  type: "k8s_pod",     runtime: "containerd",  image: "scanner:3.0.1",          cluster: "prod-k8s-2",  risk: 8,  status: "running",    findings: 1  },
  { name: "lambda-enricher",  type: "serverless",  runtime: "docker",      image: "aws-lambda:python3.12",  cluster: "us-east-1",   risk: 5,  status: "running",    findings: 0  },
  { name: "db-proxy",         type: "container",   runtime: "docker",      image: "pgbouncer:1.21.0",       cluster: "prod-k8s-1",  risk: 62, status: "suspicious", findings: 18 },
  { name: "redis-cache",      type: "container",   runtime: "docker",      image: "redis:7.2-alpine",       cluster: "prod-k8s-1",  risk: 15, status: "running",    findings: 3  },
  { name: "ml-inference-01",  type: "vm",          runtime: "docker",      image: "pytorch:2.2-cuda12",     cluster: "gpu-cluster", risk: 22, status: "running",    findings: 5  },
  { name: "intake-fn",        type: "serverless",  runtime: "docker",      image: "aws-lambda:node20",      cluster: "eu-west-1",   risk: 7,  status: "running",    findings: 1  },
  { name: "sidecar-tls",      type: "k8s_pod",     runtime: "containerd",  image: "envoy:v1.29.2",          cluster: "prod-k8s-2",  risk: 11, status: "running",    findings: 2  },
  { name: "batch-processor",  type: "container",   runtime: "containerd",  image: "batch-proc:1.4.0",       cluster: "prod-k8s-3",  risk: 31, status: "stopped",    findings: 8  },
  { name: "audit-collector",  type: "k8s_pod",     runtime: "containerd",  image: "fluentbit:3.0.4",        cluster: "prod-k8s-3",  risk: 4,  status: "running",    findings: 0  },
];

const EVENTS = [
  { workload: "auth-service",    type: "privilege_escalation", blocked: true,  desc: "Attempted setuid(0) syscall from PID 2841",             ts: "16:42:11" },
  { workload: "db-proxy",        type: "malware",              blocked: true,  desc: "Known coinminer binary hash detected in /tmp",           ts: "16:41:58" },
  { workload: "db-proxy",        type: "syscall_anomaly",      blocked: false, desc: "Unexpected ptrace call to process 1192",                  ts: "16:41:33" },
  { workload: "worker-node-07",  type: "file_integrity",       blocked: false, desc: "/etc/passwd modified outside of change window",          ts: "16:40:17" },
  { workload: "auth-service",    type: "privilege_escalation", blocked: true,  desc: "sudo execution from non-interactive shell",              ts: "16:39:52" },
  { workload: "api-gateway-prod",type: "syscall_anomaly",      blocked: false, desc: "Rare syscall sequence: mprotect+execve chain",           ts: "16:38:44" },
  { workload: "db-proxy",        type: "malware",              blocked: true,  desc: "Reverse shell command pattern in execve args",           ts: "16:37:29" },
  { workload: "batch-processor", type: "file_integrity",       blocked: false, desc: "/usr/bin/curl replaced with non-standard binary",        ts: "16:36:05" },
  { workload: "ml-inference-01", type: "syscall_anomaly",      blocked: false, desc: "mount() syscall from application process",              ts: "16:35:18" },
  { workload: "worker-node-07",  type: "malware",              blocked: true,  desc: "YARA rule match: Mirai botnet loader signature",         ts: "16:34:51" },
  { workload: "auth-service",    type: "file_integrity",       blocked: false, desc: "/etc/shadow read by unprivileged process",               ts: "16:33:39" },
  { workload: "redis-cache",     type: "syscall_anomaly",      blocked: false, desc: "bind() on unexpected port 31337",                       ts: "16:32:22" },
  { workload: "scan-job-runner", type: "privilege_escalation", blocked: true,  desc: "Capability CAP_NET_RAW requested at runtime",            ts: "16:31:07" },
  { workload: "api-gateway-prod",type: "file_integrity",       blocked: false, desc: "Nginx config overwritten during running container",      ts: "16:29:54" },
  { workload: "sidecar-tls",     type: "syscall_anomaly",      blocked: false, desc: "Unexpected outbound connection on port 4444",            ts: "16:28:41" },
];

const FINDING_TYPES = [
  { type: "vulnerable_image",      count: 89,  severity: "High",     color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
  { type: "privileged_container",  count: 23,  severity: "Critical", color: "text-red-400",   bg: "bg-red-500/10 border-red-500/20" },
  { type: "secrets_mounted",       count: 41,  severity: "Critical", color: "text-red-400",   bg: "bg-red-500/10 border-red-500/20" },
  { type: "network_exposure",      count: 58,  severity: "High",     color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20" },
  { type: "malware_detected",      count: 7,   severity: "Critical", color: "text-red-400",   bg: "bg-red-500/10 border-red-500/20" },
];

const POLICIES = [
  {
    name: "Privileged Container Block",
    rules: ["Block privileged containers", "Block hostPID/hostNetwork", "Deny SYS_ADMIN capability"],
    status: "enforcing",
    applied: 847,
  },
  {
    name: "Read-Only Root Filesystem",
    rules: ["Enforce read-only root FS", "Allow /tmp write via tmpfs", "Alert on /etc modifications"],
    status: "enforcing",
    applied: 612,
  },
  {
    name: "Registry Allowlist",
    rules: ["Allow: gcr.io, docker.io/library", "Block unverified registries", "Require image digest pinning"],
    status: "audit",
    applied: 381,
  },
];

// ── Helpers ────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    container:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    vm:         "border-purple-500/30 text-purple-400 bg-purple-500/10",
    serverless: "border-green-500/30 text-green-400 bg-green-500/10",
    k8s_pod:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function RuntimeBadge({ runtime }: { runtime: string }) {
  return <Badge className="text-[10px] border border-border text-muted-foreground">{runtime}</Badge>;
}

function EventTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    syscall_anomaly:     "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    file_integrity:      "border-orange-500/30 text-orange-400 bg-orange-500/10",
    privilege_escalation:"border-red-500/30 text-red-400 bg-red-500/10",
    malware:             "border-red-600/30 text-red-300 bg-red-600/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type.replace(/_/g, " ")}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  if (status === "running")    return <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">running</Badge>;
  if (status === "stopped")    return <Badge className="text-[10px] border border-border text-muted-foreground">stopped</Badge>;
  if (status === "suspicious") return (
    <Badge className="text-[10px] border border-red-500/50 text-red-400 bg-red-500/10 animate-pulse">suspicious</Badge>
  );
  return <Badge className="text-[10px] border border-border text-muted-foreground">{status}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function CWPPDashboard() {
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Cloud Workload Protection"
        description="Container, VM, and serverless runtime security"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Workloads Protected" value={847}  icon={Shield}        trend="up"   />
        <KpiCard title="Suspicious"          value={12}   icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Open Findings"       value={234}  icon={Activity}      trend="down" className="border-amber-500/20" />
        <KpiCard title="Events Blocked Today" value="1,847" icon={Zap}         trend="up"   className="border-green-500/20" />
      </div>

      {/* Workload Inventory */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Server className="h-4 w-4 text-blue-400" />
            Workload Inventory
          </CardTitle>
          <CardDescription className="text-xs">All monitored workloads with runtime status and risk scores</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Runtime</TableHead>
                  <TableHead className="text-[11px] h-8">Image</TableHead>
                  <TableHead className="text-[11px] h-8">Cluster</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {WORKLOADS.map((w) => (
                  <TableRow key={w.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{w.name}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={w.type} /></TableCell>
                    <TableCell className="py-2.5"><RuntimeBadge runtime={w.runtime} /></TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[140px] truncate text-muted-foreground font-mono">{w.image}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{w.cluster}</TableCell>
                    <TableCell className="py-2.5 w-28">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", w.risk >= 50 ? "bg-red-500" : w.risk >= 25 ? "bg-amber-500" : "bg-green-500")}
                            style={{ width: `${w.risk}%` }}
                          />
                        </div>
                        <span className="text-[10px] tabular-nums w-6 text-right text-muted-foreground">{w.risk}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={w.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-right tabular-nums font-medium">
                      <span className={w.findings > 0 ? "text-amber-400" : "text-muted-foreground"}>{w.findings}</span>
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Inspect</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Runtime Event Feed */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-orange-400" />
              Runtime Event Feed
            </CardTitle>
            <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">Live</Badge>
          </div>
          <CardDescription className="text-xs">Real-time behavioral anomalies and policy violations</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Workload</TableHead>
                  <TableHead className="text-[11px] h-8">Event Type</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Description</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {EVENTS.map((e, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2">{e.workload}</TableCell>
                    <TableCell className="py-2"><EventTypeBadge type={e.type} /></TableCell>
                    <TableCell className="py-2">
                      {e.blocked
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">blocked</Badge>
                        : <Badge className="text-[10px] border border-border text-muted-foreground">allowed</Badge>
                      }
                    </TableCell>
                    <TableCell className="text-xs py-2 max-w-[300px] truncate text-muted-foreground">{e.desc}</TableCell>
                    <TableCell className="text-xs py-2 text-right tabular-nums text-muted-foreground">{e.ts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Finding Severity Breakdown + Policy Enforcement */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Finding types */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Finding Severity Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Open findings grouped by category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {FINDING_TYPES.map((f) => (
              <div key={f.type} className={cn("flex items-center justify-between rounded-lg border p-3", f.bg)}>
                <div className="flex items-center gap-3">
                  <span className="text-xs font-medium">{f.type.replace(/_/g, " ")}</span>
                  <Badge className={cn("text-[10px] border", f.bg, f.color)}>{f.severity}</Badge>
                </div>
                <span className={cn("text-sm font-bold tabular-nums", f.color)}>{f.count}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Policy enforcement */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-green-400" />
              Policy Enforcement
            </CardTitle>
            <CardDescription className="text-xs">Active runtime security policies and coverage</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {POLICIES.map((p) => (
              <div key={p.name} className="rounded-lg border border-border bg-muted/10 p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold">{p.name}</span>
                  {p.status === "enforcing"
                    ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">enforcing</Badge>
                    : <Badge className="text-[10px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10">audit</Badge>
                  }
                </div>
                <ul className="space-y-0.5">
                  {p.rules.map((r) => (
                    <li key={r} className="text-[11px] text-muted-foreground flex items-center gap-1.5">
                      <span className="w-1 h-1 rounded-full bg-muted-foreground/50 flex-shrink-0" />
                      {r}
                    </li>
                  ))}
                </ul>
                <p className="text-[11px] text-muted-foreground">
                  Applied to <span className="font-semibold text-foreground">{p.applied.toLocaleString()}</span> workloads
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Inspect button */}
      <div className="flex justify-end">
        <Button variant="outline" size="sm" className="gap-2">
          <Eye className="h-4 w-4" />
          View All Runtime Events
        </Button>
      </div>
    </motion.div>
  );
}
